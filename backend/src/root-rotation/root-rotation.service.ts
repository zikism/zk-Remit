import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MerkleService } from '../merkle/merkle.service';
import { PoseidonService } from '../hash/poseidon.service';

export interface RootRotationResult {
  jurisdictionRoot: string;
  corridorRoot: string;
  revocationRoot: string;
  txHash?: string;
}

/**
 * Publishes the current merkle roots to the on-chain ComplianceVerifier via
 * its admin `update_roots` call. Credential revocation and corridor changes
 * only take effect on-chain once the admin runs this (the circuit's proofs
 * bind to the published roots, so proofs become stale after rotation).
 */
@Injectable()
export class RootRotationService {
  private readonly logger = new Logger(RootRotationService.name);
  private readonly verifierContractId: string;
  private readonly stellarRpcUrl: string;
  private readonly stellarPassphrase: string;
  private readonly deployerSecretKey: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly merkleService: MerkleService,
    private readonly poseidonService: PoseidonService,
  ) {
    this.verifierContractId = this.configService.get<string>('VERIFIER_CONTRACT_ID') ?? '';
    this.stellarRpcUrl = this.configService.get<string>('STELLAR_RPC_URL') ?? '';
    this.stellarPassphrase = this.configService.get<string>('STELLAR_PASSPHRASE') ?? '';
    this.deployerSecretKey = this.configService.get<string>('DEPLOYER_SECRET_KEY') ?? '';
  }

  /**
   * Current roots as 0x-hex fields, matching what the circuit's merkle
   * membership proofs must bind to.
   */
  async getCurrentRoots(): Promise<Omit<RootRotationResult, 'txHash'>> {
    const revocationRoot = await this.merkleService.revocationRoot();
    return {
      jurisdictionRoot: this.poseidonService.fieldToHex32(this.merkleService.jurisdictionRoot()),
      corridorRoot: this.poseidonService.fieldToHex32(this.merkleService.corridorRoot()),
      revocationRoot: this.poseidonService.fieldToHex32(revocationRoot),
    };
  }

  /** Recompute the roots and publish them to the on-chain verifier. */
  async publishRoots(): Promise<RootRotationResult> {
    if (!this.verifierContractId || !this.stellarRpcUrl || !this.deployerSecretKey) {
      throw new ServiceUnavailableException(
        'VERIFIER_CONTRACT_ID, STELLAR_RPC_URL and DEPLOYER_SECRET_KEY are required for root rotation'
      );
    }

    const current = await this.getCurrentRoots();

    try {
      const { SorobanRpc, xdr, Contract, Keypair, TransactionBuilder, Address } = await import('@stellar/stellar-sdk');

      const server = new SorobanRpc.Server(this.stellarRpcUrl);
      const sourceKeypair = Keypair.fromSecret(this.deployerSecretKey);
      const sourceAccount = await server.getAccount(sourceKeypair.publicKey());

      const contract = new Contract(this.verifierContractId);
      const call = contract.call(
        'update_roots',
        xdr.ScVal.scvAddress(new Address(sourceKeypair.publicKey()).toScAddress()),
        xdr.ScVal.scvBytes(Buffer.from(current.revocationRoot.slice(2), 'hex')),
        xdr.ScVal.scvBytes(Buffer.from(current.corridorRoot.slice(2), 'hex')),
        xdr.ScVal.scvBytes(Buffer.from(current.jurisdictionRoot.slice(2), 'hex')),
      );

      const tx = new TransactionBuilder(sourceAccount, {
        fee: '10000',
        networkPassphrase: this.stellarPassphrase,
      })
        .addOperation(call)
        .setTimeout(30)
        .build();

      const simulated = await server.simulateTransaction(tx);
      if (!simulated) {
        throw new Error('Transaction simulation failed');
      }

      tx.sign(sourceKeypair);
      const sendResponse = await server.sendTransaction(tx);

      if (sendResponse.status === 'ERROR') {
        throw new Error(sendResponse.errorResult?.result()?.toString() ?? 'Unknown send error');
      }

      const txHash = sendResponse.hash;
      this.logger.log(`Roots published on-chain (tx ${txHash})`);
      return { ...current, txHash };
    } catch (err: any) {
      this.logger.error(`Root rotation failed: ${err.message}`);
      throw new ServiceUnavailableException(`Root rotation failed: ${err.message}`);
    }
  }
}
