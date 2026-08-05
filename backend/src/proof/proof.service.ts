import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { getPool } from '../db/client';
import { NullifierService } from '../nullifier/nullifier.service';
import { ProofVerificationService } from './proof-verification.service';
import { RelayProofDto, PublicInputsDto, RelayProofResult } from './dto/relay-proof.dto';

@Injectable()
export class ProofService {
  private readonly logger = new Logger(ProofService.name);
  private readonly verifierContractId: string;
  private readonly stellarRpcUrl: string;
  private readonly stellarPassphrase: string;
  private readonly deployerSecretKey: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly nullifierService: NullifierService,
    private readonly verifierService: ProofVerificationService,
  ) {
    this.verifierContractId = this.configService.get<string>('VERIFIER_CONTRACT_ID') ?? '';
    this.stellarRpcUrl = this.configService.get<string>('STELLAR_RPC_URL') ?? '';
    this.stellarPassphrase = this.configService.get<string>('STELLAR_PASSPHRASE') ?? '';
    this.deployerSecretKey = this.configService.get<string>('DEPLOYER_SECRET_KEY') ?? '';
  }

  async relay(dto: RelayProofDto): Promise<RelayProofResult> {
    this.validateProofFormat(dto.proof);
    this.validatePublicInputs(dto.publicInputs);

    const nullifierStatus = await this.nullifierService.isUsed(dto.publicInputs.nullifier);
    if (nullifierStatus.used) {
      return { verified: false, error: 'Nullifier already used' };
    }

    // Off-chain UltraHonk verification gate (VERIFY_OFFCHAIN=true). Proves the
    // proof against the compiled circuit before any on-chain cost is paid. The
    // on-chain Groth16 check is stubbed, so this gate is the only real proof
    // verification until a verifier is deployed.
    const offchain = await this.verifierService.verify(dto.proof, dto.publicInputs);
    if (offchain.enabled && !offchain.verified) {
      return { verified: false, error: offchain.error ?? 'Off-chain proof verification failed' };
    }

    try {
      const publicInputsBytes = this.getPublicInputBytes(dto.publicInputs);
      const proofBytes = Buffer.from(dto.proof.startsWith('0x') ? dto.proof.slice(2) : dto.proof, 'hex');

      const { SorobanRpc, xdr, Contract, Keypair } = await import('@stellar/stellar-sdk');

      const server = new SorobanRpc.Server(this.stellarRpcUrl);
      const sourceKeypair = Keypair.fromSecret(this.deployerSecretKey);
      const sourceAccount = await server.getAccount(sourceKeypair.publicKey());

      const contract = new Contract(this.verifierContractId);

      const call = contract.call(
        'verify_and_record',
        xdr.ScVal.scvBytes(proofBytes),
        xdr.ScVal.scvBytes(publicInputsBytes),
      );

      const { TransactionBuilder } = await import('@stellar/stellar-sdk');

      const tx = new TransactionBuilder(sourceAccount, {
        fee: '10000',
        networkPassphrase: this.stellarPassphrase,
      })
        .addOperation(call)
        .setTimeout(30)
        .build();

      const simulated = await server.simulateTransaction(tx);
      if (!simulated) {
        throw new BadRequestException('Transaction simulation failed');
      }

      tx.sign(sourceKeypair);
      const sendResponse = await server.sendTransaction(tx);

      if (sendResponse.status === 'ERROR') {
        const errorMsg = sendResponse.errorResult?.result()?.toString() ?? 'Unknown send error';
        this.logger.error(`Transaction send error: ${errorMsg}`);
        return { verified: false, error: `Soroban transaction failed: ${errorMsg}` };
      }

      const txHash = sendResponse.hash;
      let verified = false;
      let attempts = 0;
      const maxAttempts = 15;

      while (attempts < maxAttempts) {
        await new Promise(r => setTimeout(r, 2000));
        const txResult = await server.getTransaction(txHash);

        if (txResult.status === SorobanRpc.Api.GetTransactionStatus.SUCCESS) {
          if (txResult.returnValue) {
            verified = txResult.returnValue.value() === true;
          }
          break;
        }
        if (txResult.status === SorobanRpc.Api.GetTransactionStatus.FAILED) {
          this.logger.error(`Transaction FAILED: ${JSON.stringify(txResult)}`);
          break;
        }
        attempts++;
      }

      if (attempts >= maxAttempts) {
        return { verified: false, error: 'Soroban transaction confirmation timeout (30s)' };
      }

      if (verified) {
        await this.nullifierService.record(
          dto.publicInputs.nullifier,
          '',
          dto.publicInputs.corridor_id,
          txHash,
        );
      }

      return { verified, txHash };
    } catch (err: any) {
      this.logger.error(`Proof relay failed: ${err.message}`);
      return { verified: false, error: err.message };
    }
  }

  getPublicInputBytes(inputs: PublicInputsDto): Buffer {
    const nullifierBuf = Buffer.from(inputs.nullifier.slice(2), 'hex');
    const issuerPubkeyHashBuf = Buffer.from(inputs.issuer_pubkey_hash.slice(2), 'hex');
    const paymentAssetBuf = Buffer.from(inputs.payment_asset.slice(2), 'hex');
    const amlBuf = Buffer.alloc(8);
    amlBuf.writeBigUInt64BE(BigInt(inputs.aml_threshold));
    const corridorIdBuf = Buffer.from(inputs.corridor_id.slice(2), 'hex');
    const allowedJurisdictionsRootBuf = Buffer.from(inputs.allowed_jurisdictions_root.slice(2), 'hex');
    const amountCommitmentBuf = Buffer.from(inputs.amount_commitment.slice(2), 'hex');
    const revocationRootBuf = Buffer.from(inputs.revocation_root.slice(2), 'hex');
    const approvedCorridorsRootBuf = Buffer.from(inputs.approved_corridors_root.slice(2), 'hex');

    // Layout MUST match the circuit's public parameter order in main.nr:
    // nullifier, issuer_pubkey_hash, payment_asset, aml_threshold,
    // corridor_id, allowed_jurisdictions_root, amount_commitment,
    // revocation_root, approved_corridors_root. A real verifier binds the
    // proof's public inputs in this order, so any other byte order here would
    // make every field past corridor_id decode as the wrong value.
    return Buffer.concat([
      nullifierBuf,
      issuerPubkeyHashBuf,
      paymentAssetBuf,
      amlBuf,
      corridorIdBuf,
      allowedJurisdictionsRootBuf,
      amountCommitmentBuf,
      revocationRootBuf,
      approvedCorridorsRootBuf,
    ]);
  }

  private validateProofFormat(proof: string): void {
    if (!proof || proof.length < 100) {
      throw new BadRequestException('Proof must be a hex string longer than 100 characters');
    }
    const hex = proof.startsWith('0x') ? proof.slice(2) : proof;
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new BadRequestException('Proof must be a valid hex string');
    }
  }

  private validatePublicInputs(inputs: PublicInputsDto): void {
    if (!this.nullifierService.isValidFormat(inputs.nullifier)) {
      throw new BadRequestException('Invalid nullifier format — must be a 66-char hex string starting with 0x');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.issuer_pubkey_hash)) {
      throw new BadRequestException('Invalid issuer_pubkey_hash format');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.payment_asset)) {
      throw new BadRequestException('Invalid payment_asset format');
    }
    if (inputs.aml_threshold < 0) {
      throw new BadRequestException('aml_threshold must be a positive integer');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.corridor_id)) {
      throw new BadRequestException('Invalid corridor_id format');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.amount_commitment)) {
      throw new BadRequestException('Invalid amount_commitment format');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.revocation_root)) {
      throw new BadRequestException('Invalid revocation_root format');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.approved_corridors_root)) {
      throw new BadRequestException('Invalid approved_corridors_root format');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(inputs.allowed_jurisdictions_root)) {
      throw new BadRequestException('Invalid allowed_jurisdictions_root format');
    }
  }
}
