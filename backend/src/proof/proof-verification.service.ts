import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { PublicInputsDto } from './dto/relay-proof.dto';

export interface OffchainVerificationResult {
  enabled: boolean;
  verified: boolean;
  error?: string;
}

@Injectable()
export class ProofVerificationService {
  private readonly logger = new Logger(ProofVerificationService.name);
  private readonly enabled: boolean;
  private readonly circuitPath: string;
  private backend: any = null;
  private bytecode: string | null = null;

  constructor(private readonly configService: ConfigService) {
    this.enabled =
      (configService.get<string>('VERIFY_OFFCHAIN') ?? 'false').toLowerCase() === 'true';
    this.circuitPath =
      configService.get<string>('ZK_COMPLIANCE_CIRCUIT_PATH') ??
      join(process.cwd(), 'circuits', 'zk_compliance.json');

    if (this.enabled) {
      this.logger.log(
        `Off-chain proof verification enabled (circuit: ${this.circuitPath})`
      );
    }
  }

  /**
   * Verify an UltraHonk proof off-chain against the compiled circuit before it
   * is relayed on-chain. Flag-gated via VERIFY_OFFCHAIN: when disabled the
   * relay still works against the stubbed Groth16 check; when enabled, a proof
   * that fails off-chain verification is rejected before any Stellar tx.
   */
  async verify(proofHex: string, inputs: PublicInputsDto): Promise<OffchainVerificationResult> {
    if (!this.enabled) {
      return {
        enabled: false,
        verified: false,
        error: 'Off-chain verification is disabled (VERIFY_OFFCHAIN unset)',
      };
    }

    try {
      const backend = await this.getBackend();
      if (!backend) {
        return {
          enabled: true,
          verified: false,
          error: 'Off-chain verification unavailable: circuit or bb.js backend not loaded',
        };
      }

      const proof = Buffer.from(
        proofHex.startsWith('0x') ? proofHex.slice(2) : proofHex,
        'hex'
      );
      const publicInputs = this.publicInputsToCircuitOrder(inputs);

      const verified = await backend.verifyProof({ proof, publicInputs });
      return { enabled: true, verified };
    } catch (err: any) {
      this.logger.error(`Off-chain proof verification error: ${err.message}`);
      return {
        enabled: true,
        verified: false,
        error: `Off-chain verification error: ${err.message}`,
      };
    }
  }

  /**
   * Convert the DTO's hex public inputs to decimal field strings in circuit
   * order. The layout MUST mirror main.nr's public parameters; UltraHonk binds
   * the proof's public inputs in exactly this order, so a real proof only
   * verifies if these line up.
   */
  private publicInputsToCircuitOrder(inputs: PublicInputsDto): string[] {
    const field = (hex: string) => BigInt(hex).toString();
    return [
      field(inputs.nullifier),
      field(inputs.issuer_pubkey_hash),
      field(inputs.payment_asset),
      BigInt(inputs.aml_threshold).toString(),
      field(inputs.corridor_id),
      field(inputs.allowed_jurisdictions_root),
      field(inputs.amount_commitment),
      field(inputs.revocation_root),
      field(inputs.approved_corridors_root),
    ];
  }

  private async getBackend(): Promise<any | null> {
    if (this.backend) {
      return this.backend;
    }
    if (!this.enabled || !existsSync(this.circuitPath)) {
      return null;
    }

    const { UltraHonkBackend } = await import('@aztec/bb.js');
    const circuit = JSON.parse(readFileSync(this.circuitPath, 'utf-8'));
    this.bytecode = circuit.bytecode as string;
    this.backend = new UltraHonkBackend(this.bytecode, { threads: 1 });
    return this.backend;
  }
}
