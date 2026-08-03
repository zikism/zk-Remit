import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { getPool } from '../db/client';

@Injectable()
export class NullifierService {
  private readonly logger = new Logger(NullifierService.name);
  private readonly verifierContractId: string;
  private readonly stellarRpcUrl: string;

  constructor(private readonly configService: ConfigService) {
    this.verifierContractId = this.configService.get<string>('VERIFIER_CONTRACT_ID') ?? '';
    this.stellarRpcUrl = this.configService.get<string>('STELLAR_RPC_URL') ?? '';
  }

  async isUsed(
    nullifier: string,
  ): Promise<{ used: boolean; source: 'local' | 'onchain' | 'fresh' }> {
    const pool = getPool();

    const { rows } = await pool.query(
      'SELECT 1 FROM nullifiers WHERE nullifier = $1 LIMIT 1',
      [nullifier]
    );
    if (rows.length > 0) {
      return { used: true, source: 'local' };
    }

    const onChainUsed = await this.checkOnChain(nullifier);
    if (onChainUsed) {
      await pool.query(
        `INSERT INTO nullifiers (nullifier, stellar_tx_hash)
         VALUES ($1, $2) ON CONFLICT (nullifier) DO NOTHING`,
        [nullifier, 'synced-from-chain']
      );
      return { used: true, source: 'onchain' };
    }

    return { used: false, source: 'fresh' };
  }

  async record(
    nullifier: string,
    walletAddress: string,
    corridorId: string,
    txHash: string,
  ): Promise<void> {
    const pool = getPool();
    await pool.query(
      `INSERT INTO nullifiers (nullifier, wallet_address, corridor_id, stellar_tx_hash)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (nullifier) DO NOTHING`,
      [nullifier, walletAddress, corridorId, txHash]
    );
  }

  async getCount(): Promise<number> {
    const pool = getPool();
    const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM nullifiers');
    return rows[0].count;
  }

  isValidFormat(nullifier: string): boolean {
    return /^0x[0-9a-fA-F]{64}$/.test(nullifier);
  }

  private async checkOnChain(nullifier: string): Promise<boolean> {
    if (!this.verifierContractId || !this.stellarRpcUrl) {
      this.logger.warn('VERIFIER_CONTRACT_ID or STELLAR_RPC_URL not configured — skipping on-chain check');
      return false;
    }

    try {
      const { SorobanRpc, xdr } = await import('@stellar/stellar-sdk');

      const server = new SorobanRpc.Server(this.stellarRpcUrl);
      const nullifierBytes = Buffer.from(nullifier.slice(2), 'hex');
      const key = xdr.ScVal.scvBytes(nullifierBytes);

      this.logger.debug('Querying Soroban contract for nullifier: ' + nullifier.slice(0, 18) + '...');

      const entry = await server.getContractData(this.verifierContractId, key);
      return entry !== null && entry !== undefined;
    } catch (err: any) {
      if (err?.code === 404) {
        return false;
      }
      this.logger.error(`On-chain nullifier check failed: ${err.message}`);
      return false;
    }
  }
}
