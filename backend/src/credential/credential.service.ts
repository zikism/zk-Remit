import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import nacl from 'tweetnacl';
import { getPool } from '../db/client';
import { PoseidonService } from '../hash/poseidon.service';
import { IssueCredentialDto, CredentialResponse, IssuerResponse } from './dto/issue-credential.dto';

const CORRIDOR_MAP: Record<string, { senderJurisdiction: number }> = {
  'NG-PH': { senderJurisdiction: 566 },
  'NG-GB': { senderJurisdiction: 566 },
  'GH-US': { senderJurisdiction: 288 },
  'KE-DE': { senderJurisdiction: 404 },
};

const ISSUERS: IssuerResponse[] = [
  {
    name: 'mock-issuer',
    pubkeyHash: '',
    supportedCorridors: ['NG-PH', 'NG-GB', 'GH-US', 'KE-DE'],
  },
];

@Injectable()
export class CredentialService {
  private readonly issuerPrivateKey: Buffer;
  private readonly issuerPublicKey: Buffer;

  constructor(
    private readonly configService: ConfigService,
    private readonly poseidonService: PoseidonService,
  ) {
    const privHex = this.configService.get<string>('ISSUER_PRIVATE_KEY');
    const pubHex = this.configService.get<string>('ISSUER_PUBLIC_KEY');

    if (!privHex || privHex.length !== 128) {
      throw new Error('ISSUER_PRIVATE_KEY must be a 64-byte hex string (128 chars)');
    }
    // The circuit verifies a secp256k1 signature and derives
    // issuer_pubkey_hash from the full point (x || y), so the public key is
    // the 64-byte uncompressed point.
    if (!pubHex || pubHex.length !== 128) {
      throw new Error('ISSUER_PUBLIC_KEY must be a 64-byte hex string (128 chars: x || y)');
    }

    this.issuerPrivateKey = Buffer.from(privHex, 'hex');
    this.issuerPublicKey = Buffer.from(pubHex, 'hex');
  }

  async issue(dto: IssueCredentialDto): Promise<CredentialResponse> {
    const pool = getPool();

    const corridorInfo = CORRIDOR_MAP[dto.corridorId];
    if (!corridorInfo) {
      throw new Error(`Unsupported corridor: ${dto.corridorId}`);
    }

    const credentialSecretBytes = randomBytes(32);
    const credentialSecret = '0x' + credentialSecretBytes.toString('hex');

    // Circuit-consistent Poseidon2 over the user identity bytes (chunked so
    // each field fits below the BN254 modulus).
    const userPubkeyHash = this.poseidonService.poseidon2(
      this.poseidonService.bytesToFieldChunks(Buffer.from(dto.walletAddress, 'utf-8'))
    );
    const userPubkeyHashHex = this.poseidonService.fieldToHex32(userPubkeyHash);

    const expirySec = Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60;
    const expiryBigInt = BigInt(expirySec);

    const credentialSecretField = BigInt('0x' + credentialSecretBytes.toString('hex'));
    const credentialHash = this.poseidonService.poseidon2([
      credentialSecretField,
      userPubkeyHash,
      expiryBigInt,
    ]);
    const credentialHashHex = this.poseidonService.fieldToHex32(credentialHash);

    // Corridor identifier as a field: big-endian bytes of the corridor string.
    // This is the same field the circuit's nullifier and corridor leaf use.
    const corridorIdField = BigInt('0x' + Buffer.from(dto.corridorId, 'utf-8').toString('hex'));
    const corridorIdStr = this.poseidonService.fieldToHex32(corridorIdField);

    // The circuit signs Poseidon2::hash([credential_hash, user_pubkey_hash,
    // credential_expiry], 3) over secp256k1. Signature migration to secp256k1
    // lands in a follow-up commit; keep issuing deterministic credentials.
    const message = Buffer.concat([
      this.poseidonService.fieldToBytes32(credentialHash),
      this.poseidonService.fieldToBytes32(userPubkeyHash),
      this.bigIntToBytes64(expiryBigInt),
    ]);
    const signature = nacl.sign.detached(message, this.issuerPrivateKey);
    const issuerSignature = '0x' + Buffer.from(signature).toString('hex');

    const issuerPubkey = '0x' + this.issuerPublicKey.toString('hex');

    try {
      await pool.query(
        `INSERT INTO credentials
          (wallet_address, kyc_provider, credential_hash, credential_secret,
           issuer_signature, issuer_pubkey, user_pubkey_hash,
           jurisdiction_code, corridor_id, expiry)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (wallet_address, corridor_id)
         DO UPDATE SET
           credential_hash = EXCLUDED.credential_hash,
           credential_secret = EXCLUDED.credential_secret,
           issuer_signature = EXCLUDED.issuer_signature,
           issuer_pubkey = EXCLUDED.issuer_pubkey,
           user_pubkey_hash = EXCLUDED.user_pubkey_hash,
           jurisdiction_code = EXCLUDED.jurisdiction_code,
           expiry = EXCLUDED.expiry,
           is_revoked = false,
           revoked_at = NULL`,
        [
          dto.walletAddress,
          dto.kycProvider,
          credentialHashHex,
          credentialSecret,
          issuerSignature,
          issuerPubkey,
          userPubkeyHashHex,
          corridorInfo.senderJurisdiction,
          corridorIdStr,
          expirySec,
        ]
      );
    } catch (err: any) {
      throw new InternalServerErrorException('Failed to store credential');
    }

    return {
      credentialHash: credentialHashHex,
      issuerSignature,
      issuerPubkey,
      expiry: expirySec,
      jurisdictionCode: corridorInfo.senderJurisdiction,
      credentialSecret,
    };
  }

  async getIssuers(): Promise<IssuerResponse[]> {
    // Circuit main.nr step 5: issuer_pubkey_hash = Poseidon2::hash over the
    // 64 bytes of the secp256k1 point (x || y), one field per byte.
    const pubkeyBytes = this.issuerPublicKey;
    const pubkeyFields = Array.from(pubkeyBytes).map(b => BigInt(b));
    const pubkeyHash = this.poseidonService.poseidon2(pubkeyFields);
    const pubkeyHashHex = this.poseidonService.fieldToHex32(pubkeyHash);

    ISSUERS[0].pubkeyHash = pubkeyHashHex;
    return ISSUERS;
  }

  async revoke(credentialHash: string): Promise<void> {
    const pool = getPool();
    await pool.query(
      `UPDATE credentials SET is_revoked = true, revoked_at = NOW()
       WHERE credential_hash = $1`,
      [credentialHash]
    );
  }

  private bigIntToBytes64(n: bigint): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(n);
    return buf;
  }
}
