import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { getPool } from '../db/client';
import { PoseidonService } from '../hash/poseidon.service';
import { corridorConfig } from '../compliance/compliance.config';
import { IssueCredentialDto, CredentialResponse, IssuerResponse } from './dto/issue-credential.dto';

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

    // The circuit verifies a secp256k1 ECDSA signature over
    // Poseidon2::hash([credential_hash, user_pubkey_hash, expiry], 3), so the
    // issuer key is a secp256k1 private scalar. The public key (x || y) is
    // derived here so it always matches the private key.
    if (!privHex || privHex.length !== 64) {
      throw new Error('ISSUER_PRIVATE_KEY must be a 32-byte secp256k1 hex string (64 chars)');
    }

    this.issuerPrivateKey = Buffer.from(privHex, 'hex');
    // Uncompressed point (0x04 || x || y) -> strip the 0x04 prefix.
    const publicKey = secp256k1.getPublicKey(this.issuerPrivateKey, false);
    this.issuerPublicKey = Buffer.from(publicKey.subarray(1));
  }

  async issue(dto: IssueCredentialDto): Promise<CredentialResponse> {
    const pool = getPool();

    const corridorInfo = corridorConfig(dto.corridorId);

    // 31 random bytes keeps the credential secret below the BN254 field
    // modulus (254 bits), so the circuit can use it as a Field input. A full
    // 32-byte random value exceeds the modulus ~75% of the time and would be
    // rejected by noir's witness builder.
    const credentialSecretBytes = randomBytes(31);
    const credentialSecret = '0x00' + credentialSecretBytes.toString('hex');

    // Circuit-consistent Poseidon2 over the user identity bytes (chunked so
    // each field fits below the BN254 modulus).
    const userPubkeyHash = this.poseidonService.poseidon2(
      this.poseidonService.bytesToFieldChunks(Buffer.from(dto.walletAddress, 'utf-8'))
    );
    const userPubkeyHashHex = this.poseidonService.fieldToHex32(userPubkeyHash);

    const expirySec = Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60;
    const expiryBigInt = BigInt(expirySec);

    const credentialSecretField = BigInt('0x00' + credentialSecretBytes.toString('hex'));
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

    // The circuit (main.nr) verifies the issuer's secp256k1 ECDSA signature
    // over credential_msg = Poseidon2::hash([credential_hash,
    // user_pubkey_hash, credential_expiry], 3), encoded as 32 bytes
    // big-endian. Sign that exact message.
    const credentialMsg = this.poseidonService.poseidon2([
      credentialHash,
      userPubkeyHash,
      expiryBigInt,
    ]);
    const message = this.poseidonService.fieldToBytes32(credentialMsg);
    // prehash:false signs the 32 message bytes directly. @noble/curves v2
    // defaults to prehash:true (SHA-256 first), which the circuit's
    // ecdsa_secp256k1::verify_signature does NOT perform.
    const signature = secp256k1.sign(message, this.issuerPrivateKey, { prehash: false });
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
      credentialSecret,
      issuerSignature,
      issuerPubkey,
      userPubkeyHash: userPubkeyHashHex,
      corridorId: corridorIdStr,
      expiry: expirySec,
      jurisdictionCode: corridorInfo.senderJurisdiction,
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
}
