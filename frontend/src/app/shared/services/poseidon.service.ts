import { Injectable } from '@angular/core';
import { BarretenbergSync, Fr } from '@aztec/bb.js';

export const BN254_MODULUS: bigint = Fr.MODULUS;

/**
 * Poseidon2 hashing that is bit-for-bit identical to the Noir 0.36 circuit
 * (circuits/src/main.nr). Mirrors the backend PoseidonService: Noir's
 * `Poseidon2::hash(inputs, inputs.length)` maps to Barretenberg's
 * `poseidon2_hash`, so every value computed here (nullifier, issuer public
 * key hash, amount commitment, merkle leaves) matches what the circuit
 * verifies.
 */
@Injectable({ providedIn: 'root' })
export class PoseidonService {
  private apiPromise: Promise<BarretenbergSync> | null = null;

  private api(): Promise<BarretenbergSync> {
    if (!this.apiPromise) {
      this.apiPromise = BarretenbergSync.new();
    }
    return this.apiPromise;
  }

  /** Noir `Poseidon2::hash(inputs, inputs.length)` — fixed-length sponge hash. */
  async poseidon2(inputs: bigint[]): Promise<bigint> {
    const api = await this.api();
    const out = api.poseidon2Hash(inputs.map((x) => new Fr(x)));
    return BigInt(out.toString());
  }

  /** '0x' + 32-byte big-endian hex of a field element. */
  fieldToHex32(field: bigint): string {
    return '0x' + (field % BN254_MODULUS).toString(16).padStart(64, '0');
  }

  /**
   * Circuit `issuer_pubkey_hash`: Poseidon2 over the 64 bytes of the
   * secp256k1 public key (x || y), one field per byte.
   */
  async issuerPubkeyHash(pubkeyBytes: number[]): Promise<string> {
    const hash = await this.poseidon2(pubkeyBytes.map((b) => BigInt(b)));
    return this.fieldToHex32(hash);
  }

  /** Circuit `nullifier = Poseidon2::hash([credential_secret, corridor_id], 2)`. */
  async nullifier(credentialSecret: bigint, corridorId: bigint): Promise<string> {
    const hash = await this.poseidon2([credentialSecret, corridorId]);
    return this.fieldToHex32(hash);
  }

  /** Circuit `amount_commitment = Poseidon2::hash([amount, blinding], 2)`. */
  async amountCommitment(amount: number, blinding: bigint): Promise<string> {
    const hash = await this.poseidon2([BigInt(amount), blinding]);
    return this.fieldToHex32(hash);
  }
}
