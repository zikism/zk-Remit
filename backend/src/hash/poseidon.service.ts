import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { BarretenbergSync, Fr } from '@aztec/bb.js';

export const BN254_MODULUS: bigint = Fr.MODULUS;

/**
 * Poseidon2 hashing that is bit-for-bit identical to the Noir 0.36 circuit.
 *
 * `Poseidon2::hash(inputs, inputs.length)` (fixed-length) in the circuit's
 * stdlib sponge is implemented by Barretenberg's `poseidon2_hash` foreign
 * function. This service calls that same Barretenberg wasm via bb.js, so any
 * value computed here (commitments, nullifiers, merkle leaves/roots, issuer
 * public key hashes) verifies against `circuits/src/main.nr` exactly.
 *
 * The correctness of this mapping is pinned by test vectors generated with a
 * nargo 0.36.0 helper circuit (`/tmp/opencode/zkhash`).
 */
@Injectable()
export class PoseidonService implements OnModuleInit {
  private readonly logger = new Logger(PoseidonService.name);
  private api: BarretenbergSync | undefined;

  async onModuleInit(): Promise<void> {
    const start = Date.now();
    this.api = await BarretenbergSync.new();
    this.logger.log(`Barretenberg initialized in ${Date.now() - start}ms`);
  }

  /** Noir `Poseidon2::hash(inputs, inputs.length)` — fixed-length sponge hash. */
  poseidon2(inputs: bigint[]): bigint {
    if (!this.api) {
      throw new Error('PoseidonService is not initialized (onModuleInit has not run)');
    }
    const out = this.api.poseidon2Hash(inputs.map(x => new Fr(x)));
    return BigInt(out.toString());
  }

  /** Canonical 32-byte big-endian encoding of a field element. */
  fieldToBytes32(field: bigint): Buffer {
    const hex = (field % BN254_MODULUS).toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
  }

  /** '0x' + 32-byte big-endian hex of a field element. */
  fieldToHex32(field: bigint): string {
    return '0x' + this.fieldToBytes32(field).toString('hex');
  }

  /**
   * Split bytes into big-endian field chunks of at most `maxBytes` each.
   * 31 bytes keeps every chunk below the BN254 modulus (254 bits).
   */
  bytesToFieldChunks(bytes: Uint8Array, maxBytes = 31): bigint[] {
    const chunks: bigint[] = [];
    for (let i = 0; i < bytes.length; i += maxBytes) {
      chunks.push(
        BigInt('0x' + Buffer.from(bytes.subarray(i, i + maxBytes)).toString('hex'))
      );
    }
    return chunks;
  }

  /** Circuit corridor leaf: `Poseidon2::hash([corridorIdField], 1)`. */
  corridorLeaf(corridorId: string): bigint {
    const field = BigInt('0x' + Buffer.from(corridorId, 'utf-8').toString('hex'));
    return this.poseidon2([field]);
  }

  /** Circuit jurisdiction leaf: `Poseidon2::hash([jurisdictionCode], 1)`. */
  jurisdictionLeaf(code: number): bigint {
    return this.poseidon2([BigInt(code)]);
  }

  /**
   * Circuit-style zero-padding merkle root. Matches the `compute_*_root`
   * helpers in the circuit: repeatedly `Poseidon2::hash([root, 0], 2)`.
   */
  merklePad(leaf: bigint, levels: number): bigint {
    let root = leaf;
    for (let i = 0; i < levels; i++) {
      root = this.poseidon2([root, 0n]);
    }
    return root;
  }

  /**
   * Binary merkle root following the circuit's `merkle_root` ordering:
   * for each level, when the index bit is 1 hash `[sibling, root]`,
   * otherwise hash `[root, sibling]`. Missing siblings are zero.
   */
  merkleRoot(leaf: bigint, index: bigint, path: bigint[], levels: number): bigint {
    let root = leaf;
    for (let i = 0; i < levels; i++) {
      const sibling = i < path.length ? path[i] : 0n;
      root =
        ((index >> BigInt(i)) & 1n) === 1n
          ? this.poseidon2([sibling, root])
          : this.poseidon2([root, sibling]);
    }
    return root;
  }
}
