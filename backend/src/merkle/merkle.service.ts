import { Injectable } from '@nestjs/common';
import { getPool } from '../db/client';
import { PoseidonService } from '../hash/poseidon.service';

// Jurisdiction tree: a fixed 16-leaf binary tree (the circuit's
// `build_merkle_path_and_root`) followed by six zero-padding levels, for a
// total depth of 10 (the circuit's `merkle_root`). Unset leaves are zero but
// internal nodes are always hashed (no collapse).
const JURISDICTION_LEAVES = 16;
const JURISDICTION_TREE_DEPTH = 10;
const JURISDICTION_FULL_LEVELS = 4;
const JURISDICTION_PAD_LEVELS = JURISDICTION_TREE_DEPTH - JURISDICTION_FULL_LEVELS;

// Corridor tree: a depth-10 sparse Merkle tree (1024 positions) where an
// entirely empty subtree collapses to the field zero, matching the circuit's
// `merkle_root` walk with zero siblings. Two extra zero-padding levels align
// it with the circuit's 8-bit corridor index + 2 padding levels.
const CORRIDOR_TREE_DEPTH = 10;
const CORRIDOR_PAD_LEVELS = 2;

// Revocation tree: same depth-10 sparse-collapse construction over the
// credential hashes of revoked credentials.
const REVOCATION_TREE_DEPTH = 10;

// Eligible sending jurisdictions (the four supported corridors' source
// countries), sorted ascending. Leaf values are `Poseidon2::hash([code], 1)`.
const JURISDICTION_CODES = [288, 404, 566];

// Approved corridors, sorted by their circuit field value (big-endian bytes
// of the corridor string), so the tree is deterministic.
const APPROVED_CORRIDORS = ['GH-US', 'KE-DE', 'NG-GB', 'NG-PH'];

@Injectable()
export class MerkleService {
  constructor(private readonly poseidonService: PoseidonService) {}

  /**
   * Root of the jurisdiction inclusion tree. Circuit-consistent with
   * `build_merkle_path_and_root` + `merkle_root` in `circuits/src/main.nr`.
   */
  jurisdictionRoot(): bigint {
    const leaves = new Array<bigint>(JURISDICTION_LEAVES).fill(0n);
    JURISDICTION_CODES.forEach((code, i) => {
      leaves[i] = this.poseidonService.jurisdictionLeaf(code);
    });

    let level = leaves;
    while (level.length > 1) {
      const next: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(this.poseidonService.poseidon2([level[i], level[i + 1]]));
      }
      level = next;
    }

    return this.poseidonService.merklePad(level[0], JURISDICTION_PAD_LEVELS);
  }

  /**
   * Root of the approved-corridors sparse tree. Matches the circuit's
   * `merkle_root(corridor_leaf, index, path)` with the corridor leaf at its
   * position and empty subtrees collapsed to zero.
   */
  corridorRoot(): bigint {
    const entries = new Map<bigint, bigint>();
    APPROVED_CORRIDORS.forEach((corridor, i) => {
      entries.set(BigInt(i), this.poseidonService.corridorLeaf(corridor));
    });

    const root = this.sparseRoot(entries, CORRIDOR_TREE_DEPTH);
    return this.poseidonService.merklePad(root, CORRIDOR_PAD_LEVELS);
  }

  /**
   * Root of the revocation accumulator over revoked credential hashes. Empty
   * (non-revoked) leaves are zero, so a credential not in the set proves
   * non-membership via the circuit's `assert_not_revoked`.
   */
  async revocationRoot(): Promise<bigint> {
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT credential_hash FROM credentials
       WHERE is_revoked = true
       ORDER BY revoked_at, credential_hash`
    );

    const entries = new Map<bigint, bigint>();
    rows.forEach((row: { credential_hash: string }, i) => {
      entries.set(BigInt(i), BigInt(row.credential_hash));
    });

    return this.sparseRoot(entries, REVOCATION_TREE_DEPTH);
  }

  private sparseRoot(entries: Map<bigint, bigint>, depth: number): bigint {
    const positions = Array.from(entries.keys());
    return this.sparseNode(entries, positions, 0n, 1n << BigInt(depth));
  }

  private sparseNode(
    entries: Map<bigint, bigint>,
    positions: bigint[],
    offset: bigint,
    span: bigint,
  ): bigint {
    if (span === 1n) {
      return entries.get(offset) ?? 0n;
    }
    if (!positions.some((p) => p >= offset && p < offset + span)) {
      return 0n;
    }

    const half = span >> 1n;
    const left = this.sparseNode(entries, positions, offset, half);
    const right = this.sparseNode(entries, positions, offset + half, half);
    if (left === 0n && right === 0n) {
      return 0n;
    }
    return this.poseidonService.poseidon2([left, right]);
  }
}
