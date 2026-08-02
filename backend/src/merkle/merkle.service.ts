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
// entirely empty subtree collapses to the field zero. Approved corridors sit
// at positions 0-255, so the circuit's `merkle_root(corridor_leaf, idx, path)`
// (10 levels, 8-bit index + implicit zero pads at levels 8-9) reproduces this
// root exactly.
const CORRIDOR_TREE_DEPTH = 10;
const CORRIDOR_PATH_LEVELS = 8;

// Revocation tree: same depth-10 sparse-collapse construction over the
// credential hashes of revoked credentials.
const REVOCATION_TREE_DEPTH = 10;

// Eligible sending jurisdictions (the four supported corridors' source
// countries), sorted ascending. Leaf values are `Poseidon2::hash([code], 1)`.
const JURISDICTION_CODES = [288, 404, 566];

// Approved corridors, sorted by their circuit field value (big-endian bytes
// of the corridor string), so the tree is deterministic.
const APPROVED_CORRIDORS = ['GH-US', 'KE-DE', 'NG-GB', 'NG-PH'];

export interface JurisdictionPath {
  index: bigint;
  path: bigint[];
}

export interface CorridorPath {
  indices: number[];
  path: bigint[];
}

export interface RevocationPath {
  leaf: bigint;
  indices: number[];
  path: bigint[];
}

@Injectable()
export class MerkleService {
  constructor(private readonly poseidonService: PoseidonService) {}

  /**
   * Root of the jurisdiction inclusion tree. Circuit-consistent with
   * `build_merkle_path_and_root` + `merkle_root` in `circuits/src/main.nr`.
   */
  jurisdictionRoot(): bigint {
    return this.jurisdictionLevels()[JURISDICTION_FULL_LEVELS][0];
  }

  /**
   * Path and index proving that `code` is an eligible jurisdiction.
   * `path` is the 10 sibling fields for the circuit's `merkle_root`.
   */
  jurisdictionPath(code: number): JurisdictionPath {
    const index = BigInt(JURISDICTION_CODES.indexOf(code));
    if (index < 0n) {
      throw new Error(`Jurisdiction code ${code} is not eligible`);
    }

    const levels = this.jurisdictionLevels();
    const path: bigint[] = [];
    for (let level = 0; level < JURISDICTION_FULL_LEVELS; level++) {
      const sibling = (index >> BigInt(level)) ^ 1n;
      path.push(levels[level][Number(sibling)]);
    }
    for (let level = JURISDICTION_FULL_LEVELS; level < JURISDICTION_TREE_DEPTH; level++) {
      path.push(0n);
    }

    return { index, path };
  }

  /**
   * Root of the approved-corridors sparse tree. Matches the circuit's
   * `merkle_root(corridor_leaf, index, path)` with the corridor leaf at its
   * position and empty subtrees collapsed to zero.
   */
  corridorRoot(): bigint {
    const { entries } = this.corridorEntries();
    return this.sparseRoot(entries, CORRIDOR_TREE_DEPTH);
  }

  /**
   * Path and indices proving that `corridorId` is approved. `indices` is the
   * 8-bit LSB-first position (the circuit's `bits8_to_index`), `path` is the
   * 8 sibling fields; levels 8-9 are implicit zero padding.
   */
  corridorPath(corridorId: string): CorridorPath {
    const { entries, leafPositions } = this.corridorEntries();
    const position = leafPositions.get(corridorId);
    if (position === undefined) {
      throw new Error(`Corridor ${corridorId} is not approved`);
    }

    const indices: number[] = [];
    for (let i = 0; i < CORRIDOR_PATH_LEVELS; i++) {
      indices.push(Number((position >> BigInt(i)) & 1n));
    }

    const path = this.collectSparsePath(entries, position, CORRIDOR_TREE_DEPTH)
      .slice(0, CORRIDOR_PATH_LEVELS);

    return { indices, path };
  }

  /**
   * Root of the revocation accumulator. The circuit's `assert_not_revoked`
   * proves `merkle_root(candidate_leaf, indices, path) == revocation_root`,
   * so the published root must include a deterministic candidate leaf at the
   * first free position (revoked hashes occupy positions 0..n-1).
   */
  async revocationRoot(): Promise<bigint> {
    const { entries } = await this.revocationData();
    return this.sparseRoot(entries, REVOCATION_TREE_DEPTH);
  }

  /**
   * Non-membership path for the first free revocation-tree position `n`:
   * the prover uses the returned `leaf` (the candidate, `hash([n])`) with
   * these `indices`/`path` to reconstruct the published revocation root.
   */
  async revocationPath(): Promise<RevocationPath> {
    const { entries, candidate, position } = await this.revocationData();

    const indices: number[] = [];
    for (let i = 0; i < REVOCATION_TREE_DEPTH; i++) {
      indices.push(Number((position >> BigInt(i)) & 1n));
    }

    return {
      leaf: candidate,
      indices,
      path: this.collectSparsePath(entries, position, REVOCATION_TREE_DEPTH),
    };
  }

  private async revocationData(): Promise<{
    entries: Map<bigint, bigint>;
    candidate: bigint;
    position: bigint;
  }> {
    const entries = await this.revocationEntries();
    const position = BigInt(entries.size);
    const candidate = this.poseidonService.poseidon2([position]);
    entries.set(position, candidate);
    return { entries, candidate, position };
  }

  private jurisdictionLevels(): bigint[][] {
    const leaves = new Array<bigint>(JURISDICTION_LEAVES).fill(0n);
    JURISDICTION_CODES.forEach((code, i) => {
      leaves[i] = this.poseidonService.jurisdictionLeaf(code);
    });

    const levels: bigint[][] = [leaves];
    let level = leaves;
    for (let depth = 0; depth < JURISDICTION_FULL_LEVELS; depth++) {
      const next: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(this.poseidonService.poseidon2([level[i], level[i + 1]]));
      }
      levels.push(next);
      level = next;
    }

    const root = this.poseidonService.merklePad(level[0], JURISDICTION_PAD_LEVELS);
    levels[JURISDICTION_FULL_LEVELS][0] = root;
    return levels;
  }

  private corridorEntries(): { entries: Map<bigint, bigint>; leafPositions: Map<string, bigint> } {
    const entries = new Map<bigint, bigint>();
    const leafPositions = new Map<string, bigint>();
    APPROVED_CORRIDORS.forEach((corridor, i) => {
      const position = BigInt(i);
      entries.set(position, this.poseidonService.corridorLeaf(corridor));
      leafPositions.set(corridor, position);
    });
    return { entries, leafPositions };
  }

  private async revocationEntries(): Promise<Map<bigint, bigint>> {
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
    return entries;
  }

  private sparseRoot(entries: Map<bigint, bigint>, depth: number): bigint {
    const positions = Array.from(entries.keys());
    return this.sparseNode(entries, positions, 0n, 1n << BigInt(depth));
  }

  /** Sibling field at every level from the leaf's position to the root. */
  private collectSparsePath(
    entries: Map<bigint, bigint>,
    position: bigint,
    depth: number,
  ): bigint[] {
    const positions = Array.from(entries.keys());
    const path: bigint[] = [];

    for (let level = 0; level < depth; level++) {
      const size = 1n << BigInt(level);
      const siblingStart = (position & ~(size - 1n)) ^ size;
      path.push(this.sparseNode(entries, positions, siblingStart, size));
    }
    return path;
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
