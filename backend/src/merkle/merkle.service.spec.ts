import { MerkleService } from './merkle.service';
import { PoseidonService } from '../hash/poseidon.service';

jest.mock('../db/client', () => {
  const pool = { query: jest.fn().mockResolvedValue({ rows: [] }) };
  return {
    getPool: jest.fn(() => pool),
    closePool: jest.fn(),
  };
});

/**
 * Reference roots produced by a nargo 0.36.0 helper circuit
 * (/tmp/opencode/zkmerkle) that mirrors the exact tree constructions in
 * circuits/src/main.nr, so these assert the backend trees are byte-for-byte
 * consistent with what the circuit's merkle_root walk will verify.
 */
describe('MerkleService (matches Noir 0.36 circuit trees)', () => {
  let service: MerkleService;
  let poolQuery: jest.Mock;

  beforeAll(async () => {
    const poseidonService = new PoseidonService();
    await poseidonService.onModuleInit();
    service = new MerkleService(poseidonService);
  }, 60_000);

  beforeEach(() => {
    const { getPool } = jest.requireMock('../db/client');
    poolQuery = getPool().query;
    poolQuery.mockResolvedValue({ rows: [] });
  });

  it('should match the 3-leaf jurisdiction root from the circuit oracle', () => {
    expect(service.jurisdictionRoot().toString(16)).toBe(
      '24fd258bcaaa111c9f434e984d85c75cbed93537096f1bf489b9373279ef2d53'
    );
  });

  it('should match the 4-corridor sparse root from the circuit oracle', () => {
    expect(service.corridorRoot().toString(16)).toBe(
      '2ae6c2f478d439f420fc2aff3e3b0281ee56412071103027b3266d3f84dee600'
    );
  });

  it('should match the two-revoked-hash root from the circuit oracle', async () => {
    poolQuery.mockResolvedValue({
      rows: [
        { credential_hash: '0x' + 1111111111n.toString(16).padStart(64, '0') },
        { credential_hash: '0x' + 2222222222n.toString(16).padStart(64, '0') },
      ],
    });

    const root = await service.revocationRoot();
    // Root of the tree with the candidate leaf (Poseidon2::hash([2], 1))
    // inserted at position 2, pinned against the nargo 0.36.0 oracle.
    expect(root.toString(16)).toBe(
      '204c1debacc559b7d24df79c20d131e1bec92dbedf6be27958bcd52e1656e2e6'
    );
  });

  it('should place the candidate leaf at position 0 for an empty revocation set', async () => {
    const root = await service.revocationRoot();
    // Candidate Poseidon2::hash([0], 1) at position 0, hashed up 10 levels.
    expect('0x' + root.toString(16).padStart(64, '0')).toBe(
      '0x097ce8473506051524c0eb452870e04fadc52385c087b750f52874f05a299c78'
    );
  });

  it('should provide a jurisdiction path that rehashes to the published root', () => {
    const { index, path } = service.jurisdictionPath(566);
    expect(index).toBe(2n);
    expect(path).toHaveLength(10);
    // merkle_root(leaf, index, path) must equal the published jurisdiction root.
    const leaf = service['poseidonService'].jurisdictionLeaf(566);
    const poseidon = service['poseidonService'];
    let root = leaf;
    for (let i = 0; i < 10; i++) {
      root =
        ((index >> BigInt(i)) & 1n) === 1n
          ? poseidon.poseidon2([path[i], root])
          : poseidon.poseidon2([root, path[i]]);
    }
    expect(root).toBe(service.jurisdictionRoot());
  });

  it('should provide a corridor path that rehashes to the published root', () => {
    const { indices, path } = service.corridorPath('NG-PH');
    // NG-PH sits at position 3 (binary 11, LSB-first).
    expect(indices).toEqual([1, 1, 0, 0, 0, 0, 0, 0]);
    expect(path).toHaveLength(8);
    // Circuit: corridor_idx = bits8_to_index(indices); merkle_root(leaf, idx, path padded to 10).
    const poseidon = service['poseidonService'];
    const leaf = poseidon.corridorLeaf('NG-PH');
    let idx = 0n;
    for (let i = 0; i < indices.length; i++) {
      idx |= BigInt(indices[i]) << BigInt(i);
    }
    const padded = [...path, 0n, 0n];
    let root = leaf;
    for (let i = 0; i < 10; i++) {
      root =
        ((idx >> BigInt(i)) & 1n) === 1n
          ? poseidon.poseidon2([padded[i], root])
          : poseidon.poseidon2([root, padded[i]]);
    }
    expect(root).toBe(service.corridorRoot());
  });

  it('should provide a revocation path that rehashes to the published root', async () => {
    poolQuery.mockResolvedValue({
      rows: [
        { credential_hash: '0x' + 1111111111n.toString(16).padStart(64, '0') },
        { credential_hash: '0x' + 2222222222n.toString(16).padStart(64, '0') },
      ],
    });

    const { leaf, indices, path } = await service.revocationPath();
    const poseidon2 = service['poseidonService'].poseidon2.bind(service['poseidonService']);
    expect(leaf).toBe(poseidon2([2n]));
    expect(path).toHaveLength(10);
    expect(indices).toHaveLength(10);
    // Position 2 (binary 10, LSB-first) — the first free slot.
    expect(indices).toEqual([0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);

    let idx = 0n;
    for (let i = 0; i < indices.length; i++) {
      idx |= BigInt(indices[i]) << BigInt(i);
    }
    let root = leaf;
    for (let i = 0; i < 10; i++) {
      root =
        ((idx >> BigInt(i)) & 1n) === 1n
          ? poseidon2([path[i], root])
          : poseidon2([root, path[i]]);
    }
    expect(root).toBe(await service.revocationRoot());
  });
});
