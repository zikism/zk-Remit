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
      '1760c4255b3d3ba7fcc6517567a41641c4a133b7b9aba08f4ef21d1bd08a86d'
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
    expect(root.toString(16)).toBe(
      '17a4070478338a839a0fdb9bdd3701520d7994c0cf3433b480434bccb7129c91'
    );
  });

  it('should collapse to zero for an empty revocation set', async () => {
    const root = await service.revocationRoot();
    expect(root).toBe(0n);
  });
});
