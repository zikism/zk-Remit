import { PoseidonService, BN254_MODULUS } from './poseidon.service';

/**
 * Reference vectors produced by a nargo 0.36.0 helper circuit
 * (/tmp/opencode/zkhash) so these asserts the JS implementation of
 * Poseidon2 matches the Noir circuit byte-for-byte.
 */
describe('PoseidonService (matches Noir 0.36 Poseidon2::hash)', () => {
  let service: PoseidonService;

  beforeAll(async () => {
    service = new PoseidonService();
    await service.onModuleInit();
  }, 60_000);

  it('should match Poseidon2::hash([500, 12345], 2) from the circuit oracle', () => {
    expect(service.poseidon2([500n, 12345n]).toString()).toBe(
      '167471502961214629332637195682882514874558755618490110074898540022582197023'
    );
  });

  it('should match Poseidon2::hash([0xcafebabe], 1) corridor leaf', () => {
    expect(service.poseidon2([BigInt('0xcafebabe')]).toString()).toBe(
      '11099733308237490468810006363152524310670240653200561608754200473313705075832'
    );
  });

  it('should match Poseidon2::hash([1, 2, 3, 4], 4) multi-block hash', () => {
    expect(service.poseidon2([1n, 2n, 3n, 4n]).toString()).toBe(
      '8615049788434614272061777381929479688528564767750167561409097996914085376441'
    );
  });

  it('should match Poseidon2::hash([1, 2, 3, 4, 5, 6], 6) multi-block hash', () => {
    expect(service.poseidon2([1n, 2n, 3n, 4n, 5n, 6n]).toString()).toBe(
      '3599949537341985477016757037706432767211961921187530182442854462554790207098'
    );
  });

  it('should match the 10-level revocation merkle pad of leaf 99999', () => {
    const root = service.merklePad(99999n, 10);
    const expected = BN254_MODULUS - 5821943418489702188015605312091511648170236105097353286672338772926286477069n;
    expect(root).toBe(expected);
  });

  it('should match the circuit corridor_root built from a corridor leaf', () => {
    const leaf = service.poseidon2([BigInt('0xcafebabe')]);
    const root = service.merklePad(leaf, 10);
    expect(root.toString()).toBe(
      '1919788944370224384828822552308434604911603467097934453868833495645208928148'
    );
  });

  it('should reproduce the circuit corridor tree with an 8-bit index plus 2 zero levels', () => {
    // Simulates the corridor membership check in main.nr: 8 real path
    // siblings, then 2 zero-padded levels, index 0 => all-zero siblings.
    const leaf = service.poseidon2([BigInt('0x' + Buffer.from('NG-PH').toString('hex'))]);
    const path: bigint[] = Array(8).fill(0n);
    const root = service.merkleRoot(leaf, 0n, path, 10);
    expect(root).toBe(service.merklePad(leaf, 10));
  });

  it('should split bytes into field chunks that stay below the modulus', () => {
    const chunks = service.bytesToFieldChunks(Buffer.from('GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7'));
    expect(chunks.length).toBe(2);
    for (const c of chunks) {
      expect(c).toBeGreaterThan(0n);
      expect(c).toBeLessThan(BN254_MODULUS);
    }
  });
});
