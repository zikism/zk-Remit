import { readFile } from 'fs/promises';
import { join } from 'path';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { Noir } from '@noir-lang/noir_js';
import { PoseidonService } from '../../src/hash/poseidon.service';
import { MerkleService } from '../../src/merkle/merkle.service';
import { CredentialService } from '../../src/credential/credential.service';
import { corridorConfig } from '../../src/compliance/compliance.config';

jest.mock('../../src/db/client', () => {
  const pool = { query: jest.fn().mockResolvedValue({ rows: [] }) };
  return {
    getPool: jest.fn(() => pool),
    closePool: jest.fn(),
  };
});

// The compiled circuit the frontend proves against (noir 0.36.0).
const CIRCUIT_JSON_PATH = join(
  __dirname,
  '../../../frontend/src/assets/circuits/zk_compliance.json'
);

describe('Circuit consistency (real pipeline -> Noir 0.36 witness)', () => {
  let poseidonService: PoseidonService;
  let merkleService: MerkleService;
  let credentialService: CredentialService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PoseidonService,
        MerkleService,
        CredentialService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) =>
              key === 'ISSUER_PRIVATE_KEY'
                ? 'a'.repeat(64)
                : undefined
            ),
          },
        },
      ],
    }).compile();

    poseidonService = module.get(PoseidonService);
    await poseidonService.onModuleInit();
    merkleService = module.get(MerkleService);
    credentialService = module.get(CredentialService);
  }, 120_000);

  const corridor = 'NG-PH';

  async function buildCircuitInputs(amount: number, blinding: bigint) {
    const config = corridorConfig(corridor);

    // Issue a real credential through the production service (secp256k1
    // signature over the circuit's credential message, circuit-consistent
    // poseidon commitments, 31-byte field-safe secret).
    const credential = await credentialService.issue({
      walletAddress: 'GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7',
      kycProvider: 'mock-issuer',
      corridorId: corridor,
    });

    // Real merkle trees (jurisdiction + corridor + revocation membership).
    const jurisdictionPath = merkleService.jurisdictionPath(credential.jurisdictionCode);
    const corridorPath = merkleService.corridorPath(corridor);
    const revocationPath = await merkleService.revocationPath();

    const pubkeyBytes = Buffer.from(credential.issuerPubkey.slice(2), 'hex');
    const secretField = BigInt(credential.credentialSecret);
    const corridorField = BigInt(credential.corridorId);

    // Mirror the frontend prover's public-input derivation exactly.
    const issuerPubkeyHash = poseidonService.fieldToHex32(
      poseidonService.poseidon2(Array.from(pubkeyBytes).map((b) => BigInt(b)))
    );
    const nullifier = poseidonService.fieldToHex32(
      poseidonService.poseidon2([secretField, corridorField])
    );
    const amountCommitment = poseidonService.fieldToHex32(
      poseidonService.poseidon2([BigInt(amount), blinding])
    );

    return {
      credential_secret: credential.credentialSecret,
      credential_hash: credential.credentialHash,
      issuer_signature: Array.from(Buffer.from(credential.issuerSignature.slice(2), 'hex')),
      issuer_pubkey_x: Array.from(pubkeyBytes.subarray(0, 32)),
      issuer_pubkey_y: Array.from(pubkeyBytes.subarray(32, 64)),
      user_pubkey_hash: credential.userPubkeyHash,
      amount,
      jurisdiction_code: credential.jurisdictionCode,
      credential_expiry: credential.expiry,
      current_timestamp: Math.floor(Date.now() / 1000),
      allowed_jurisdictions_path: jurisdictionPath.path.map((f) =>
        poseidonService.fieldToHex32(f)
      ),
      allowed_jurisdictions_index: '0x' + BigInt(jurisdictionPath.index).toString(16),
      amount_blinding: poseidonService.fieldToHex32(blinding),
      revocation_candidate_leaf: poseidonService.fieldToHex32(revocationPath.leaf),
      revocation_path: revocationPath.path.map((f) => poseidonService.fieldToHex32(f)),
      revocation_indices: revocationPath.indices,
      approved_corridors_path: corridorPath.path.map((f) => poseidonService.fieldToHex32(f)),
      approved_corridors_indices: corridorPath.indices,
      nullifier,
      issuer_pubkey_hash: issuerPubkeyHash,
      payment_asset: '0x00',
      aml_threshold: config.amlThreshold,
      corridor_id: credential.corridorId,
      allowed_jurisdictions_root: poseidonService.fieldToHex32(merkleService.jurisdictionRoot()),
      amount_commitment: amountCommitment,
      revocation_root: poseidonService.fieldToHex32(await merkleService.revocationRoot()),
      approved_corridors_root: poseidonService.fieldToHex32(merkleService.corridorRoot()),
    };
  }

  it('should produce a satisfiable witness from the real issuance + merkle pipeline', async () => {
    jest.setTimeout(120_000);
    const circuitJson = JSON.parse(await readFile(CIRCUIT_JSON_PATH, 'utf-8'));
    expect(circuitJson.noir_version.startsWith('0.36')).toBe(true);

    const inputs = await buildCircuitInputs(500, 123456789n);
    const noir = new Noir(circuitJson);

    // If every constraint is satisfied, execute returns the witness. This is
    // the definitive proof that the credentials, merkle trees, signatures and
    // commitments produced by the backend satisfy the deployed circuit.
    const { witness } = await noir.execute(inputs as any);
    expect(witness).toBeDefined();
    expect(witness.length).toBeGreaterThan(0);
  });

  it('should reject a tampered nullifier (constraints are actually enforced)', async () => {
    jest.setTimeout(120_000);
    const circuitJson = JSON.parse(await readFile(CIRCUIT_JSON_PATH, 'utf-8'));

    const inputs = await buildCircuitInputs(500, 123456789n);
    inputs.nullifier = '0x' + 'ff'.repeat(32);

    const noir = new Noir(circuitJson);
    await expect(noir.execute(inputs as any)).rejects.toThrow();
  });

  it('should enforce the per-corridor AML threshold (amount < aml_threshold)', async () => {
    jest.setTimeout(120_000);
    const circuitJson = JSON.parse(await readFile(CIRCUIT_JSON_PATH, 'utf-8'));
    const config = corridorConfig(corridor);

    // One unit over the configured threshold must be rejected in-circuit.
    const inputs = await buildCircuitInputs(config.amlThreshold, 123456789n);
    const noir = new Noir(circuitJson);
    await expect(noir.execute(inputs as any)).rejects.toThrow();
  });
});
