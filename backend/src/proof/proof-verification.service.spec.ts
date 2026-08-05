import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ProofVerificationService } from './proof-verification.service';
import { PublicInputsDto } from './dto/relay-proof.dto';
import { join } from 'path';

const mockVerifyProof = jest.fn();

jest.mock('@aztec/bb.js', () => ({
  UltraHonkBackend: jest.fn().mockImplementation(() => ({
    verifyProof: (args: unknown) => mockVerifyProof(args),
  })),
}));

const CIRCUIT_PATH = join(__dirname, '../../circuits/zk_compliance.json');

function configService(values: Record<string, string>) {
  return {
    get: jest.fn((key: string) => values[key]),
  } as unknown as ConfigService;
}

const field = (lastByte: string) => '0x' + '00'.repeat(31) + lastByte;

const inputs: PublicInputsDto = {
  nullifier: field('11'),
  issuer_pubkey_hash: field('22'),
  payment_asset: field('33'),
  aml_threshold: 10000,
  corridor_id: field('44'),
  allowed_jurisdictions_root: field('55'),
  amount_commitment: field('66'),
  revocation_root: field('77'),
  approved_corridors_root: field('88'),
};

describe('ProofVerificationService', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be disabled when VERIFY_OFFCHAIN is unset and never touch bb.js', async () => {
    const service = new ProofVerificationService(configService({}));

    const result = await service.verify('0x' + 'ab'.repeat(100), inputs);

    expect(result.enabled).toBe(false);
    expect(result.verified).toBe(false);
    expect(mockVerifyProof).not.toHaveBeenCalled();
  });

  it('should report unavailable when the circuit artifact is missing', async () => {
    const service = new ProofVerificationService(
      configService({
        VERIFY_OFFCHAIN: 'true',
        ZK_COMPLIANCE_CIRCUIT_PATH: '/nonexistent/zk_compliance.json',
      })
    );

    const result = await service.verify('0x' + 'ab'.repeat(100), inputs);

    expect(result.enabled).toBe(true);
    expect(result.verified).toBe(false);
    expect(result.error).toContain('unavailable');
  });

  it('should verify a proof and feed public inputs to the backend in circuit order', async () => {
    mockVerifyProof.mockResolvedValue(true);

    const service = new ProofVerificationService(
      configService({
        VERIFY_OFFCHAIN: 'true',
        ZK_COMPLIANCE_CIRCUIT_PATH: CIRCUIT_PATH,
      })
    );

    const result = await service.verify('0x' + 'ab'.repeat(100), inputs);

    expect(result.enabled).toBe(true);
    expect(result.verified).toBe(true);
    expect(mockVerifyProof).toHaveBeenCalledTimes(1);

    const { proof, publicInputs } = mockVerifyProof.mock.calls[0][0];
    expect(Buffer.from(proof).toString('hex')).toBe('ab'.repeat(100));
    // Circuit order: nullifier, issuer, asset, aml(u64), corridor,
    // allowed_jurisdictions_root, amount_commitment, revocation_root,
    // approved_corridors_root — NOT the DTO order.
    expect(publicInputs).toEqual([
      '17',
      '34',
      '51',
      '10000',
      '68',
      '85',
      '102',
      '119',
      '136',
    ]);
  });

  it('should surface a rejected proof as verified=false without throwing', async () => {
    mockVerifyProof.mockResolvedValue(false);

    const service = new ProofVerificationService(
      configService({
        VERIFY_OFFCHAIN: 'true',
        ZK_COMPLIANCE_CIRCUIT_PATH: CIRCUIT_PATH,
      })
    );

    const result = await service.verify('0x' + 'ab'.repeat(100), inputs);

    expect(result.enabled).toBe(true);
    expect(result.verified).toBe(false);
  });

  it('should turn a backend exception into a verified=false result', async () => {
    mockVerifyProof.mockRejectedValue(new Error('wasm trap'));

    const service = new ProofVerificationService(
      configService({
        VERIFY_OFFCHAIN: 'true',
        ZK_COMPLIANCE_CIRCUIT_PATH: CIRCUIT_PATH,
      })
    );

    const result = await service.verify('0x' + 'ab'.repeat(100), inputs);

    expect(result.enabled).toBe(true);
    expect(result.verified).toBe(false);
    expect(result.error).toContain('wasm trap');
  });
});
