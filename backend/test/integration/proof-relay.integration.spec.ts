import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ProofService } from '../../src/proof/proof.service';
import { ProofVerificationService } from '../../src/proof/proof-verification.service';
import { NullifierService } from '../../src/nullifier/nullifier.service';
import { RelayProofDto, PublicInputsDto } from '../../src/proof/dto/relay-proof.dto';
import { BadRequestException } from '@nestjs/common';

jest.mock('../../src/db/client', () => ({
  getPool: jest.fn(() => ({
    query: jest.fn().mockResolvedValue({ rows: [] }),
  })),
  closePool: jest.fn(),
}));

jest.mock('@stellar/stellar-sdk', () => {
  const mockServer = {
    getAccount: jest.fn().mockResolvedValue({
      sequenceNumber: '123',
      id: 'GAXK...',
      accountId: jest.fn().mockReturnValue('GAXK...'),
    }),
    simulateTransaction: jest.fn().mockResolvedValue({
      _mockData: true,
      result: { value: jest.fn().mockReturnValue(true) },
    }),
    sendTransaction: jest.fn().mockResolvedValue({
      status: 'PENDING',
      hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    }),
    getTransaction: jest.fn().mockResolvedValue({
      status: 'NOT_FOUND',
    }),
  };

  const mockContract = {
    call: jest.fn().mockReturnValue({ _mockOp: true }),
  };

  return {
    SorobanRpc: {
      Server: jest.fn(() => mockServer),
      Api: {
        GetTransactionStatus: {
          SUCCESS: 'SUCCESS',
          FAILED: 'FAILED',
          NOT_FOUND: 'NOT_FOUND',
        },
      },
    },
    xdr: {
      ScVal: {
        scvBytes: jest.fn((bytes) => ({
          _type: 'bytes',
          _value: bytes,
          value: jest.fn().mockReturnValue(true),
        })),
      },
    },
    Contract: jest.fn(() => mockContract),
    Keypair: {
      fromSecret: jest.fn(() => ({
        publicKey: jest.fn().mockReturnValue('GAXK...'),
      })),
    },
    TransactionBuilder: class {
      static fromXDR() {
        return {
          hash: jest.fn().mockReturnValue(Buffer.from('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890', 'hex')),
        };
      }

      constructor() {}

      addOperation() {
        return this;
      }

      setTimeout() {
        return this;
      }

      build() {
        return { sign: jest.fn() };
      }
    },
    Horizon: {
      Server: jest.fn(),
    },
    Asset: {
      native: jest.fn(),
    },
    Operation: {
      payment: jest.fn(),
    },
    Memo: {
      hash: jest.fn(),
    },
  };
});

describe('ProofService Integration', () => {
  let proofService: ProofService;
  let nullifierService: NullifierService;
  let verifierService: ProofVerificationService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProofService,
        NullifierService,
        ProofVerificationService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const config: Record<string, string> = {
                VERIFIER_CONTRACT_ID: 'CA3D5R2V6Z3Q5KJ7M9N1P3R5T7V9X2C4E6G8',
                STELLAR_RPC_URL: 'https://soroban-testnet.stellar.org',
                STELLAR_PASSPHRASE: 'Test SDF Network ; September 2015',
                DEPLOYER_SECRET_KEY: 'SAV75E7RY5Q6Z3Q5KJ7M9N1P3R5T7V9X2C4E6G8A1B2C3D4F5G6H7J8K9L0',
                STELLAR_HORIZON_URL: 'https://horizon-testnet.stellar.org',
                ISSUER_PRIVATE_KEY: 'a'.repeat(128),
                ISSUER_PUBLIC_KEY: 'b'.repeat(64),
              };
              return config[key] ?? undefined;
            }),
          },
        },
      ],
    }).compile();

    proofService = module.get<ProofService>(ProofService);
    nullifierService = module.get<NullifierService>(NullifierService);
    verifierService = module.get<ProofVerificationService>(ProofVerificationService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const validPublicInputs: PublicInputsDto = {
    nullifier: '0x' + 'a'.repeat(64),
    issuer_pubkey_hash: '0x' + 'b'.repeat(64),
    payment_asset: '0x' + 'c'.repeat(64),
    aml_threshold: 10000,
    corridor_id: '0x' + 'd'.repeat(64),
    amount_commitment: '0x' + 'e'.repeat(64),
    revocation_root: '0x' + 'f'.repeat(64),
    approved_corridors_root: '0x' + '0'.repeat(64),
    allowed_jurisdictions_root: '0x' + '1'.repeat(64),
  };

  it('should encode public inputs in circuit byte order', () => {
    const buf = proofService.getPublicInputBytes(validPublicInputs);
    expect(buf.length).toBe(264);

    const expectField = (start: number, hex: string) => {
      expect(buf.subarray(start, start + 32).toString('hex')).toBe(hex);
    };

    // Layout MUST mirror the circuit public params in main.nr:
    // nullifier, issuer_pubkey_hash, payment_asset, aml_threshold,
    // corridor_id, allowed_jurisdictions_root, amount_commitment,
    // revocation_root, approved_corridors_root.
    expectField(0, 'a'.repeat(64));
    expectField(32, 'b'.repeat(64));
    expectField(64, 'c'.repeat(64));
    const amlBytes = buf.subarray(96, 104);
    expect(amlBytes.readBigUInt64BE()).toBe(BigInt(10000));
    expectField(104, 'd'.repeat(64));
    expectField(136, '1'.repeat(64));
    expectField(168, 'e'.repeat(64));
    expectField(200, 'f'.repeat(64));
    expectField(232, '0'.repeat(64));
  });

  it('should reject nullifier already used locally', async () => {
    jest.spyOn(nullifierService, 'isUsed').mockResolvedValue({
      used: true,
      source: 'local',
    });

    const dto: RelayProofDto = {
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: validPublicInputs,
    };

    const result = await proofService.relay(dto);
    expect(result.verified).toBe(false);
    expect(result.error).toBe('Nullifier already used');
  });

  it('should run the off-chain gate when VERIFY_OFFCHAIN is enabled and reject on failure', async () => {
    jest.spyOn(nullifierService, 'isUsed').mockResolvedValue({
      used: false,
      source: 'fresh',
    });
    jest.spyOn(verifierService, 'verify').mockResolvedValue({
      enabled: true,
      verified: false,
      error: 'Off-chain verification error: proof rejected',
    });

    const dto: RelayProofDto = {
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: validPublicInputs,
    };

    const result = await proofService.relay(dto);
    expect(result.verified).toBe(false);
    expect(result.error).toBe('Off-chain verification error: proof rejected');

    // No Stellar tx should ever be attempted for a failed proof.
    const { SorobanRpc } = require('@stellar/stellar-sdk');
    expect(SorobanRpc.Server().getTransaction).not.toHaveBeenCalled();
  });

  it('should skip the off-chain gate when VERIFY_OFFCHAIN is disabled', async () => {
    jest.spyOn(nullifierService, 'isUsed').mockResolvedValue({
      used: false,
      source: 'fresh',
    });
    jest.spyOn(verifierService, 'verify').mockResolvedValue({
      enabled: false,
      verified: false,
      error: 'Off-chain verification is disabled (VERIFY_OFFCHAIN unset)',
    });

    const mockStellarSdk = require('@stellar/stellar-sdk');
    mockStellarSdk.SorobanRpc.Server().sendTransaction.mockResolvedValue({
      status: 'PENDING',
      hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    });
    mockStellarSdk.SorobanRpc.Server().getTransaction.mockResolvedValue({
      status: 'SUCCESS',
      returnValue: { value: jest.fn().mockReturnValue(true) },
    });

    const dto: RelayProofDto = {
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: validPublicInputs,
    };

    const result = await proofService.relay(dto);
    expect(result.verified).toBe(true);
    expect(result.txHash).toBe('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890');
  });

  it('should reject invalid proof format (too short)', async () => {
    const dto: RelayProofDto = {
      proof: '0xabcd',
      publicInputs: validPublicInputs,
    };

    await expect(proofService.relay(dto)).rejects.toThrow(BadRequestException);
  });

  it('should reject non-hex proof', async () => {
    const dto: RelayProofDto = {
      proof: '0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
      publicInputs: validPublicInputs,
    };

    await expect(proofService.relay(dto)).rejects.toThrow(BadRequestException);
  });

  it('should reject invalid nullifier format', async () => {
    const badInputs = { ...validPublicInputs, nullifier: 'invalid' };
    const dto: RelayProofDto = {
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: badInputs,
    };

    await expect(proofService.relay(dto)).rejects.toThrow(BadRequestException);
  });

  it('should reject invalid issuer_pubkey_hash format', async () => {
    const badInputs = { ...validPublicInputs, issuer_pubkey_hash: '0x123' };
    const dto: RelayProofDto = {
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: badInputs,
    };

    await expect(proofService.relay(dto)).rejects.toThrow(BadRequestException);
  });

  it('should handle Soroban timeout gracefully', async () => {
    jest.useFakeTimers();

    const mockStellarSdk = require('@stellar/stellar-sdk');
    const mockServer = mockStellarSdk.SorobanRpc.Server();

    mockServer.getTransaction.mockResolvedValue({
      status: 'NOT_FOUND',
    });

    jest.spyOn(nullifierService, 'isUsed').mockResolvedValue({
      used: false,
      source: 'fresh',
    });

    const relayPromise = proofService.relay({
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: validPublicInputs,
    });

    await jest.advanceTimersByTimeAsync(31000);
    const result = await relayPromise;

    expect(result.verified).toBe(false);
    expect(result.error).toContain('timeout');

    jest.useRealTimers();
  });

  it('should reject negative aml_threshold', async () => {
    const badInputs = { ...validPublicInputs, aml_threshold: -1 };
    const dto: RelayProofDto = {
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: badInputs,
    };

    await expect(proofService.relay(dto)).rejects.toThrow(BadRequestException);
  });

  it('should handle Soroban transaction error', async () => {
    const mockStellarSdk = require('@stellar/stellar-sdk');
    const mockServer = mockStellarSdk.SorobanRpc.Server();

    mockServer.sendTransaction.mockResolvedValue({
      status: 'ERROR',
      errorResult: {
        result: () => 'HostError: Contract invocation failed',
      },
    });

    jest.spyOn(nullifierService, 'isUsed').mockResolvedValue({
      used: false,
      source: 'fresh',
    });

    const result = await proofService.relay({
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: validPublicInputs,
    });

    expect(result.verified).toBe(false);
    expect(result.error).toContain('Soroban transaction failed');
  });

  it('should relay a valid proof successfully and record nullifier', async () => {
    const recordSpy = jest.spyOn(nullifierService, 'record').mockResolvedValue(undefined);
    jest.spyOn(nullifierService, 'isUsed').mockResolvedValue({
      used: false,
      source: 'fresh',
    });

    const mockStellarSdk = require('@stellar/stellar-sdk');
    mockStellarSdk.SorobanRpc.Server().sendTransaction.mockResolvedValue({
      status: 'PENDING',
      hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    });
    mockStellarSdk.SorobanRpc.Server().getTransaction.mockResolvedValue({
      status: 'SUCCESS',
      returnValue: { value: jest.fn().mockReturnValue(true) },
    });

    const result = await proofService.relay({
      proof: '0x' + 'ab'.repeat(100),
      publicInputs: validPublicInputs,
    });

    expect(result.verified).toBe(true);
    expect(result.txHash).toBeDefined();
    expect(recordSpy).toHaveBeenCalledWith(
      validPublicInputs.nullifier,
      '',
      validPublicInputs.corridor_id,
      expect.any(String),
    );
  });
});
