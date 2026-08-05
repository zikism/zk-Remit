import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RootRotationService } from './root-rotation.service';
import { MerkleService } from '../merkle/merkle.service';
import { PoseidonService } from '../hash/poseidon.service';

jest.mock('../db/client', () => {
  const pool = { query: jest.fn().mockResolvedValue({ rows: [] }) };
  return {
    getPool: jest.fn(() => pool),
    closePool: jest.fn(),
  };
});

const mockSendResponse = { status: 'SENT', hash: '0xrotatedtx' };

jest.mock('@stellar/stellar-sdk', () => {
  const mockServer = {
    getAccount: jest.fn().mockResolvedValue({ sequence: '1' }),
    simulateTransaction: jest.fn().mockResolvedValue({ something: true }),
    sendTransaction: jest.fn().mockResolvedValue(mockSendResponse),
  };
  return {
    SorobanRpc: {
      Server: jest.fn().mockImplementation(() => mockServer),
    },
    xdr: {
      ScVal: {
        scvBytes: jest.fn((b: Buffer) => ({ type: 'bytes', bytes: b })),
        scvAddress: jest.fn((a: unknown) => ({ type: 'address', address: a })),
      },
    },
    Contract: jest.fn().mockImplementation(() => ({
      call: jest.fn((method: string, ...args: unknown[]) => ({ method, args })),
    })),
    Keypair: {
      fromSecret: jest.fn(() => ({
        publicKey: jest.fn().mockReturnValue('GBZEID7KWIKJPJ36VY5OPNCVIQWHWLKG7KJA6N37GZ6AAZLUPXA2AS4D'),
      })),
    },
    TransactionBuilder: jest.fn().mockImplementation(() => ({
      addOperation: jest.fn().mockReturnThis(),
      setTimeout: jest.fn().mockReturnThis(),
      build: jest.fn(() => ({ sign: jest.fn() })),
    })),
    Address: jest.fn().mockImplementation(() => ({
      toScAddress: jest.fn(() => ({ _scAddress: true })),
    })),
    __mockServer: mockServer,
  };
});

describe('RootRotationService', () => {
  let service: RootRotationService;

  const envConfig: Record<string, unknown> = {
    VERIFIER_CONTRACT_ID: 'CAABB',
    STELLAR_RPC_URL: 'https://rpc.example',
    STELLAR_PASSPHRASE: 'Test SDF Network ; September 2015',
    DEPLOYER_SECRET_KEY: 'SAABB',
  };

  const makeService = async (overrides: Record<string, unknown> = {}) => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RootRotationService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) =>
              key in overrides ? overrides[key] : envConfig[key]
            ),
          },
        },
        {
          provide: MerkleService,
          useValue: {
            jurisdictionRoot: jest.fn(() => 0x11n),
            corridorRoot: jest.fn(() => 0x22n),
            revocationRoot: jest.fn(() => 0x33n),
          },
        },
        {
          provide: PoseidonService,
          useValue: {
            fieldToHex32: jest.fn((f: bigint) => '0x' + f.toString(16).padStart(64, '0')),
          },
        },
      ],
    }).compile();

    return module.get<RootRotationService>(RootRotationService);
  };

  beforeEach(async () => {
    jest.clearAllMocks();
  });

  it('should return the current circuit-consistent roots', async () => {
    service = await makeService();
    const roots = await service.getCurrentRoots();
    expect(roots.jurisdictionRoot).toBe('0x' + '0'.repeat(62) + '11');
    expect(roots.corridorRoot).toBe('0x' + '0'.repeat(62) + '22');
    expect(roots.revocationRoot).toBe('0x' + '0'.repeat(62) + '33');
  });

  it('should refuse to publish when Stellar config is missing', async () => {
    service = await makeService({
      VERIFIER_CONTRACT_ID: '',
      STELLAR_RPC_URL: '',
      DEPLOYER_SECRET_KEY: '',
    });
    await expect(service.publishRoots()).rejects.toThrow('required for root rotation');
  });

  it('should build and submit update_roots with the current roots', async () => {
    service = await makeService();

    const { Contract, TransactionBuilder } = await import('@stellar/stellar-sdk');

    const result = await service.publishRoots();

    expect(Contract).toHaveBeenCalledWith('CAABB');
    expect(result.txHash).toBe('0xrotatedtx');
    expect(result.revocationRoot).toBe('0x' + '0'.repeat(62) + '33');

    const mockContractInstance = (Contract as jest.Mock).mock.results[0].value;
    const call = mockContractInstance.call;
    expect(call).toHaveBeenCalledTimes(1);
    const [method, ...args] = call.mock.calls[0];
    expect(method).toBe('update_roots');
    expect(TransactionBuilder).toHaveBeenCalledTimes(1);
    // admin address + revocation_root + corridor_root + jurisdiction_root
    expect(args.length).toBe(4);
  });

  it('should surface submission errors as ServiceUnavailableException', async () => {
    service = await makeService();

    const sdk = await import('@stellar/stellar-sdk');
    (sdk as unknown as { __mockServer: { sendTransaction: jest.Mock } }).__mockServer.sendTransaction
      .mockRejectedValueOnce(new Error('network down'));

    await expect(service.publishRoots()).rejects.toThrow('Root rotation failed: network down');
  });
});
