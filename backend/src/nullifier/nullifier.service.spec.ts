import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { NullifierService } from './nullifier.service';
import { getPool } from '../db/client';

jest.mock('../db/client');

const mockGetContractData = jest.fn();

jest.mock('@stellar/stellar-sdk', () => ({
  SorobanRpc: {
    Server: jest.fn().mockImplementation(() => ({ getContractData: mockGetContractData })),
  },
  xdr: {
    ScVal: {
      scvBytes: (bytes: Buffer) => ({ __type: 'bytes', bytes }),
    },
  },
}));

describe('NullifierService', () => {
  let service: NullifierService;

  const mockQuery = jest.fn();

  beforeEach(() => {
    mockGetContractData.mockReset();
  });

  beforeEach(async () => {
    (getPool as jest.Mock).mockReturnValue({
      query: mockQuery,
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        NullifierService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'VERIFIER_CONTRACT_ID') return 'C123';
              if (key === 'STELLAR_RPC_URL') return 'https://soroban-testnet.stellar.org';
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<NullifierService>(NullifierService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('isValidFormat', () => {
    it('should accept valid 66-char hex string', () => {
      expect(service.isValidFormat('0x' + 'a'.repeat(64))).toBe(true);
    });

    it('should reject string without 0x prefix', () => {
      expect(service.isValidFormat('a'.repeat(64))).toBe(false);
    });

    it('should reject short string', () => {
      expect(service.isValidFormat('0xabc')).toBe(false);
    });

    it('should reject non-hex characters', () => {
      expect(service.isValidFormat('0x' + 'z'.repeat(64))).toBe(false);
    });
  });

  describe('isUsed', () => {
    it('should return fresh for unknown nullifier', async () => {
      mockQuery.mockResolvedValue({ rows: [] });

      const result = await service.isUsed('0x' + 'a'.repeat(64));
      expect(result.used).toBe(false);
      expect(result.source).toBe('fresh');
    });

    it('should return local for DB-stored nullifier', async () => {
      mockQuery.mockResolvedValue({ rows: [{ 1: 1 }] });

      const result = await service.isUsed('0x' + 'a'.repeat(64));
      expect(result.used).toBe(true);
      expect(result.source).toBe('local');
    });

    it('should return onchain and sync row when contract data exists', async () => {
      mockQuery.mockResolvedValue({ rows: [] });
      mockGetContractData.mockResolvedValue({ val: true });

      const result = await service.isUsed('0x' + 'b'.repeat(64));
      expect(result).toEqual({ used: true, source: 'onchain' });
      expect(mockGetContractData).toHaveBeenCalledWith(
        'C123',
        expect.objectContaining({ __type: 'bytes' }),
      );
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO nullifiers'),
        [expect.any(String), 'synced-from-chain'],
      );
    });

    it('should return fresh when contract data is missing (404)', async () => {
      mockQuery.mockResolvedValue({ rows: [] });
      mockGetContractData.mockRejectedValue({ code: 404, message: 'Contract data not found' });

      const result = await service.isUsed('0x' + 'c'.repeat(64));
      expect(result.used).toBe(false);
      expect(result.source).toBe('fresh');
    });

    it('should fail open (fresh) on RPC errors', async () => {
      mockQuery.mockResolvedValue({ rows: [] });
      mockGetContractData.mockRejectedValue(new Error('network down'));

      const result = await service.isUsed('0x' + 'd'.repeat(64));
      expect(result.used).toBe(false);
      expect(result.source).toBe('fresh');
    });
  });

  describe('getCount', () => {
    it('should return count from DB', async () => {
      mockQuery.mockResolvedValue({ rows: [{ count: 5 }] });

      const count = await service.getCount();
      expect(count).toBe(5);
    });
  });
});
