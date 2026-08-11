import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PaymentService } from './payment.service';
import { NullifierService } from '../nullifier/nullifier.service';
import { getPool } from '../db/client';

jest.mock('../db/client');

// Circuit field of the configured NG-PH corridor (compliance.config.ts) and
// its AML threshold. The proof's corridor_id public input carries this field.
const NG_PH_CORRIDOR_FIELD = '0x0000000000000000000000000000000000000000000000000000004e472d5048';
const GH_US_CORRIDOR_FIELD = '0x00000000000000000000000000000000000000000000000000000047482d5553';

const mockSubmitTransaction = jest.fn();

const mockTx = {
  hash: () => Buffer.from('ab', 'hex'),
  source: 'GASOURCE0000000000000000000000000000000000000000000000000000000',
  operations: [
    {
      type: 'payment',
      to: 'GADEST00000000000000000000000000000000000000000000000000000000',
      amount: '100.5',
      asset: {
        isNative: () => false,
        getCode: () => 'USDC',
        getIssuer: () => 'GAISS0000000000000000000000000000000000000000000000000000000',
      },
    },
  ],
};

const mockTxLargeAmount = {
  ...mockTx,
  hash: () => Buffer.from('ab', 'hex'),
  operations: [{ ...mockTx.operations[0], amount: '50000' }],
};

const mockTxNoPayment = {
  hash: () => Buffer.from('cd', 'hex'),
  source: 'GASOURCE0000000000000000000000000000000000000000000000000000000',
  operations: [{ type: 'create_account', to: 'GADEST00000000000000000000000000000000000000000000000000000000' }],
};

jest.mock('@stellar/stellar-sdk', () => ({
  TransactionBuilder: {
    fromXDR: jest.fn(() => mockTx),
  },
  Horizon: {
    Server: jest.fn().mockImplementation(() => ({ submitTransaction: mockSubmitTransaction })),
  },
}));

describe('PaymentService', () => {
  let service: PaymentService;

  const mockQuery = jest.fn();
  const mockIsValidFormat = jest.fn().mockReturnValue(true);

  beforeEach(async () => {
    mockSubmitTransaction.mockReset();
    mockQuery.mockReset();
    mockIsValidFormat.mockReset().mockReturnValue(true);
    (getPool as jest.Mock).mockReturnValue({ query: mockQuery });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PaymentService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'STELLAR_HORIZON_URL') return 'https://horizon-testnet.stellar.org';
              if (key === 'STELLAR_PASSPHRASE') return 'Test SDF Network ; September 2015';
              return undefined;
            }),
          },
        },
        {
          provide: NullifierService,
          useValue: {
            isValidFormat: mockIsValidFormat,
          },
        },
      ],
    }).compile();

    service = module.get<PaymentService>(PaymentService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('send', () => {
    it('should reject invalid nullifier format', async () => {
      mockIsValidFormat.mockReturnValue(false);

      await expect(
        service.send({ nullifier: '0xabc', signedXdr: 'AAAA' }),
      ).rejects.toThrow(BadRequestException);
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it('should reject when proof is not verified', async () => {
      mockQuery.mockImplementation((sql: string) =>
        sql.includes('FROM nullifiers')
          ? Promise.resolve({ rows: [] })
          : Promise.resolve({ rows: [] }),
      );

      await expect(
        service.send({ nullifier: '0x' + 'a'.repeat(64), signedXdr: 'AAAA' }),
      ).rejects.toThrow('Proof not verified');
    });

    it('should reject a nullifier already used for a payment', async () => {
      mockQuery.mockImplementation((sql: string) =>
        sql.includes('FROM nullifiers')
          ? Promise.resolve({ rows: [{ corridor_id: 'corr' }] })
          : Promise.resolve({ rows: [{ 1: 1 }] }),
      );

      await expect(
        service.send({ nullifier: '0x' + 'a'.repeat(64), signedXdr: 'AAAA' }),
      ).rejects.toThrow('Nullifier already used for a payment');
    });

    it('should submit and record payment details from the XDR', async () => {
      mockQuery.mockImplementation((sql: string) =>
        sql.includes('FROM nullifiers')
          ? Promise.resolve({ rows: [{ corridor_id: NG_PH_CORRIDOR_FIELD }] })
          : Promise.resolve({ rows: [] }),
      );
      mockSubmitTransaction.mockResolvedValue({ ledger: 12345 });

      const result = await service.send({
        nullifier: '0x' + 'a'.repeat(64),
        signedXdr: 'AAAA',
      });

      expect(result).toEqual({ success: true, txHash: 'ab', ledger: 12345 });
      expect(mockSubmitTransaction).toHaveBeenCalledTimes(1);

      const insertCall = mockQuery.mock.calls.find(
        ([sql]: [string]) => sql.includes('INSERT INTO payments'),
      );
      expect(insertCall).toBeDefined();
      expect(insertCall[1]).toEqual([
        '0x' + 'a'.repeat(64),
        'GASOURCE0000000000000000000000000000000000000000000000000000000',
        'GADEST00000000000000000000000000000000000000000000000000000000',
        '100.5',
        'USDC',
        'GAISS0000000000000000000000000000000000000000000000000000000',
        NG_PH_CORRIDOR_FIELD,
        'ab',
        12345,
      ]);
    });

    it('should reject a payment above the corridor AML threshold', async () => {
      const { TransactionBuilder } = await import('@stellar/stellar-sdk');
      (TransactionBuilder.fromXDR as jest.Mock).mockReturnValueOnce(mockTxLargeAmount);
      mockQuery.mockImplementation((sql: string) =>
        sql.includes('FROM nullifiers')
          ? Promise.resolve({ rows: [{ corridor_id: GH_US_CORRIDOR_FIELD }] })
          : Promise.resolve({ rows: [] }),
      );

      await expect(
        service.send({ nullifier: '0x' + 'a'.repeat(64), signedXdr: 'AAAA' }),
      ).rejects.toThrow('AML threshold');
      expect(mockSubmitTransaction).not.toHaveBeenCalled();
    });

    it('should reject a payment whose nullifier corridor is not configured', async () => {
      mockQuery.mockImplementation((sql: string) =>
        sql.includes('FROM nullifiers')
          ? Promise.resolve({ rows: [{ corridor_id: '0x' + 'ff'.repeat(32) }] })
          : Promise.resolve({ rows: [] }),
      );

      await expect(
        service.send({ nullifier: '0x' + 'a'.repeat(64), signedXdr: 'AAAA' }),
      ).rejects.toThrow('Corridor not configured');
      expect(mockSubmitTransaction).not.toHaveBeenCalled();
    });

    it('should reject a transaction without a payment operation', async () => {
      const { TransactionBuilder } = await import('@stellar/stellar-sdk');
      (TransactionBuilder.fromXDR as jest.Mock).mockReturnValueOnce(mockTxNoPayment);
      mockQuery.mockImplementation((sql: string) =>
        sql.includes('FROM nullifiers')
          ? Promise.resolve({ rows: [{ corridor_id: 'corr' }] })
          : Promise.resolve({ rows: [] }),
      );

      await expect(
        service.send({ nullifier: '0x' + 'a'.repeat(64), signedXdr: 'AAAA' }),
      ).rejects.toThrow('Transaction must contain a payment operation');
    });
  });
});
