import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { getPool } from '../db/client';
import { NullifierService } from '../nullifier/nullifier.service';
import {
  SendPaymentDto,
  BuildPaymentDto,
  SendPaymentResult,
  Sep31AnchorInfo,
} from './dto/send-payment.dto';

@Injectable()
export class PaymentService {
  private readonly logger = new Logger(PaymentService.name);
  private readonly horizonUrl: string;
  private readonly stellarPassphrase: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly nullifierService: NullifierService,
  ) {
    this.horizonUrl = this.configService.get<string>('STELLAR_HORIZON_URL') ?? '';
    this.stellarPassphrase = this.configService.get<string>('STELLAR_PASSPHRASE') ?? '';
  }

  async send(dto: SendPaymentDto): Promise<SendPaymentResult> {
    if (!this.nullifierService.isValidFormat(dto.nullifier)) {
      throw new BadRequestException('Invalid nullifier format — must be a 66-char hex string starting with 0x');
    }

    const pool = getPool();

    const { rows } = await pool.query(
      'SELECT corridor_id FROM nullifiers WHERE nullifier = $1 LIMIT 1',
      [dto.nullifier]
    );
    if (rows.length === 0) {
      throw new BadRequestException('Proof not verified — cannot send payment');
    }

    const { rows: spentRows } = await pool.query(
      'SELECT 1 FROM payments WHERE nullifier = $1 LIMIT 1',
      [dto.nullifier]
    );
    if (spentRows.length > 0) {
      throw new BadRequestException('Nullifier already used for a payment');
    }

    const { TransactionBuilder } = await import('@stellar/stellar-sdk');

    let transaction = TransactionBuilder.fromXDR(dto.signedXdr, this.stellarPassphrase);
    if ('innerTransaction' in transaction) {
      transaction = transaction.innerTransaction;
    }

    const paymentOp = transaction.operations.find((op: any) => op.type === 'payment') as any;
    if (!paymentOp) {
      throw new BadRequestException('Transaction must contain a payment operation');
    }

    const fromAddress = transaction.source;
    const toAddress = typeof paymentOp.to === 'string'
      ? paymentOp.to
      : paymentOp.to.accountId();
    const asset = paymentOp.asset;
    const assetCode = asset.isNative() ? 'XLM' : asset.getCode();
    const assetIssuer = asset.isNative() ? null : asset.getIssuer();
    const txHash = transaction.hash().toString('hex');

    try {
      const { Horizon } = await import('@stellar/stellar-sdk');

      const server = new Horizon.Server(this.horizonUrl);

      const submitResult = await server.submitTransaction(transaction);

      const ledger = submitResult.ledger;

      await pool.query(
        `INSERT INTO payments (nullifier, from_address, to_address, amount, asset_code, asset_issuer, corridor_id, stellar_tx_hash, ledger)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          dto.nullifier,
          fromAddress,
          toAddress,
          paymentOp.amount,
          assetCode,
          assetIssuer,
          rows[0].corridor_id ?? '',
          txHash,
          ledger,
        ]
      );

      return { success: true, txHash, ledger };
    } catch (err: any) {
      this.logger.error(`Payment submission failed: ${err.message}`);
      if (err.response?.data?.extras?.result_codes) {
        const codes = err.response.data.extras.result_codes;
        return { success: false, error: `Stellar error: ${JSON.stringify(codes)}` };
      }
      return { success: false, error: err.message };
    }
  }

  async buildUnsignedPaymentXdr(dto: BuildPaymentDto): Promise<{ unsignedXdr: string }> {
    try {
      const { TransactionBuilder, Operation, Asset, Memo, Horizon } = await import('@stellar/stellar-sdk');

      const server = new Horizon.Server(this.horizonUrl);
      const sourceAccount = await server.loadAccount(dto.fromAddress);

      let asset: any;
      if (dto.asset === 'XLM') {
        asset = Asset.native();
      } else if (dto.assetIssuer) {
        asset = new Asset(dto.asset, dto.assetIssuer);
      } else {
        throw new BadRequestException('assetIssuer is required for non-XLM assets');
      }

      const nullifierHash = Buffer.from(dto.nullifier.slice(2), 'hex').subarray(0, 32);
      const memo = Memo.hash(nullifierHash);

      const tx = new TransactionBuilder(sourceAccount, {
        fee: '1000',
        networkPassphrase: this.stellarPassphrase,
      })
        .addOperation(
          Operation.payment({
            destination: dto.toAddress,
            asset,
            amount: dto.amount,
          })
        )
        .addMemo(memo)
        .setTimeout(300)
        .build();

      const xdr = tx.toEnvelope().toXDR('base64');
      return { unsignedXdr: xdr };
    } catch (err: any) {
      this.logger.error(`Build unsigned XDR failed: ${err.message}`);
      throw err;
    }
  }

  async getHistory(): Promise<any[]> {
    const pool = getPool();
    const { rows } = await pool.query(
      'SELECT * FROM payments ORDER BY created_at DESC LIMIT 50'
    );
    return rows;
  }

  async getSep31AnchorInfo(corridorId: string): Promise<Sep31AnchorInfo> {
    const corridorMap: Record<string, Sep31AnchorInfo> = {
      'NG-PH': {
        anchorUrl: 'https://anchor.example.com',
        assetCode: 'USDC',
        minAmount: '1',
        maxAmount: '10000',
        fields: {
          sender: { name: 'required', email: 'optional' },
        },
      },
      'NG-GB': {
        anchorUrl: 'https://anchor.example.com',
        assetCode: 'USDC',
        minAmount: '1',
        maxAmount: '10000',
        fields: {
          sender: { name: 'required', email: 'optional' },
        },
      },
      'GH-US': {
        anchorUrl: 'https://anchor.example.com',
        assetCode: 'USDC',
        minAmount: '1',
        maxAmount: '5000',
        fields: {
          sender: { name: 'required', email: 'optional' },
        },
      },
      'KE-DE': {
        anchorUrl: 'https://anchor.example.com',
        assetCode: 'USDC',
        minAmount: '1',
        maxAmount: '5000',
        fields: {
          sender: { name: 'required', email: 'optional' },
        },
      },
    };

    const info = corridorMap[corridorId];
    if (!info) {
      throw new BadRequestException(`Unsupported corridor: ${corridorId}`);
    }

    return info;
  }
}
