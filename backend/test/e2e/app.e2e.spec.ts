import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../src/app.module';

process.env.ISSUER_PRIVATE_KEY = 'a'.repeat(64);

jest.mock('../../src/db/client', () => ({
  getPool: jest.fn(() => ({
    query: jest.fn().mockResolvedValue({ rows: [] }),
  })),
  closePool: jest.fn(),
}));

jest.mock('@stellar/stellar-sdk', () => {
  const mockServer = {
    getAccount: jest.fn().mockResolvedValue({ sequenceNumber: '123', id: 'GAXK...' }),
    simulateTransaction: jest.fn().mockResolvedValue({ _mock: true }),
    sendTransaction: jest.fn().mockResolvedValue({ status: 'PENDING', hash: '0xabcd' }),
    getTransaction: jest.fn().mockResolvedValue({
      status: 'SUCCESS',
      returnValue: { value: () => true },
    }),
  };

  return {
    SorobanRpc: {
      Server: jest.fn(() => mockServer),
      Api: { GetTransactionStatus: { SUCCESS: 'SUCCESS', FAILED: 'FAILED', NOT_FOUND: 'NOT_FOUND' } },
    },
    xdr: { ScVal: { scvBytes: jest.fn((b) => ({ _bytes: b })) } },
    Contract: jest.fn(() => ({ call: jest.fn() })),
    Keypair: { fromSecret: jest.fn(() => ({ publicKey: () => 'GAXK...' })) },
    TransactionBuilder: { fromXDR: jest.fn(() => ({ hash: () => Buffer.alloc(32) })) },
    Horizon: { Server: jest.fn() },
    Asset: { native: jest.fn() },
    Operation: { payment: jest.fn() },
    Memo: { hash: jest.fn() },
  };
});

describe('zkremit Backend E2E', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true }));
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health returns ok status', async () => {
    const res = await request(app.getHttpServer()).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body).toHaveProperty('timestamp');
    expect(res.body).toHaveProperty('network');
  });

  it('GET /credential/issuers returns issuer list', async () => {
    const res = await request(app.getHttpServer()).get('/credential/issuers');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect(res.body[0]).toHaveProperty('name');
    expect(res.body[0]).toHaveProperty('pubkeyHash');
    expect(res.body[0]).toHaveProperty('supportedCorridors');
  });

  it('POST /credential/issue validates wallet address', async () => {
    const res = await request(app.getHttpServer())
      .post('/credential/issue')
      .send({
        walletAddress: 'invalid',
        kycProvider: 'mock-issuer',
        corridorId: 'NG-PH',
      });
    expect(res.status).toBe(400);
  });

  it('POST /credential/issue validates corridor', async () => {
    const res = await request(app.getHttpServer())
      .post('/credential/issue')
      .send({
        walletAddress: 'GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y',
        kycProvider: 'mock-issuer',
        corridorId: 'INVALID',
      });
    expect(res.status).toBe(400);
  });

  it('POST /proof/relay validates proof format', async () => {
    const res = await request(app.getHttpServer())
      .post('/proof/relay')
      .send({
        proof: '0xabcd',
        publicInputs: {
          nullifier: '0x' + 'a'.repeat(64),
          issuer_pubkey_hash: '0x' + 'b'.repeat(64),
          payment_asset: '0x' + 'c'.repeat(64),
          aml_threshold: 10000,
          corridor_id: '0x' + 'd'.repeat(64),
          amount_commitment: '0x' + 'e'.repeat(64),
          revocation_root: '0x' + 'f'.repeat(64),
          approved_corridors_root: '0x' + '0'.repeat(64),
          allowed_jurisdictions_root: '0x' + '1'.repeat(64),
        },
      });
    expect(res.status).toBe(400);
  });

  it('GET /nullifier/:nullifier validates format', async () => {
    const res = await request(app.getHttpServer()).get('/nullifier/invalid');
    expect(res.status).toBe(400);
  });

  it('GET /nullifier/:nullifier returns fresh for unknown nullifier', async () => {
    const res = await request(app.getHttpServer()).get('/nullifier/0x' + 'a'.repeat(64));
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('used');
    expect(res.body).toHaveProperty('nullifier');
  });

  it('GET /payment/sep31-info/:corridorId returns anchor info', async () => {
    const res = await request(app.getHttpServer()).get('/payment/sep31-info/NG-PH');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('anchorUrl');
    expect(res.body).toHaveProperty('assetCode');
    expect(res.body).toHaveProperty('minAmount');
    expect(res.body).toHaveProperty('maxAmount');
    expect(res.body).toHaveProperty('fields');
  });

  it('GET /payment/sep31-info/:corridorId rejects unknown corridor', async () => {
    const res = await request(app.getHttpServer()).get('/payment/sep31-info/INVALID');
    expect(res.status).toBe(400);
  });
});
