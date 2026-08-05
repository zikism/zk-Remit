import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { CredentialService } from './credential.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { PoseidonService } from '../hash/poseidon.service';
import { Fr } from '@aztec/bb.js';

const FrModulus = (): bigint => Fr.MODULUS;

jest.mock('../db/client', () => {
  const query = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
  return {
    getPool: jest.fn(() => ({ query })),
    closePool: jest.fn(),
  };
});

describe('CredentialService', () => {
  let service: CredentialService;
  let configService: ConfigService;

  // 32-byte secp256k1 private scalar (64 hex chars).
  const mockPrivateKey = 'a'.repeat(64);

  const poseidonServiceMock = {
    poseidon2: jest.fn((inputs: bigint[]) =>
      inputs.reduce((acc, x) => (acc + x) % (1n << 254n), 0n)
    ),
    bytesToFieldChunks: jest.fn((bytes: Uint8Array) => [
      BigInt('0x' + Buffer.from(bytes).toString('hex').slice(0, 62)),
    ]),
    fieldToHex32: jest.fn((field: bigint) =>
      '0x' + field.toString(16).padStart(64, '0')
    ),
    fieldToBytes32: jest.fn((field: bigint) =>
      Buffer.from(field.toString(16).padStart(64, '0'), 'hex')
    ),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CredentialService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'ISSUER_PRIVATE_KEY') return mockPrivateKey;
              return undefined;
            }),
          },
        },
        { provide: PoseidonService, useValue: poseidonServiceMock },
      ],
    }).compile();

    service = module.get<CredentialService>(CredentialService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should require ISSUER_PRIVATE_KEY on construction', () => {
    expect(() => {
      new CredentialService(
        {
          get: jest.fn(() => undefined),
        } as any,
        poseidonServiceMock as any
      );
    }).toThrow('ISSUER_PRIVATE_KEY');
  });

  it('should reject a non-32-byte ISSUER_PRIVATE_KEY', () => {
    expect(() => {
      new CredentialService(
        {
          get: jest.fn((key: string) =>
            key === 'ISSUER_PRIVATE_KEY' ? 'a'.repeat(128) : undefined
          ),
        } as any,
        poseidonServiceMock as any
      );
    }).toThrow('ISSUER_PRIVATE_KEY');
  });

  it('should return issuers with pubkeyHash populated', async () => {
    const issuers = await service.getIssuers();
    expect(issuers).toHaveLength(1);
    expect(issuers[0].name).toBe('mock-issuer');
    expect(issuers[0].pubkeyHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(issuers[0].supportedCorridors).toContain('NG-PH');
  });

  it('should not mutate the module-level issuer list between calls', async () => {
    const first = await service.getIssuers();
    const second = await service.getIssuers();
    expect(first).not.toBe(second);
    expect(first[0]).not.toBe(second[0]);
    expect(first[0].pubkeyHash).toBe(second[0].pubkeyHash);
  });

  it('should derive a 64-byte secp256k1 public key from the private key', () => {
    const pub = secp256k1.getPublicKey(Buffer.from(mockPrivateKey, 'hex'), false);
    // The credential response should expose x || y (64 bytes).
    expect(pub.subarray(1).length).toBe(64);
  });

  it('should sign the raw credential message with prehash:false', async () => {
    poseidonServiceMock.poseidon2.mockReturnValue(0x1234n);
    poseidonServiceMock.fieldToBytes32.mockReturnValue(
      Buffer.from('1234000000000000000000000000000000000000000000000000000000000000', 'hex')
    );

    const dto: IssueCredentialDto = {
      walletAddress: 'GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7',
      kycProvider: 'mock-issuer',
      corridorId: 'NG-PH',
    };

    const response = await service.issue(dto);
    const sig = Buffer.from(response.issuerSignature.slice(2), 'hex');
    const msg = Buffer.from('1234000000000000000000000000000000000000000000000000000000000000', 'hex');
    const pub = secp256k1.getPublicKey(Buffer.from(mockPrivateKey, 'hex'), false);

    // prehash:false: the 32 message bytes are signed directly (matches the
    // circuit's ecdsa_secp256k1::verify_signature).
    expect(secp256k1.verify(sig, msg, pub, { prehash: false })).toBe(true);
    // prehash:true (v2 default) would sign SHA256(msg) instead -> must NOT verify.
    expect(secp256k1.verify(sig, msg, pub)).toBe(false);
  });

  it('should issue a credential secret that is a valid BN254 field element', async () => {
    const dto: IssueCredentialDto = {
      walletAddress: 'GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7',
      kycProvider: 'mock-issuer',
      corridorId: 'NG-PH',
    };

    const response = await service.issue(dto);
    const secretField = BigInt(response.credentialSecret);
    // A full 32-byte random value exceeds the modulus ~75% of the time and
    // would be rejected by the circuit's witness builder, so the issued
    // secret must always be a canonical field element.
    expect(secretField).toBeLessThan(FrModulus());
    expect(response.credentialSecret).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('should throw for unsupported corridor', async () => {
    const dto: IssueCredentialDto = {
      walletAddress: 'GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7',
      kycProvider: 'mock-issuer',
      corridorId: 'INVALID' as any,
    };

    await expect(service.issue(dto)).rejects.toThrow('Unsupported corridor');
  });

  describe('revoke', () => {
    it('should mark a credential revoked', async () => {
      const { getPool } = jest.requireMock('../db/client');
      const pool = getPool();
      pool.query.mockResolvedValue({ rowCount: 1 });

      await expect(service.revoke('0x' + 'ab'.repeat(32))).resolves.toBeUndefined();

      const updateCall = pool.query.mock.calls.find(([sql]: [string]) =>
        sql.includes('UPDATE credentials')
      );
      expect(updateCall).toBeDefined();
      expect(updateCall[1]).toEqual(['0x' + 'ab'.repeat(32)]);
    });

    it('should throw NotFoundException when the credential does not exist', async () => {
      const { getPool } = jest.requireMock('../db/client');
      const pool = getPool();
      pool.query.mockResolvedValue({ rowCount: 0 });

      await expect(service.revoke('0x' + 'cd'.repeat(32))).rejects.toThrow('not found');
    });
  });
});
