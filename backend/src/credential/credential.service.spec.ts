import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { CredentialService } from './credential.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { PoseidonService } from '../hash/poseidon.service';

describe('CredentialService', () => {
  let service: CredentialService;
  let configService: ConfigService;

  const mockPrivateKey = 'a'.repeat(128);
  // 64-byte secp256k1 point (x || y) as the circuit requires.
  const mockPublicKey = 'b'.repeat(128);

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
              if (key === 'ISSUER_PUBLIC_KEY') return mockPublicKey;
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
          get: jest.fn((key: string) => {
            if (key === 'ISSUER_PRIVATE_KEY') return undefined;
            if (key === 'ISSUER_PUBLIC_KEY') return mockPublicKey;
            return undefined;
          }),
        } as any,
        poseidonServiceMock as any
      );
    }).toThrow('ISSUER_PRIVATE_KEY');
  });

  it('should require a 64-byte ISSUER_PUBLIC_KEY on construction', () => {
    expect(() => {
      new CredentialService(
        {
          get: jest.fn((key: string) => {
            if (key === 'ISSUER_PRIVATE_KEY') return mockPrivateKey;
            if (key === 'ISSUER_PUBLIC_KEY') return 'c'.repeat(64);
            return undefined;
          }),
        } as any,
        poseidonServiceMock as any
      );
    }).toThrow('ISSUER_PUBLIC_KEY');
  });

  it('should return issuers with pubkeyHash populated', async () => {
    const issuers = await service.getIssuers();
    expect(issuers).toHaveLength(1);
    expect(issuers[0].name).toBe('mock-issuer');
    expect(issuers[0].pubkeyHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(issuers[0].supportedCorridors).toContain('NG-PH');
  });

  it('should throw for unsupported corridor', async () => {
    const dto: IssueCredentialDto = {
      walletAddress: 'GAXK2SOZ2RI4ZJ6ZYVJXL6QY7YV5Z7G7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7Y6Y7',
      kycProvider: 'mock-issuer',
      corridorId: 'INVALID' as any,
    };

    await expect(service.issue(dto)).rejects.toThrow('Unsupported corridor');
  });
});
