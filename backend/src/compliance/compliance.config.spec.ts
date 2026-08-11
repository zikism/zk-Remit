import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { CORRIDORS, APPROVED_CORRIDORS, JURISDICTION_CODES, corridorConfig, corridorIdToFieldHex, corridorConfigByFieldHex } from './compliance.config';

describe('ComplianceController', () => {
  let controller: ComplianceController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ComplianceController],
    }).compile();

    controller = module.get<ComplianceController>(ComplianceController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should list every approved corridor with its AML threshold', () => {
    const corridors = controller.getCorridors();
    expect(corridors).toEqual(CORRIDORS);
    for (const c of corridors) {
      expect(c.amlThreshold).toBeGreaterThan(0);
      expect(c.maxAmount).toBeGreaterThan(0);
      expect(c.senderJurisdiction).toBeGreaterThan(0);
      expect(c.paymentAsset.length).toBeGreaterThan(0);
    }
  });

  it('should return a single corridor by id', () => {
    const ngPh = controller.getCorridor('NG-PH');
    expect(ngPh.amlThreshold).toBe(10000);
  });

  it('should 404 for an unknown corridor', () => {
    expect(() => controller.getCorridor('XX-XX')).toThrow(NotFoundException);
  });
});

describe('ComplianceConfig', () => {
  it('should derive a deterministic sorted corridor list for the merkle tree', () => {
    expect(APPROVED_CORRIDORS).toEqual(['GH-US', 'KE-DE', 'NG-GB', 'NG-PH']);
  });

  it('should derive sorted unique jurisdiction codes for the merkle tree', () => {
    expect(JURISDICTION_CODES).toEqual([288, 404, 566]);
  });

  it('should expose corridor config through the lookup helper', () => {
    expect(corridorConfig('KE-DE').senderJurisdiction).toBe(404);
    expect(() => corridorConfig('NOPE')).toThrow('Unsupported corridor');
  });

  it('should round-trip a corridor through its circuit field', () => {
    // The credential issuer and the relay both encode corridor ids as
    // BigInt(utf8 bytes) padded to 32 bytes; this is what the proof's
    // corridor_id public input carries.
    const field = corridorIdToFieldHex('NG-PH');
    expect(field).toBe('0x0000000000000000000000000000000000000000000000000000004e472d5048');
    expect(corridorConfigByFieldHex(field)?.corridorId).toBe('NG-PH');
    expect(corridorConfigByFieldHex('0x' + 'ff'.repeat(32))).toBeUndefined();
  });
});
