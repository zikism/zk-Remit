import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { CORRIDORS, APPROVED_CORRIDORS, JURISDICTION_CODES, corridorConfig } from './compliance.config';

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
});
