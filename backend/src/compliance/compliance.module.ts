import { Module } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';

@Module({
  controllers: [ComplianceController],
})
export class ComplianceModule {}
