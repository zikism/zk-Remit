import { Module } from '@nestjs/common';
import { ProofService } from './proof.service';
import { ProofVerificationService } from './proof-verification.service';
import { ProofController } from './proof.controller';
import { NullifierModule } from '../nullifier/nullifier.module';

@Module({
  imports: [NullifierModule],
  controllers: [ProofController],
  providers: [ProofService, ProofVerificationService],
  exports: [ProofService],
})
export class ProofModule {}
