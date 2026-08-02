import { Module } from '@nestjs/common';
import { PoseidonService } from './poseidon.service';

@Module({
  providers: [PoseidonService],
  exports: [PoseidonService],
})
export class HashModule {}
