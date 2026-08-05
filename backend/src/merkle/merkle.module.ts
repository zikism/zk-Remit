import { Module } from '@nestjs/common';
import { HashModule } from '../hash/hash.module';
import { MerkleService } from './merkle.service';
import { MerkleController } from './merkle.controller';

@Module({
  imports: [HashModule],
  providers: [MerkleService],
  controllers: [MerkleController],
  exports: [MerkleService],
})
export class MerkleModule {}
