import { Module } from '@nestjs/common';
import { MerkleModule } from '../merkle/merkle.module';
import { HashModule } from '../hash/hash.module';
import { RootRotationService } from './root-rotation.service';
import { RootRotationController } from './root-rotation.controller';

@Module({
  imports: [MerkleModule, HashModule],
  providers: [RootRotationService],
  controllers: [RootRotationController],
})
export class RootRotationModule {}
