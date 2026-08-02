import { Module } from '@nestjs/common';
import { CredentialController } from './credential.controller';
import { CredentialService } from './credential.service';
import { HashModule } from '../hash/hash.module';

@Module({
  imports: [HashModule],
  controllers: [CredentialController],
  providers: [CredentialService],
  exports: [CredentialService],
})
export class CredentialModule {}
