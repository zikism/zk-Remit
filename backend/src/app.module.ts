import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { CredentialModule } from './credential/credential.module';
import { ProofModule } from './proof/proof.module';
import { PaymentModule } from './payment/payment.module';
import { NullifierModule } from './nullifier/nullifier.module';
import { HashModule } from './hash/hash.module';
import { MerkleModule } from './merkle/merkle.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }]),
    CredentialModule,
    ProofModule,
    PaymentModule,
    NullifierModule,
    HashModule,
    MerkleModule,
  ],
})
export class AppModule {}
