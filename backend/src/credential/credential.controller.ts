import { Controller, Post, Get, Body, ValidationPipe, UsePipes, UseGuards } from '@nestjs/common';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import { CredentialService } from './credential.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { RevokeCredentialDto } from './dto/revoke-credential.dto';

@Controller('credential')
@UseGuards(ThrottlerGuard)
export class CredentialController {
  constructor(private readonly credentialService: CredentialService) {}

  /**
   * Minting a credential grants the holder a valid KYC asset for 90 days, so
   * it is the one endpoint that should never be freely spamable: a fixed
   * per-IP budget of 5 issuances/minute (vs the global 10 req/min default)
   * caps credential minting without needing any user identity.
   */
  @Post('issue')
  @Throttle({ default: { ttl: 60000, limit: 5 } })
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async issue(@Body() dto: IssueCredentialDto) {
    return this.credentialService.issue(dto);
  }

  @Get('issuers')
  async getIssuers() {
    return this.credentialService.getIssuers();
  }

  /**
   * Admin: revoke a credential. The credential hash is added to the
   * revocation set, so the next published revocation_root makes the
   * circuit's `assert_not_revoked` proof fail for it. The caller must
   * trigger root rotation afterward (see the root-rotation endpoint) for
   * the revocation to take effect on-chain.
   */
  @Post('revoke')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  async revoke(@Body() dto: RevokeCredentialDto) {
    await this.credentialService.revoke(dto.credentialHash);
    return { revoked: true };
  }
}
