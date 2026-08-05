import { Controller, Post, Get, Body, ValidationPipe, UsePipes } from '@nestjs/common';
import { CredentialService } from './credential.service';
import { IssueCredentialDto } from './dto/issue-credential.dto';
import { RevokeCredentialDto } from './dto/revoke-credential.dto';

@Controller('credential')
export class CredentialController {
  constructor(private readonly credentialService: CredentialService) {}

  @Post('issue')
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
