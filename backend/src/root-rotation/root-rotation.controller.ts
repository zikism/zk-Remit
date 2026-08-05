import { Controller, Post, Get, UseGuards } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { RootRotationService } from './root-rotation.service';

@Controller('admin')
@UseGuards(ThrottlerGuard)
export class RootRotationController {
  constructor(private readonly rootRotationService: RootRotationService) {}

  @Get('roots')
  getRoots() {
    return this.rootRotationService.getCurrentRoots();
  }

  /**
   * Recompute the current jurisdiction/corridor/revocation roots and publish
   * them to the on-chain ComplianceVerifier. Should be run after revoking a
   * credential or changing the corridor set; existing proofs become stale.
   */
  @Post('rotate-roots')
  rotateRoots() {
    return this.rootRotationService.publishRoots();
  }
}
