import { Controller, Get } from '@nestjs/common';
import { MerkleService } from './merkle.service';
import { PoseidonService } from '../hash/poseidon.service';

@Controller('merkle')
export class MerkleController {
  constructor(
    private readonly merkleService: MerkleService,
    private readonly poseidonService: PoseidonService,
  ) {}

  @Get('jurisdiction-root')
  jurisdictionRoot() {
    return { root: this.poseidonService.fieldToHex32(this.merkleService.jurisdictionRoot()) };
  }

  @Get('corridor-root')
  corridorRoot() {
    return { root: this.poseidonService.fieldToHex32(this.merkleService.corridorRoot()) };
  }

  @Get('revocation-root')
  async revocationRoot() {
    const root = await this.merkleService.revocationRoot();
    return { root: this.poseidonService.fieldToHex32(root) };
  }
}
