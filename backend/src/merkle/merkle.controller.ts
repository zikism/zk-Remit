import { Controller, Get, Param } from '@nestjs/common';
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

  @Get('jurisdiction-path/:code')
  jurisdictionPath(@Param('code') code: string) {
    const { index, path } = this.merkleService.jurisdictionPath(Number(code));
    return {
      index: index.toString(),
      path: path.map((f) => this.poseidonService.fieldToHex32(f)),
    };
  }

  @Get('corridor-root')
  corridorRoot() {
    return { root: this.poseidonService.fieldToHex32(this.merkleService.corridorRoot()) };
  }

  @Get('corridor-path/:corridorId')
  corridorPath(@Param('corridorId') corridorId: string) {
    const { indices, path } = this.merkleService.corridorPath(corridorId);
    return {
      indices,
      path: path.map((f) => this.poseidonService.fieldToHex32(f)),
    };
  }

  @Get('revocation-root')
  async revocationRoot() {
    const root = await this.merkleService.revocationRoot();
    return { root: this.poseidonService.fieldToHex32(root) };
  }

  @Get('revocation-path')
  async revocationPath() {
    const { leaf, indices, path } = await this.merkleService.revocationPath();
    return {
      leaf: this.poseidonService.fieldToHex32(leaf),
      indices,
      path: path.map((f) => this.poseidonService.fieldToHex32(f)),
    };
  }
}
