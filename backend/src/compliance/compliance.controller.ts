import { Controller, Get, NotFoundException, Param } from '@nestjs/common';
import { CORRIDORS, CORRIDOR_MAP } from './compliance.config';

@Controller('compliance')
export class ComplianceController {
  @Get('corridors')
  getCorridors() {
    return CORRIDORS;
  }

  @Get('corridors/:id')
  getCorridor(@Param('id') id: string) {
    const corridor = CORRIDOR_MAP[id];
    if (!corridor) {
      throw new NotFoundException(`Unsupported corridor: ${id}`);
    }
    return corridor;
  }
}
