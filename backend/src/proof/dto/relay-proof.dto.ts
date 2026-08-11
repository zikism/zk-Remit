import { IsString, IsNumber, Min, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class PublicInputsDto {
  @IsString()
  nullifier!: string;

  @IsString()
  issuer_pubkey_hash!: string;

  @IsString()
  payment_asset!: string;

  @IsNumber()
  @Min(0)
  aml_threshold!: number;

  @IsString()
  corridor_id!: string;

  @IsString()
  amount_commitment!: string;

  @IsString()
  revocation_root!: string;

  @IsString()
  approved_corridors_root!: string;

  @IsString()
  allowed_jurisdictions_root!: string;
}

export class RelayProofDto {
  @IsString()
  proof!: string;

  @ValidateNested()
  @Type(() => PublicInputsDto)
  publicInputs!: PublicInputsDto;
}

export interface RelayProofResult {
  verified: boolean;
  txHash?: string;
  error?: string;
}
