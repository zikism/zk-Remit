import { IsString, IsIn } from 'class-validator';
import { IsStellarAddress } from '../decorators/is-stellar-address.decorator';

export class IssueCredentialDto {
  @IsStellarAddress()
  walletAddress!: string;

  @IsString()
  @IsIn(['mock-issuer'])
  kycProvider!: string;

  @IsString()
  @IsIn(['NG-PH', 'NG-GB', 'GH-US', 'KE-DE'])
  corridorId!: string;
}

export interface CredentialResponse {
  credentialHash: string;
  credentialSecret: string;
  issuerSignature: string;
  issuerPubkey: string;
  userPubkeyHash: string;
  corridorId: string;
  expiry: number;
  jurisdictionCode: number;
}

export interface IssuerResponse {
  name: string;
  pubkeyHash: string;
  supportedCorridors: string[];
}
