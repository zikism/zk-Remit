/**
 * Mapping between the bb.js UltraHonk public-input array and the relay's wire
 * format. The circuit (`circuits/src/main.nr`) declares its public parameters
 * in this exact order, bb.js returns them as decimal field strings, and the
 * backend relay + Soroban contract consume them as 0x-prefixed 32-byte
 * big-endian hex (see backend/src/proof/proof.service.ts and
 * contracts/verifier/src/lib.rs). Any reordering here makes every field past
 * the first decode as the wrong value, so keep it in lockstep with main.nr.
 */
export const CIRCUIT_PUBLIC_INPUT_ORDER = [
  'nullifier',
  'issuer_pubkey_hash',
  'payment_asset',
  'aml_threshold',
  'corridor_id',
  'allowed_jurisdictions_root',
  'amount_commitment',
  'revocation_root',
  'approved_corridors_root',
] as const;

export interface ProofPublicInputs {
  nullifier: string;
  issuer_pubkey_hash: string;
  payment_asset: string;
  aml_threshold: number;
  corridor_id: string;
  allowed_jurisdictions_root: string;
  amount_commitment: string;
  revocation_root: string;
  approved_corridors_root: string;
}

/** Decimal field string (as returned by bb.js) → '0x' + 32-byte big-endian hex. */
export function decimalFieldToHex32(decimal: string): string {
  const hex = BigInt(decimal).toString(16);
  if (hex.length > 64) {
    throw new Error(`Field value ${decimal} exceeds the 32-byte wire format`);
  }
  return '0x' + hex.padStart(64, '0');
}

/**
 * UTF-8 string → the same field encoding the backend derives for corridor ids
 * (BigInt of the big-endian bytes, 32-byte padded). Used for `payment_asset`.
 */
export function utf8ToFieldHex(value: string): string {
  const hex = Array.from(new TextEncoder().encode(value))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return decimalFieldToHex32(BigInt('0x' + hex).toString());
}

/**
 * Map the bb.js public-input array (decimal strings, circuit order) to named
 * fields in the relay's wire format.
 */
export function mapProofPublicInputs(piArray: string[]): ProofPublicInputs {
  return {
    nullifier: decimalFieldToHex32(piArray[0]),
    issuer_pubkey_hash: decimalFieldToHex32(piArray[1]),
    payment_asset: decimalFieldToHex32(piArray[2]),
    aml_threshold: Number(piArray[3]),
    corridor_id: decimalFieldToHex32(piArray[4]),
    allowed_jurisdictions_root: decimalFieldToHex32(piArray[5]),
    amount_commitment: decimalFieldToHex32(piArray[6]),
    revocation_root: decimalFieldToHex32(piArray[7]),
    approved_corridors_root: decimalFieldToHex32(piArray[8]),
  };
}
