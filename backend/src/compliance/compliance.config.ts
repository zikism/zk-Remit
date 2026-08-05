/**
 * Single source of truth for the compliance program: which corridors are
 * approved, their sending jurisdiction, their per-corridor AML threshold,
 * and the settlement asset.
 *
 * These values flow into every layer of the system:
 *  - the Noir circuit's public inputs (`corridor_id`, `aml_threshold`,
 *    `payment_asset`) built by the frontend prover,
 *  - the merkle trees (approved corridors + eligible jurisdictions) that the
 *    circuit membership proofs bind to,
 *  - the on-chain `ComplianceVerifier` AML thresholds (admin keeps
 *    `set_aml_threshold` in sync with `amlThreshold` here),
 *  - SEP-31 anchor limits surfaced by the payment API.
 *
 * The corridor set MUST stay sorted-agnostic here — the derived
 * `APPROVED_CORRIDORS` and `JURISDICTION_CODES` arrays are sorted so the
 * published merkle roots are deterministic.
 */

export interface CorridorConfig {
  corridorId: string;
  /** Sending jurisdiction code (the circuit's `jurisdiction_code` u32). */
  senderJurisdiction: number;
  /** Exclusive maximum amount per transfer; the circuit asserts amount < aml_threshold. */
  amlThreshold: number;
  /** Settlement asset code on Stellar. */
  paymentAsset: string;
  /** SEP-31 anchor max amount (decimal string compatible). */
  maxAmount: number;
}

export const CORRIDORS: CorridorConfig[] = [
  { corridorId: 'NG-PH', senderJurisdiction: 566, amlThreshold: 10000, paymentAsset: 'XLM', maxAmount: 10000 },
  { corridorId: 'NG-GB', senderJurisdiction: 566, amlThreshold: 10000, paymentAsset: 'XLM', maxAmount: 10000 },
  { corridorId: 'GH-US', senderJurisdiction: 288, amlThreshold: 5000, paymentAsset: 'XLM', maxAmount: 5000 },
  { corridorId: 'KE-DE', senderJurisdiction: 404, amlThreshold: 5000, paymentAsset: 'XLM', maxAmount: 5000 },
];

/** Approved corridors sorted by their circuit field value (big-endian corridor-string bytes). */
export const APPROVED_CORRIDORS: string[] = CORRIDORS.map((c) => c.corridorId).sort();

/** Eligible sending jurisdictions, sorted ascending. */
export const JURISDICTION_CODES: number[] = [
  ...new Set(CORRIDORS.map((c) => c.senderJurisdiction)),
].sort((a, b) => a - b);

export const CORRIDOR_MAP: Record<string, CorridorConfig> = Object.fromEntries(
  CORRIDORS.map((c) => [c.corridorId, c])
);

export function corridorConfig(corridorId: string): CorridorConfig {
  const config = CORRIDOR_MAP[corridorId];
  if (!config) {
    throw new Error(`Unsupported corridor: ${corridorId}`);
  }
  return config;
}
