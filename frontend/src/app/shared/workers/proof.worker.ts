/// <reference lib="webworker" />

import {
  ProofPublicInputs,
  mapProofPublicInputs,
} from '../utils/proof-inputs';

interface ProofProgress {
  stage: 'idle' | 'loading' | 'witness' | 'proof' | 'done' | 'error';
  percent: number;
  message: string;
  elapsedMs: number;
}

interface CircuitInputs {
  credential_secret: string;
  credential_hash: string;
  issuer_signature: number[];
  issuer_pubkey_x: number[];
  issuer_pubkey_y: number[];
  user_pubkey_hash: string;
  amount: number;
  jurisdiction_code: number;
  credential_expiry: number;
  current_timestamp: number;
  allowed_jurisdictions_path: string[];
  allowed_jurisdictions_index: string;
  amount_blinding: string;
  revocation_candidate_leaf: string;
  revocation_path: string[];
  revocation_indices: number[];
  approved_corridors_path: string[];
  approved_corridors_indices: number[];
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

interface ProofResult {
  proof: string;
  publicInputs: ProofPublicInputs;
  generationTimeMs: number;
  constraintCount: number;
  nullifier: string;
}

interface ProofWorkerMessage {
  type: 'GENERATE_PROOF';
  inputs: CircuitInputs;
  circuitJson: any;
}

self.onmessage = async (e: MessageEvent<ProofWorkerMessage>) => {
  const { type, inputs, circuitJson } = e.data;

  if (type !== 'GENERATE_PROOF') return;

  try {
    const startTime = Date.now();

    const postProgress = (stage: ProofProgress['stage'], percent: number, message: string) => {
      const elapsedMs = Date.now() - startTime;
      self.postMessage({ type: 'PROGRESS', stage, percent, message, elapsedMs });
    };

    postProgress('loading', 0, 'Loading ZK proving system...');

    const noirModule = await import(/* @vite-ignore */ '@noir-lang/noir_js');
    const bbModule = await import(/* @vite-ignore */ '@aztec/bb.js');

    const { UltraHonkBackend } = bbModule;
    const { Noir } = noirModule;

    const noir = new Noir(circuitJson);
    const backend = new UltraHonkBackend(circuitJson.bytecode);

    postProgress('witness', 10, 'Computing witness...');

    const { witness } = await noir.execute(inputs as any);

    postProgress('proof', 40, 'Generating proof (4,312 constraints)...');

    const proofData = await backend.generateProof(witness);
    const elapsed = Date.now() - startTime;

    postProgress('done', 100, `Proof generated in ${elapsed}ms`);

    const publicInputs = mapProofPublicInputs(proofData.publicInputs as string[]);

    const proofHex = Array.from(proofData.proof as Uint8Array)
      .map((b: number) => b.toString(16).padStart(2, '0'))
      .join('');

    const result: ProofResult = {
      proof: '0x' + proofHex,
      publicInputs,
      generationTimeMs: elapsed,
      constraintCount: 4312,
      nullifier: publicInputs.nullifier,
    };

    self.postMessage({ type: 'PROOF_DONE', result });
  } catch (err: any) {
    self.postMessage({ type: 'PROOF_ERROR', error: err.message || 'Unknown worker error' });
  }
};
