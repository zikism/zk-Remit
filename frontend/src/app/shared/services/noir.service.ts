import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Subject, lastValueFrom } from 'rxjs';

export interface ProofProgress {
  stage: 'idle' | 'loading' | 'witness' | 'proof' | 'done' | 'error';
  percent: number;
  message: string;
  elapsedMs: number;
}

export interface CircuitInputs {
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

export interface ProofResult {
  proof: string;
  publicInputs: Record<string, string>;
  generationTimeMs: number;
  constraintCount: number;
  nullifier: string;
}

@Injectable({ providedIn: 'root' })
export class NoirService {
  private _isReady = signal(false);
  readonly isReady = this._isReady.asReadonly();
  readonly useWorker = signal(false);

  private progressSubject = new Subject<ProofProgress>();
  readonly proofProgress$ = this.progressSubject.asObservable();

  private noir: any = null;
  private backend: any = null;

  constructor(private http: HttpClient) {
    this.useWorker.set(this.detectMobile());
  }

  detectMobile(): boolean {
    return window.innerWidth < 768 || /Mobi|Android/i.test(navigator.userAgent);
  }

  shouldUseWorker(): boolean {
    return this.detectMobile() || (navigator as any).hardwareConcurrency <= 2;
  }

  async initialize(): Promise<void> {
    this.progressSubject.next({
      stage: 'loading',
      percent: 0,
      message: 'Loading ZK proving system...',
      elapsedMs: 0,
    });

    const [noirModule, bbModule, circuitJson] = await Promise.all([
      import('@noir-lang/noir_js'),
      import('@aztec/bb.js'),
      lastValueFrom(this.http.get<any>('assets/circuits/zk_compliance.json')),
    ]);

    const { UltraHonkBackend } = bbModule;
    const { Noir } = noirModule;

    this.noir = new Noir(circuitJson);
    this.backend = new UltraHonkBackend(circuitJson.bytecode);
    this._isReady.set(true);
  }

  async generateProof(inputs: CircuitInputs): Promise<ProofResult> {
    if (this.shouldUseWorker()) {
      this.useWorker.set(true);
      return this.generateProofInWorker(inputs);
    }

    this.useWorker.set(false);

    if (!this._isReady()) {
      await this.initialize();
    }

    const startTime = Date.now();

    this.progressSubject.next({
      stage: 'witness',
      percent: 10,
      message: 'Computing witness...',
      elapsedMs: Date.now() - startTime,
    });

    const { witness } = await this.noir.execute(inputs);

    this.progressSubject.next({
      stage: 'proof',
      percent: 40,
      message: 'Generating proof (4,312 constraints)...',
      elapsedMs: Date.now() - startTime,
    });

    const proofData = await this.backend.generateProof(witness);
    const elapsed = Date.now() - startTime;

    this.progressSubject.next({
      stage: 'done',
      percent: 100,
      message: `Proof generated in ${elapsed}ms`,
      elapsedMs: elapsed,
    });

    const publicInputs: Record<string, string> = {};
    const piArray = proofData.publicInputs as string[];
    piArray.forEach((val: string, idx: number) => {
      publicInputs[`pub_${idx}`] = val;
    });

    const proofHex = Array.from(proofData.proof as Uint8Array)
      .map((b: number) => b.toString(16).padStart(2, '0'))
      .join('');

    return {
      proof: '0x' + proofHex,
      publicInputs,
      generationTimeMs: elapsed,
      constraintCount: 4312,
      nullifier: publicInputs['nullifier'] || '',
    };
  }

  private async generateProofInWorker(inputs: CircuitInputs): Promise<ProofResult> {
    const circuitJson = await lastValueFrom(
      this.http.get<any>('assets/circuits/zk_compliance.json')
    );

    return new Promise<ProofResult>((resolve, reject) => {
      const worker = new Worker(
        new URL('../workers/proof.worker.ts', import.meta.url),
        { type: 'module' }
      );

      worker.onmessage = (e: MessageEvent) => {
        const msg = e.data;

        switch (msg.type) {
          case 'PROGRESS':
            this.progressSubject.next({
              stage: msg.stage,
              percent: msg.percent,
              message: msg.message,
              elapsedMs: msg.elapsedMs,
            });
            break;

          case 'PROOF_DONE':
            worker.terminate();
            resolve(msg.result);
            break;

          case 'PROOF_ERROR':
            worker.terminate();
            reject(new Error(msg.error));
            break;
        }
      };

      worker.onerror = (err) => {
        worker.terminate();
        reject(new Error('Web Worker error: ' + err.message));
      };

      worker.postMessage({
        type: 'GENERATE_PROOF',
        inputs,
        circuitJson,
      });
    });
  }
}
