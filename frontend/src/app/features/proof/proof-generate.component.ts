import { Component, Input, Output, EventEmitter, signal, computed, OnDestroy } from '@angular/core';
import { NgClass } from '@angular/common';
import {
  NoirService,
  ProofProgress,
  ProofResult,
  CircuitInputs,
} from '../../shared/services/noir.service';
import { CredentialService } from '../../shared/services/credential.service';
import { PoseidonService } from '../../shared/services/poseidon.service';
import { utf8ToFieldHex } from '../../shared/utils/proof-inputs';
import { Credential } from '../credential/credential-fetch.component';
import { ProofStatusComponent } from '../../shared/components/proof-status/proof-status.component';

function hexToBytes(hex: string): number[] {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes: number[] = [];
  for (let i = 0; i < h.length; i += 2) {
    bytes.push(parseInt(h.substring(i, i + 2), 16));
  }
  return bytes;
}

@Component({
  selector: 'app-proof-generate',
  standalone: true,
  imports: [NgClass, ProofStatusComponent],
  template: `
    <div class="rounded-xl bg-[#1e293b] p-6 text-white shadow-lg">
      <h3 class="mb-4 text-lg font-semibold">Generate ZK Proof</h3>

      <button
        (click)="generate()"
        [disabled]="isGenerating() || !credential"
        class="w-full rounded-lg bg-[#2563eb] px-6 py-3 font-semibold transition-colors hover:bg-[#1d4ed8] disabled:cursor-not-allowed disabled:opacity-50"
      >
        @if (isGenerating()) {
          <span class="flex items-center justify-center gap-2">
            <svg class="h-5 w-5 animate-spin" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            Generating...
          </span>
        } @else {
          Generate ZK Proof
        }
      </button>

      @if (showProgress()) {
        <div class="mt-4 space-y-3">
          <div class="flex gap-2">
            <span
              class="rounded-full px-3 py-1 text-xs font-medium"
              [ngClass]="pillClass('witness')"
            >Witness</span>
            <span
              class="rounded-full px-3 py-1 text-xs font-medium"
              [ngClass]="pillClass('proof')"
            >Proof</span>
          </div>

          <div class="h-2 w-full overflow-hidden rounded-full bg-gray-700">
            <div
              class="h-full rounded-full bg-green-500 transition-all duration-500"
              [style.width.%]="progressBarWidth()"
            ></div>
          </div>

          <div class="flex justify-between text-sm text-gray-400">
            <span>{{ proofStatus().message }}</span>
            <span>{{ (proofStatus().elapsedMs / 1000).toFixed(1) }}s</span>
          </div>

          <div class="flex gap-4 text-xs text-gray-500">
            <span>Constraints: 4,312</span>
            <span>Elapsed: {{ (proofStatus().elapsedMs / 1000).toFixed(1) }}s</span>
          </div>
        </div>
      }

      @if (noirService.useWorker()) {
        <div class="mt-3 text-xs text-blue-400">
          Running proof generation in background thread — your UI stays responsive
        </div>
        <div class="text-xs text-gray-500">
          Estimated time: ~8–15 seconds
        </div>
      } @else {
        <div class="mt-3 text-xs text-gray-500">
          Estimated time: ~2–4 seconds
        </div>
      }

      @if (proofResult(); as pr) {
        <div class="mt-4 rounded-lg border border-green-600/30 bg-green-900/20 p-4">
          <p class="mb-2 font-semibold text-green-400">
            ✓ Proof generated in {{ (pr.generationTimeMs / 1000).toFixed(1) }}s
          </p>
          <div class="mb-2 font-mono text-xs text-gray-400">
            <span class="break-all">Nullifier: {{ pr.nullifier }}</span>
            <button (click)="copyNullifier()" class="ml-2 text-blue-400 hover:text-blue-300">
              {{ nullifierCopied() ? 'Copied!' : 'Copy' }}
            </button>
          </div>
          <div class="grid grid-cols-2 gap-1 text-xs text-gray-500">
            <span>AML Threshold: {{ pr.publicInputs.aml_threshold }}</span>
            <span>Corridor: {{ corridorId }}</span>
            <span>Asset: {{ paymentAsset }}</span>
          </div>
          <button
            (click)="proceed()"
            class="mt-3 w-full rounded-lg bg-[#16a34a] px-4 py-2 font-semibold transition-colors hover:bg-[#15803d]"
          >
            Proceed to Payment →
          </button>
        </div>
      }

      @if (proofStatus().stage === 'error') {
        <div class="mt-4 rounded-lg bg-red-900/50 p-4 text-center">
          <p class="mb-2 text-red-300">✗ {{ proofStatus().message }}</p>
          <button (click)="generate()" class="text-sm text-blue-400 hover:text-blue-300">
            Retry
          </button>
        </div>
      }
    </div>
  `,
})
export class ProofGenerateComponent implements OnDestroy {
  @Input({ required: true }) credential!: Credential;
  @Input({ required: true }) amount!: number;
  @Input({ required: true }) corridorId!: string;
  @Input({ required: true }) paymentAsset!: string;
  @Output() proofGenerated = new EventEmitter<ProofResult>();

  proofStatus = signal<ProofProgress>({
    stage: 'idle',
    percent: 0,
    message: '',
    elapsedMs: 0,
  });
  proofResult = signal<ProofResult | null>(null);
  nullifierCopied = signal(false);
  private elapsedTimer: any = null;

  progressBarWidth = computed(() => this.proofStatus().percent);
  isGenerating = computed(() =>
    ['loading', 'witness', 'proof'].includes(this.proofStatus().stage)
  );
  showProgress = computed(() =>
    ['loading', 'witness', 'proof', 'done'].includes(this.proofStatus().stage)
  );

  constructor(
    public noirService: NoirService,
    private credentialService: CredentialService,
    private poseidonService: PoseidonService
  ) {}

  ngOnDestroy(): void {
    this.clearTimer();
  }

  private clearTimer(): void {
    if (this.elapsedTimer) {
      clearInterval(this.elapsedTimer);
      this.elapsedTimer = null;
    }
  }

  private randomHexBytes(count: number): string {
    const bytes = new Uint8Array(count);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  pillClass(stage: string): Record<string, boolean> {
    const s = this.proofStatus().stage as string;
    const isActive = (stage === 'witness' && s === 'witness');
    const isDone = s === 'done' ||
      (stage === 'witness' && ['proof', 'done'].includes(s)) ||
      (stage === 'proof' && ['proof', 'done'].includes(s));
    return {
      'bg-green-600': isDone,
      'bg-yellow-600': isActive,
      'bg-gray-600': !isDone && !isActive,
      'text-white': isDone || isActive,
      'text-gray-300': !isDone && !isActive,
    };
  }

  async generate(): Promise<void> {
    this.proofResult.set(null);
    this.proofStatus.set({
      stage: 'loading',
      percent: 0,
      message: 'Initializing...',
      elapsedMs: 0,
    });

    const genStartTime = Date.now();
    this.clearTimer();
    this.elapsedTimer = setInterval(() => {
      this.proofStatus.update((s) => ({
        ...s,
        elapsedMs: Date.now() - genStartTime,
      }));
    }, 100);

    const sub = this.noirService.proofProgress$.subscribe((p) => {
      this.proofStatus.set(p);
    });

    try {
      const merkleRoots = await this.credentialService.getMerkleRoots();

      // The corridor's configured AML threshold is the single source of truth
      // (backend compliance config). The circuit only proves amount <
      // aml_threshold and the on-chain verifier pins aml_threshold to the
      // corridor's configured value, so a proof must use the same threshold
      // the contract enforces or it will be rejected after relay.
      const config = await this.credentialService.getCorridorConfig(this.corridorId);
      if (this.amount >= config.amlThreshold) {
        throw new Error(
          `Amount ${this.amount} exceeds the ${this.corridorId} AML threshold of ${config.amlThreshold}`
        );
      }

      const [jurisdictionPath, corridorPath, revocationPath] = await Promise.all([
        this.credentialService.getJurisdictionPath(this.credential.jurisdictionCode),
        this.credentialService.getCorridorPath(this.credential.corridorLabel),
        this.credentialService.getRevocationPath(),
      ]);

      const pubkeyBytes = hexToBytes(this.credential.issuerPubkey);
      const issuerPubkeyX = pubkeyBytes.slice(0, 32);
      const issuerPubkeyY = pubkeyBytes.slice(32, 64);

      const secretField = BigInt(this.credential.credentialSecret);
      const corridorField = BigInt(this.credential.corridorId);

      const issuerPubkeyHash = await this.poseidonService.issuerPubkeyHash(pubkeyBytes);
      const nullifier = await this.poseidonService.nullifier(secretField, corridorField);

      const blinding = BigInt('0x' + this.randomHexBytes(32));
      const amountCommitment = await this.poseidonService.amountCommitment(
        this.amount,
        blinding
      );

      const inputs: CircuitInputs = {
        credential_secret: this.credential.credentialSecret,
        credential_hash: this.credential.credentialHash,
        issuer_signature: hexToBytes(this.credential.issuerSignature),
        issuer_pubkey_x: issuerPubkeyX,
        issuer_pubkey_y: issuerPubkeyY,
        user_pubkey_hash: this.credential.userPubkeyHash,
        amount: this.amount,
        jurisdiction_code: this.credential.jurisdictionCode,
        credential_expiry: this.credential.expiry,
        current_timestamp: Math.floor(Date.now() / 1000),
        allowed_jurisdictions_path: jurisdictionPath.path,
        allowed_jurisdictions_index:
          '0x' + BigInt(jurisdictionPath.index).toString(16),
        amount_blinding: this.poseidonService.fieldToHex32(blinding),
        revocation_candidate_leaf: revocationPath.leaf,
        revocation_path: revocationPath.path,
        revocation_indices: revocationPath.indices,
        approved_corridors_path: corridorPath.path,
        approved_corridors_indices: corridorPath.indices,
        nullifier,
        issuer_pubkey_hash: issuerPubkeyHash,
        // The asset actually being paid, encoded the same way the backend
        // derives corridor fields (BigInt of the UTF-8 bytes, 32-byte padded).
        payment_asset: utf8ToFieldHex(this.paymentAsset),
        aml_threshold: config.amlThreshold,
        corridor_id: this.credential.corridorId,
        allowed_jurisdictions_root: merkleRoots.jurisdictionRoot,
        amount_commitment: amountCommitment,
        revocation_root: merkleRoots.revocationRoot,
        approved_corridors_root: merkleRoots.corridorRoot,
      };

      const result = await this.noirService.generateProof(inputs);
      this.proofResult.set(result);
      this.proofGenerated.emit(result);
    } catch (err: any) {
      this.proofStatus.set({
        stage: 'error',
        percent: 0,
        message: err.message || 'Proof generation failed',
        elapsedMs: Date.now() - genStartTime,
      });
    } finally {
      sub.unsubscribe();
      this.clearTimer();
    }
  }

  async copyNullifier(): Promise<void> {
    const p = this.proofResult();
    if (!p) return;
    await navigator.clipboard.writeText(p.nullifier);
    this.nullifierCopied.set(true);
    setTimeout(() => this.nullifierCopied.set(false), 2000);
  }

  proceed(): void {
    const p = this.proofResult();
    if (p) {
      this.proofGenerated.emit(p);
    }
  }
}
