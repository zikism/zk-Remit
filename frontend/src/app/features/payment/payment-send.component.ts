import { Component, Input, Output, EventEmitter, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { lastValueFrom } from 'rxjs';
import { NgClass } from '@angular/common';
import { StellarService } from '../../shared/services/stellar.service';
import { ProofResult } from '../../shared/services/noir.service';
import { environment } from '../../../environments/environment';
type PaymentStep = 'idle' | 'verifying' | 'building' | 'signing' | 'submitting' | 'done' | 'error';

@Component({
  selector: 'app-payment-send',
  standalone: true,
  imports: [NgClass],
  template: `
    <div class="rounded-xl bg-[#1e293b] p-6 text-white shadow-lg">
      <h3 class="mb-4 text-lg font-semibold">Complete Payment</h3>

      <div class="mb-6 flex flex-col gap-2 md:flex-row md:items-center md:gap-1">
        @for (s of flowSteps; track s.key; let i = $index; let last = $last) {
          <div class="flex items-center gap-2">
            <div class="flex items-center gap-1">
              <div
                class="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full text-xs font-bold transition-colors"
                [ngClass]="stepBadgeClass(s.key)"
              >
                @if (stepCompleted(s.key)) { ✓ }
                @else { {{ s.num }} }
              </div>
              <span
                class="hidden text-xs md:inline"
                [ngClass]="stepTextClass(s.key)"
              >{{ s.label }}</span>
            </div>
            @if (!last) {
              <div
                class="mx-1 h-px w-6 flex-shrink-0 md:w-10"
                [ngClass]="stepConnectorClass(i)"
              ></div>
            }
          </div>
        }
      </div>

      <div class="mb-4 min-h-[120px]">
        @if (step() === 'verifying' || step() === 'building' || step() === 'signing' || step() === 'submitting') {
          <div class="flex flex-col items-center gap-3 py-4">
            <svg class="h-8 w-8 animate-spin text-blue-400" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            <p class="text-sm text-gray-300">{{ stepMessage() }}</p>
            @if (step() === 'signing') {
              <p class="text-xs text-gray-500">Check your Freighter extension</p>
            }
          </div>
        }

        @if (step() === 'done') {
          <div class="flex flex-col items-center gap-3 py-4">
            <div class="flex h-12 w-12 items-center justify-center rounded-full bg-green-500 text-2xl text-white">✓</div>
            <p class="text-lg font-bold text-green-400">Payment sent</p>
            <p class="text-sm text-gray-300">
              {{ amount }} {{ asset }} → {{ recipientAddress.slice(0, 4) }}...{{ recipientAddress.slice(-4) }}
            </p>
            @if (txHash(); as hash) {
              <a
                [href]="'https://stellar.expert/explorer/testnet/tx/' + hash"
                target="_blank"
                class="max-w-full truncate text-xs text-blue-400 underline hover:text-blue-300"
              >
                {{ hash }}
              </a>
            }
            <p class="text-xs text-gray-500">Proof verified on-chain • Nullifier recorded • Privacy preserved</p>
            <button
              (click)="reset()"
              class="mt-2 rounded-lg bg-[#16a34a] px-6 py-2 font-semibold transition-colors hover:bg-[#15803d]"
            >
              Send Another Payment
            </button>
          </div>
        }

        @if (step() === 'error') {
          <div class="flex flex-col items-center gap-3 py-4">
            <div class="flex h-12 w-12 items-center justify-center rounded-full bg-red-500 text-2xl text-white">✗</div>
            <p class="text-sm text-red-300">{{ error() }}</p>
            <button
              (click)="sendPayment()"
              class="mt-2 rounded-lg bg-[#2563eb] px-6 py-2 font-semibold transition-colors hover:bg-[#1d4ed8]"
            >
              Try Again
            </button>
          </div>
        }

        @if (step() === 'idle') {
          <div class="flex flex-col items-center gap-3 py-4">
            <p class="text-sm text-gray-400">Press send to start the compliance verification and payment flow</p>
            <button
              (click)="sendPayment()"
              class="mt-2 w-full rounded-lg bg-[#16a34a] px-6 py-3 font-semibold transition-colors hover:bg-[#15803d]"
            >
              Send Payment
            </button>
          </div>
        }
      </div>
    </div>
  `,
})
export class PaymentSendComponent {
  @Input({ required: true }) proofResult!: ProofResult;
  @Input({ required: true }) amount!: string;
  @Input({ required: true }) asset!: string;
  @Input({ required: true }) corridorId!: string;
  @Input({ required: true }) recipientAddress!: string;
  @Output() paymentComplete = new EventEmitter<void>();

  flowSteps = [
    { num: 1, key: 'verifying' as const, label: 'On-chain Verify' },
    { num: 2, key: 'building' as const, label: 'Build Tx' },
    { num: 3, key: 'signing' as const, label: 'Sign with Freighter' },
    { num: 4, key: 'submitting' as const, label: 'Submit' },
  ];

  step = signal<PaymentStep>('idle');
  txHash = signal<string | null>(null);
  error = signal<string | null>(null);
  ledger = signal<number | null>(null);

  stepOrder: PaymentStep[] = ['idle', 'verifying', 'building', 'signing', 'submitting', 'done', 'error'];

  stepIndex = computed(() => this.stepOrder.indexOf(this.step()));

  stepMessage = computed(() => {
    switch (this.step()) {
      case 'verifying': return 'Verifying proof on Stellar testnet...';
      case 'building': return 'Building payment transaction...';
      case 'signing': return 'Awaiting Freighter signature...';
      case 'submitting': return 'Submitting to Stellar network...';
      default: return '';
    }
  });

  constructor(
    private stellarService: StellarService,
    private http: HttpClient
  ) {}

  stepBadgeClass(key: string): Record<string, boolean> {
    const currentIdx = this.flowSteps.findIndex(s => s.key === key);
    const s = this.step();
    const currentStepIdx = this.flowSteps.findIndex(fs => fs.key === s);
    const isDone = currentIdx < currentStepIdx || (s === 'done' && currentIdx < this.flowSteps.length);
    const isActive = this.flowSteps[currentIdx]?.key === s;
    return {
      'bg-green-500 text-white': isDone,
      'bg-yellow-500 text-black': isActive && !isDone,
      'bg-gray-600 text-gray-400': !isDone && !isActive,
    };
  }

  stepTextClass(key: string): Record<string, boolean> {
    const currentIdx = this.flowSteps.findIndex(s => s.key === key);
    const s = this.step();
    const currentStepIdx = this.flowSteps.findIndex(fs => fs.key === s);
    const isDone = currentIdx < currentStepIdx || s === 'done';
    const isActive = this.flowSteps[currentIdx]?.key === s;
    return {
      'text-green-400': isDone,
      'text-yellow-400': isActive && !isDone,
      'text-gray-600': !isDone && !isActive,
    };
  }

  stepCompleted(key: string): boolean {
    const currentIdx = this.flowSteps.findIndex(s => s.key === key);
    const s = this.step();
    const currentStepIdx = this.flowSteps.findIndex(fs => fs.key === s);
    return currentIdx < currentStepIdx || s === 'done';
  }

  stepConnectorClass(index: number): Record<string, boolean> {
    const s = this.step();
    const nextKey = this.flowSteps[index + 1]?.key;
    const nextIdx = this.flowSteps.findIndex(fs => fs.key === nextKey);
    const currentStepIdx = this.flowSteps.findIndex(fs => fs.key === s);
    return {
      'bg-green-500': nextIdx <= currentStepIdx || s === 'done',
      'bg-gray-700': nextIdx > currentStepIdx && s !== 'done',
    };
  }

  async sendPayment(): Promise<void> {
    this.step.set('verifying');
    this.error.set(null);
    this.txHash.set(null);

    try {
      const pi = this.proofResult.publicInputs;
      const relayResult: any = await lastValueFrom(
        this.http.post(`${environment.apiUrl}/proof/relay`, {
          proof: this.proofResult.proof,
          publicInputs: {
            nullifier: this.proofResult.nullifier,
            issuer_pubkey_hash: pi.issuer_pubkey_hash,
            payment_asset: pi.payment_asset,
            aml_threshold: pi.aml_threshold,
            corridor_id: pi.corridor_id,
            amount_commitment: pi.amount_commitment,
            revocation_root: pi.revocation_root,
            approved_corridors_root: pi.approved_corridors_root,
            allowed_jurisdictions_root: pi.allowed_jurisdictions_root,
          },
        })
      );

      if (!relayResult.verified) {
        throw new Error(relayResult.error || 'Proof verification failed on-chain');
      }

      this.step.set('building');

      const buildResult: any = await lastValueFrom(
        this.http.post(`${environment.apiUrl}/payment/build-unsigned`, {
          fromAddress: this.stellarService.address(),
          toAddress: this.recipientAddress,
          amount: this.amount,
          asset: this.asset,
          assetIssuer: this.asset === 'XLM' ? undefined : 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          nullifier: this.proofResult.nullifier,
        })
      );

      const unsignedXdr = buildResult.unsignedXdr;

      this.step.set('signing');

      const freighter = await import('@stellar/freighter-api');
      const signedRes = await freighter.signTransaction(unsignedXdr, {
        networkPassphrase:
          environment.stellarNetwork === 'testnet'
            ? 'Test SDF Network ; September 2015'
            : 'Public Global Stellar Network ; September 2015',
      });

      this.step.set('submitting');

      const sendResult: any = await lastValueFrom(
        this.http.post(`${environment.apiUrl}/payment/send`, {
          signedXdr: signedRes.signedTxXdr,
          nullifier: this.proofResult.nullifier,
        })
      );

      if (!sendResult.success) {
        throw new Error(sendResult.error || 'Payment submission failed');
      }

      this.txHash.set(sendResult.txHash);
      this.ledger.set(sendResult.ledger);
      this.step.set('done');
      this.paymentComplete.emit();
    } catch (err: any) {
      this.error.set(err.message || 'Payment flow failed');
      this.step.set('error');
    }
  }

  reset(): void {
    this.step.set('idle');
    this.txHash.set(null);
    this.error.set(null);
    this.ledger.set(null);
    this.paymentComplete.emit();
  }
}
