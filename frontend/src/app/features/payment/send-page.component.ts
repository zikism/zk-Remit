import { Component, signal, computed } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NgClass } from '@angular/common';
import { WalletConnectComponent } from '../wallet/wallet-connect.component';
import { CredentialFetchComponent, Credential } from '../credential/credential-fetch.component';
import { ProofGenerateComponent } from '../proof/proof-generate.component';
import { PaymentSendComponent } from './payment-send.component';
import { ProofResult } from '../../shared/services/noir.service';

@Component({
  selector: 'app-send-page',
  standalone: true,
  imports: [
    FormsModule,
    NgClass,
    WalletConnectComponent,
    CredentialFetchComponent,
    ProofGenerateComponent,
    PaymentSendComponent,
  ],
  template: `
    <div class="space-y-6">
      <div class="mb-6 flex flex-col gap-2 md:flex-row md:items-center md:gap-1">
        @for (s of steps; track s.num; let i = $index; let last = $last) {
          <div class="flex items-center gap-2">
            <div
              class="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full text-sm font-bold"
              [ngClass]="{
                'bg-green-500 text-white': s.num < currentStep(),
                'bg-yellow-500 text-black': s.num === currentStep(),
                'bg-gray-700 text-gray-500': s.num > currentStep()
              }"
            >
              @if (s.num < currentStep()) { ✓ }
              @else { {{ s.num }} }
            </div>
            <span
              class="hidden text-sm md:inline"
              [ngClass]="{
                'text-green-400': s.num <= currentStep(),
                'text-gray-500': s.num > currentStep(),
              }"
            >{{ s.label }}</span>
            @if (!last) {
              <div
                class="h-px w-6 md:w-10"
                [ngClass]="{
                  'bg-green-500': s.num < currentStep(),
                  'bg-gray-700': s.num >= currentStep()
                }"
              ></div>
            }
          </div>
        }
      </div>

      <div class="space-y-6">
        <!-- Step 1: Wallet -->
        <div
          class="cursor-pointer rounded-xl bg-[#1e293b] p-4 shadow-lg"
          (click)="toggleStep(1)"
        >
          <div class="flex items-center justify-between">
            <h3 class="text-lg font-semibold text-white">1. Connect Wallet</h3>
            <span class="text-gray-500">{{ stepCollapsed(1) ? '▼' : '▲' }}</span>
          </div>
        </div>
        @if (!stepCollapsed(1)) {
          <div class="ml-2">
            <app-wallet-connect (connected)="onWalletConnected($event)" />
          </div>
        }

        <!-- Step 2: Credential -->
        @if (currentStep() >= 2) {
          <div
            class="cursor-pointer rounded-xl bg-[#1e293b] p-4 shadow-lg"
            (click)="toggleStep(2)"
          >
            <div class="flex items-center justify-between">
              <h3 class="text-lg font-semibold text-white">2. Get Credential</h3>
              <span class="text-gray-500">{{ stepCollapsed(2) ? '▼' : '▲' }}</span>
            </div>
          </div>
          @if (!stepCollapsed(2)) {
            <div class="ml-2">
              <app-credential-fetch
                [walletAddress]="walletAddress()!"
                (credentialFetched)="onCredentialFetched($event)"
              />
            </div>
          }
        }

        <!-- Step 3: Proof -->
        @if (currentStep() >= 3) {
          <div
            class="cursor-pointer rounded-xl bg-[#1e293b] p-4 shadow-lg"
            (click)="toggleStep(3)"
          >
            <div class="flex items-center justify-between">
              <h3 class="text-lg font-semibold text-white">3. Generate ZK Proof</h3>
              <span class="text-gray-500">{{ stepCollapsed(3) ? '▼' : '▲' }}</span>
            </div>
          </div>
          @if (!stepCollapsed(3)) {
            <div class="ml-2">
              <app-proof-generate
                [credential]="credential()!"
                [amount]="paymentAmount()"
                [corridorId]="selectedCorridor()"
                [paymentAsset]="paymentAsset()"
                (proofGenerated)="onProofGenerated($event)"
              />
            </div>
          }
        }

        <!-- Step 4: Payment -->
        @if (currentStep() >= 4) {
          <div
            class="cursor-pointer rounded-xl bg-[#1e293b] p-4 shadow-lg"
            (click)="toggleStep(4)"
          >
            <div class="flex items-center justify-between">
              <h3 class="text-lg font-semibold text-white">4. Send Payment</h3>
              <span class="text-gray-500">{{ stepCollapsed(4) ? '▼' : '▲' }}</span>
            </div>
          </div>
          @if (!stepCollapsed(4)) {
            <div class="ml-2 space-y-4">
              <div class="rounded-xl bg-[#1e293b] p-6 text-white shadow-lg">
                <label class="mb-1 block text-sm text-gray-400">Recipient Stellar Address</label>
                <input
                  type="text"
                  [(ngModel)]="recipientAddress"
                  placeholder="G..."
                  class="w-full rounded-lg border border-gray-600 bg-gray-800 p-3 font-mono text-white"
                />
              </div>
              <app-payment-send
                [proofResult]="proofResult()!"
                [amount]="paymentAmountDisplay()"
                [asset]="paymentAsset()"
                [corridorId]="selectedCorridor()"
                [recipientAddress]="recipientAddress()"
                (paymentComplete)="onPaymentComplete()"
              />
            </div>
          }
        }
      </div>
    </div>
  `,
})
export class SendPageComponent {
  steps = [
    { num: 1, label: 'Wallet' },
    { num: 2, label: 'Credential' },
    { num: 3, label: 'Proof' },
    { num: 4, label: 'Payment' },
  ];

  currentStep = signal(1);
  walletAddress = signal<string | null>(null);
  credential = signal<Credential | null>(null);
  proofResult = signal<ProofResult | null>(null);
  recipientAddress = signal('');

  selectedCorridor = signal('NG-PH');
  paymentAmount = signal(500);
  paymentAsset = signal('USDC');
  paymentAmountDisplay = computed(() => this.paymentAmount().toString());
  collapsedSteps = signal<Set<number>>(new Set());

  toggleStep(num: number): void {
    const current = this.collapsedSteps();
    if (current.has(num)) {
      current.delete(num);
    } else {
      current.add(num);
    }
    this.collapsedSteps.set(new Set(current));
  }

  stepCollapsed(num: number): boolean {
    return this.collapsedSteps().has(num);
  }

  onWalletConnected(address: string): void {
    this.walletAddress.set(address);
    this.currentStep.set(2);
  }

  onCredentialFetched(c: Credential): void {
    this.credential.set(c);
    this.selectedCorridor.set(c.corridorLabel);
    this.currentStep.set(3);
  }

  onProofGenerated(result: ProofResult): void {
    this.proofResult.set(result);
    this.currentStep.set(4);
  }

  onPaymentComplete(): void {
  }
}
