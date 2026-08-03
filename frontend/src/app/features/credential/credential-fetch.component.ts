import { Component, Input, Output, EventEmitter, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NgClass } from '@angular/common';
import {
  CredentialService,
  CredentialResponse,
} from '../../shared/services/credential.service';

export interface Credential extends CredentialResponse {
  corridorLabel: string;
}

const CORRIDORS = [
  { id: 'NG-PH', label: 'Lagos → Manila' },
  { id: 'NG-GB', label: 'Lagos → London' },
  { id: 'GH-US', label: 'Accra → New York' },
  { id: 'KE-DE', label: 'Nairobi → Berlin' },
] as const;

@Component({
  selector: 'app-credential-fetch',
  standalone: true,
  imports: [FormsModule, NgClass],
  template: `
    <div class="rounded-xl bg-[#1e293b] p-6 text-white shadow-lg">
      <h3 class="mb-4 text-lg font-semibold">Payment Details</h3>

      <div class="mb-4">
        <label class="mb-1 block text-sm text-gray-400">Corridor</label>
        <select
          [(ngModel)]="selectedCorridor"
          class="w-full rounded-lg border border-gray-600 bg-gray-800 p-2 text-white"
        >
          @for (c of corridors; track c.id) {
            <option [value]="c.id">{{ c.label }} ({{ c.id }})</option>
          }
        </select>
      </div>

      <div class="mb-4">
        <label class="mb-1 block text-sm text-gray-400">Amount</label>
        <div class="flex gap-2">
          <input
            type="number"
            [(ngModel)]="paymentAmount"
            min="1"
            class="w-full rounded-lg border border-gray-600 bg-gray-800 p-2 text-white"
          />
          <span class="flex items-center text-sm text-gray-400">USD</span>
        </div>
      </div>

      <div class="mb-6">
        <label class="mb-2 block text-sm text-gray-400">Asset</label>
        <div class="flex gap-4">
          @for (a of assets; track a) {
            <label class="flex items-center gap-2">
              <input
                type="radio"
                [(ngModel)]="paymentAsset"
                [value]="a"
                class="accent-green-500"
              />
              {{ a }}
            </label>
          }
        </div>
      </div>

      <button
        (click)="fetchCredential()"
        [disabled]="isLoading() || !walletAddress"
        class="w-full rounded-lg bg-[#16a34a] px-6 py-3 font-semibold transition-colors hover:bg-[#15803d] disabled:cursor-not-allowed disabled:opacity-50"
      >
        @if (isLoading()) {
          <span class="flex items-center justify-center gap-2">
            <svg class="h-5 w-5 animate-spin" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            Verifying KYC status...
          </span>
        } @else {
          Get Compliance Credential
        }
      </button>

      @if (error()) {
        <div class="mt-3 rounded-lg bg-red-900/50 p-3 text-sm text-red-300">
          ✗ {{ error() }}
        </div>
      }

      @if (credential(); as c) {
        <div class="mt-4 rounded-lg border border-green-600/30 bg-green-900/20 p-4">
          <div class="mb-1 flex items-center gap-2 text-green-400">
            <span>✓</span>
            <span class="font-semibold">Credential issued</span>
          </div>
          <p class="text-sm text-gray-400">
            Valid until: {{ formatExpiry(c.expiry) }}
          </p>
          <div class="mt-3 grid grid-cols-1 gap-2 text-xs text-gray-400 md:grid-cols-2">
            <span>Issuer: mock-issuer</span>
            <span>Corridor: {{ c.corridorLabel }}</span>
            <span>Jurisdiction: {{ c.jurisdictionCode }}</span>
            <span>Credential: {{ c.credentialHash.slice(0, 10) }}...</span>
          </div>
        </div>
      }
    </div>
  `,
})
export class CredentialFetchComponent {
  @Input({ required: true }) walletAddress!: string;
  @Output() credentialFetched = new EventEmitter<Credential>();

  corridors = CORRIDORS;
  assets = ['USDC', 'XLM'];

  selectedCorridor = 'NG-PH';
  paymentAmount = 500;
  paymentAsset = 'USDC';
  credential = signal<Credential | null>(null);
  isLoading = signal(false);
  error = signal<string | null>(null);

  constructor(private credentialService: CredentialService) {}

  formatExpiry(expiry: number): string {
    return new Date(expiry * 1000).toLocaleDateString();
  }

  async fetchCredential(): Promise<void> {
    if (!this.walletAddress) return;

    this.isLoading.set(true);
    this.error.set(null);

    try {
      const res = await this.credentialService.issue({
        walletAddress: this.walletAddress,
        kycProvider: 'mock-issuer',
        corridorId: this.selectedCorridor,
      });

      const credential: Credential = {
        ...res,
        corridorLabel: this.selectedCorridor,
      };

      this.credential.set(credential);
      this.credentialFetched.emit(credential);
    } catch (err: any) {
      this.error.set(err.message || 'Failed to fetch credential');
    } finally {
      this.isLoading.set(false);
    }
  }
}
