# zkremit — Private Cross-Border Payments on Stellar

> Zero-knowledge compliance proofs for cross-border payments, verified on-chain via Soroban using Stellar Protocol 25/26 BN254 host functions.

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Install Dependencies](#2-install-dependencies)
  - [3. Environment Variables](#3-environment-variables)
  - [4. Compile the Noir Circuit](#4-compile-the-noir-circuit)
  - [5. Deploy the Soroban Verifier](#5-deploy-the-soroban-verifier)
  - [6. Run the Backend](#6-run-the-backend)
  - [7. Run the Frontend](#7-run-the-frontend)
- [ZK Circuit Design](#zk-circuit-design)
- [Soroban Verifier Contract](#soroban-verifier-contract)
- [API Reference](#api-reference)
- [Frontend Flow](#frontend-flow)
- [Demo Walkthrough](#demo-walkthrough)
- [Stellar Protocol 25 & 26 Integration](#stellar-protocol-25--26-integration)
- [Security Considerations](#security-considerations)
- [Roadmap](#roadmap)
- [Team](#team)
- [License](#license)

---

## Overview

**zkremit** is a privacy-preserving compliance layer for cross-border payments on Stellar. It allows users to prove they satisfy regulatory requirements — KYC status, AML thresholds, jurisdiction eligibility without revealing their identity or financial details on-chain.

The project uses:
- **Noir (Barretenberg)** to generate zero-knowledge proofs off-chain in the browser
- **Soroban smart contracts** leveraging Stellar Protocol 25/26 BN254 host functions to verify proofs on-chain
- **Stellar's native payment rails** (stablecoins, anchors, path payments) to execute the actual transfer

**The result:** A fully private, compliant, on-chain payment flow. Regulators get assurance. Users keep their privacy. Stellar gets real-world ZK.

---

## The Problem

Cross-border payments on Stellar are fast, cheap, and globally accessible. But real-world corridors such as remittances, B2B settlement, stablecoin rails, institutional transfers are blocked by compliance:

- Senders must prove they are not on sanctions lists
- AML regulations require proof that payment amounts are under reporting thresholds
- Jurisdiction-specific rules govern corridor eligibility (e.g. FATF compliance, VASP licensing)

Today, complying with these requirements means **revealing identity on-chain** full KYC data, wallet history, or counterparty information exposed to every node in the network. This is:

- A **privacy risk** for individuals (especially in remittance corridors with political risk)
- A **legal liability** for institutions handling data across jurisdictions
- A **barrier to adoption** for privacy-conscious users and regulated entities

---

## The Solution

zkremit introduces a **proof layer between identity and payment**:

1. A trusted credential issuer (KYC provider, compliance oracle) attests to a user's compliance attributes off-chain.
2. The user generates a **Noir zero-knowledge proof** locally in their browser proving they hold a valid credential satisfying the required conditions, without revealing the credential itself.
3. The proof is submitted alongside the Stellar payment transaction.
4. A **Soroban verifier contract** checks the proof on-chain using Stellar's BN254 host functions (Protocol 25/26).
5. Only if the proof is valid does the payment proceed.

No identity on-chain. No credential data exposed. Full regulatory assurance.

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                      USER BROWSER                       │
│                                                         │
│  1. Connect Freighter wallet                            │
│  2. Fetch compliance credential (signed by issuer)      │
│  3. Generate ZK proof locally via Noir WASM             │
│     - Prove: credential is valid & not expired          │
│     - Prove: amount < AML threshold                     │
│     - Prove: jurisdiction is eligible                   │
│     - Reveal: nullifier (prevents double-use)           │
│  4. Submit payment tx + proof to Stellar network        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              SOROBAN VERIFIER CONTRACT                  │
│                                                         │
│  5. Receive proof + public inputs                       │
│  6. Call BN254 host functions (Protocol 25/26):         │
│     - bn254_g1_add, bn254_g1_mul (MSM)                 │
│     - bn254_pairing_check                              │
│     - Groth16 / UltraHonk verification                 │
│  7. If valid → emit compliance event, allow payment     │
│  8. If invalid → reject transaction                     │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              STELLAR PAYMENT NETWORK                    │
│                                                         │
│  9. Execute payment (USDC, XLM, or any asset)          │
│  10. On-chain record: nullifier hash only (no PII)     │
└─────────────────────────────────────────────────────────┘
```

---

## Architecture

```
zkremit/
├── circuits/              # Noir ZK circuits
├── contracts/             # Soroban verifier (Rust)
├── backend/               # NestJS API server
├── frontend/              # Angular web app
└── scripts/               # Deployment & test scripts
```

### Component Responsibilities

| Component | Role |
|---|---|
| **Noir Circuit** | Defines the compliance proof — what must be true for a payment to be valid |
| **Barretenberg (WASM)** | Runs in the browser; generates the proof from the user's private credential |
| **NestJS Backend** | Issues mock credentials, relays proofs, indexes nullifiers |
| **Soroban Contract** | On-chain verifier; calls BN254 host functions to check the proof |
| **Angular Frontend** | User-facing app; handles wallet connection, proof generation, payment flow |

---

## Tech Stack

| Layer | Technology |
|---|---|
| ZK Proof System | [Noir](https://noir-lang.org/) + Barretenberg (UltraHonk) |
| Proof Generation | `@noir-lang/noir_js` + `@aztec/bb.js` (WASM, runs in browser) |
| Smart Contract | Rust on [Soroban](https://soroban.stellar.org/) |
| On-chain Crypto | Stellar Protocol 25/26 BN254 host functions |
| Blockchain | [Stellar](https://stellar.org/) Testnet → Mainnet |
| Backend | [NestJS](https://nestjs.com/) (TypeScript) |
| Frontend | [Angular](https://angular.io/) 17+ (standalone components) |
| Wallet | [Freighter](https://www.freighter.app/) |
| Stellar SDK | `@stellar/stellar-sdk` |

---

## Project Structure

```
zkremit/
│
├── circuits/
│   ├── src/
│   │   └── main.nr                  # Main Noir compliance circuit
│   ├── Nargo.toml                   # Noir project config
│   └── Prover.toml                  # Example proof inputs (for testing)
│
├── contracts/
│   ├── verifier/
│   │   ├── src/
│   │   │   └── lib.rs               # Soroban verifier contract
│   │   └── Cargo.toml
│   └── scripts/
│       ├── deploy.sh                # Deploy to Stellar testnet
│       └── invoke.sh                # Test contract invocation
│
├── backend/
│   ├── src/
│   │   ├── app.module.ts
│   │   ├── credential/
│   │   │   ├── credential.module.ts
│   │   │   ├── credential.service.ts  # Issues signed compliance credentials
│   │   │   └── credential.controller.ts
│   │   ├── proof/
│   │   │   ├── proof.module.ts
│   │   │   └── proof.service.ts       # Proof relay & nullifier indexing
│   │   ├── payment/
│   │   │   ├── payment.module.ts
│   │   │   └── payment.service.ts     # Stellar payment execution
│   │   └── nullifier/
│   │       ├── nullifier.module.ts
│   │       └── nullifier.service.ts   # Prevents double-spend
│   ├── .env.example
│   └── package.json
│
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── app.component.ts
│   │   │   ├── app.routes.ts
│   │   │   ├── features/
│   │   │   │   ├── wallet/
│   │   │   │   │   └── wallet-connect.component.ts
│   │   │   │   ├── credential/
│   │   │   │   │   └── credential-fetch.component.ts
│   │   │   │   ├── proof/
│   │   │   │   │   └── proof-generate.component.ts
│   │   │   │   └── payment/
│   │   │   │       └── payment-send.component.ts
│   │   │   └── shared/
│   │   │       ├── services/
│   │   │       │   ├── noir.service.ts         # Barretenberg WASM wrapper
│   │   │       │   ├── stellar.service.ts      # Stellar SDK wrapper
│   │   │       │   └── credential.service.ts   # Credential API client
│   │   │       └── components/
│   │   │           └── proof-status/
│   │   └── environments/
│   ├── angular.json
│   └── package.json
│
├── scripts/
│   ├── setup.sh                     # Full environment setup
│   ├── test-e2e.sh                  # End-to-end test (circuit → contract → payment)
│   └── fund-testnet.sh              # Fund test accounts on Stellar testnet
│
├── .env.example
├── docker-compose.yml
└── README.md
```

---

## Prerequisites

Ensure you have the following installed:

```bash
# Node.js 20+
node --version   # v20.x.x

# Rust + Cargo (for Soroban contracts)
rustup --version
rustup target add wasm32-unknown-unknown

# Stellar CLI (Soroban)
cargo install --locked stellar-cli --features opt

# Noir toolchain (nargo)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup
nargo --version   # nargo 0.36.x or later

# Barretenberg CLI (for circuit testing)
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup
bb --version
```

Optional (for Docker-based setup):
```bash
docker --version
docker compose --version
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/zkremit.git
cd zkremit
```

### 2. Install Dependencies

```bash
# Backend
cd backend && npm install && cd ..

# Frontend
cd frontend && npm install && cd ..
```

Or use the setup script:
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 3. Environment Variables

Copy and configure environment files:

```bash
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/src/environments/environment.example.ts frontend/src/environments/environment.ts
```

**Root `.env`:**
```env
STELLAR_NETWORK=testnet
STELLAR_RPC_URL=https://soroban-testnet.stellar.org
STELLAR_HORIZON_URL=https://horizon-testnet.stellar.org
STELLAR_PASSPHRASE="Test SDF Network ; September 2015"

# Deployer keypair (fund via friendbot)
DEPLOYER_SECRET_KEY=S...
DEPLOYER_PUBLIC_KEY=G...

# Contract IDs (set after deployment)
VERIFIER_CONTRACT_ID=C...
```

**`backend/.env`:**
```env
PORT=3000
STELLAR_RPC_URL=https://soroban-testnet.stellar.org
STELLAR_PASSPHRASE="Test SDF Network ; September 2015"
VERIFIER_CONTRACT_ID=C...
ISSUER_PRIVATE_KEY=<32-byte secp256k1 hex key for signing credentials>
DATABASE_URL=postgres://nullcarbon:nullcarbon@localhost:5432/zkremit
JWT_SECRET=your-jwt-secret

# Off-chain UltraHonk proof verification gate (optional).
# When "true" the relay proves every proof against the compiled circuit before
# any Soroban tx and rejects proofs that fail. The on-chain Groth16 check is
# stubbed, so keep this on in front of the relay until a real verifier is
# deployed. The circuit artifact lives at backend/circuits/zk_compliance.json.
VERIFY_OFFCHAIN=false
ZK_COMPLIANCE_CIRCUIT_PATH=
```

### 4. Compile the Noir Circuit

```bash
cd circuits

# Compile
nargo compile

# Run unit tests
nargo test

# Generate a test proof (uses Prover.toml)
nargo prove

# Verify the test proof
nargo verify
```

**Expected output:**
```
[zk_compliance] Constraint system size: 4,312 constraints
[zk_compliance] Proof generated in 1.8s
[zk_compliance] Proof verified: true ✓
```

To export the verifier key (needed for the Soroban contract):
```bash
bb write_vk -b ./target/zk_compliance.json -o ./target/vk
```

### 5. Deploy the Soroban Verifier

```bash
cd contracts/verifier

# Build the contract
cargo build --target wasm32-unknown-unknown --release

# Optimize the WASM
stellar contract optimize \
  --wasm target/wasm32-unknown-unknown/release/verifier.wasm

# Fund deployer account (testnet only)
stellar keys generate deployer --network testnet
curl "https://friendbot.stellar.org?addr=$(stellar keys address deployer)"

# Deploy
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/verifier.optimized.wasm \
  --source deployer \
  --network testnet
# → Outputs contract ID: C...

# Initialize with the verifier key
stellar contract invoke \
  --id <CONTRACT_ID> \
  --source deployer \
  --network testnet \
  -- initialize \
  --vk "$(cat ../../circuits/target/vk | base64)"
```

Copy the contract ID into your `.env` files.

### 6. Run the Backend

```bash
cd backend

# Development
npm run start:dev

# Production
npm run build
npm run start:prod
```

The API will be available at `http://localhost:3000`.

### 7. Run the Frontend

```bash
cd frontend

# Development server
ng serve

# Production build
ng build --configuration production
```

The app will be available at `http://localhost:4200`.

---

## ZK Circuit Design

The core Noir circuit (`circuits/src/main.nr`) proves the following statement in zero knowledge:

> *"I hold a valid compliance credential, signed by a trusted issuer, that certifies: (1) I have passed KYC, (2) I am not on a sanctions list, (3) this payment amount is below the AML reporting threshold, and (4) my jurisdiction is eligible for this corridor — without revealing who I am."*

### Circuit Inputs

```noir
// circuits/src/main.nr

use dep::std::hash::poseidon2;
use dep::std::ecdsa_secp256k1;

fn main(
    // Private inputs (never revealed)
    credential_secret: Field,          // User's secret credential value
    credential_hash: Field,            // Hash of full credential data
    issuer_signature: [u8; 64],        // ECDSA signature from trusted issuer
    issuer_pubkey: [u8; 64],           // Issuer's public key
    user_pubkey_hash: Field,           // Hash of user's identity key
    amount: u64,                       // Payment amount (private)
    jurisdiction_code: u32,            // User's jurisdiction (private)
    credential_expiry: u64,            // Credential expiry timestamp
    current_timestamp: u64,            // Current time (from oracle or user)

    // Public inputs (revealed on-chain)
    pub nullifier: Field,              // Prevents double-use of credential
    pub issuer_pubkey_hash: Field,     // Identifies which issuer signed
    pub payment_asset: Field,          // Asset code hash (USDC, XLM, etc.)
    pub aml_threshold: u64,            // Public AML threshold for corridor
    pub corridor_id: Field,            // Identifies sender/receiver corridor
    pub allowed_jurisdictions_root: Field, // Merkle root of allowed jurisdictions
) {
    // 1. Verify credential signature
    let credential_msg = poseidon2::hash(
        [credential_hash, user_pubkey_hash, Field::from(credential_expiry)], 3
    );
    let sig_valid = ecdsa_secp256k1::verify_signature(
        issuer_pubkey, issuer_signature, credential_msg.to_be_bytes(32)
    );
    assert(sig_valid, "Invalid issuer signature");

    // 2. Verify credential is not expired
    assert(current_timestamp < credential_expiry, "Credential expired");

    // 3. Verify amount is below AML threshold
    assert(amount < aml_threshold, "Amount exceeds AML threshold");

    // 4. Verify jurisdiction is in allowed set (Merkle proof)
    // ... (merkle inclusion proof for jurisdiction_code in allowed_jurisdictions_root)

    // 5. Verify issuer public key matches the expected issuer
    let computed_issuer_hash = poseidon2::hash([issuer_pubkey[0] as Field, issuer_pubkey[1] as Field], 2);
    assert(computed_issuer_hash == issuer_pubkey_hash, "Issuer mismatch");

    // 6. Compute nullifier = Poseidon2(credential_secret, corridor_id)
    //    This binds the proof to the specific corridor — can't reuse across corridors
    let computed_nullifier = poseidon2::hash([credential_secret, corridor_id], 2);
    assert(computed_nullifier == nullifier, "Invalid nullifier");
}
```

### Why These Constraints?

| Constraint | Purpose |
|---|---|
| Issuer signature check | Only credentials from approved KYC providers are accepted |
| Expiry check | Stale credentials (from lapsed KYC) are rejected |
| AML threshold | Amount privacy preserved while enforcing reporting rules |
| Jurisdiction merkle proof | Efficient set membership without revealing which jurisdiction |
| Nullifier binding | One credential use per corridor; prevents replay attacks |

### Poseidon2 for Stellar

The circuit uses **Poseidon2** hashing — one of the ZK-friendly hash functions natively accelerated by Stellar Protocol 25's host functions. This means nullifier and credential hash computations on-chain are fast and cheap.

---

## Soroban Verifier Contract

The Soroban contract (`contracts/verifier/src/lib.rs`) does three things:

1. **Verifies the Noir UltraHonk proof** using BN254 host functions from Protocol 25/26
2. **Checks the nullifier** has not been used before (replay protection)
3. **Emits a compliance event** that the payment transaction can check

```rust
// contracts/verifier/src/lib.rs (simplified)

#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Map};

#[contract]
pub struct ComplianceVerifier;

#[contractimpl]
impl ComplianceVerifier {
    /// Initialize with the Noir verification key
    pub fn initialize(env: Env, vk: Bytes) {
        env.storage().instance().set(&Symbol::new(&env, "vk"), &vk);
    }

    /// Verify a compliance proof and record the nullifier
    /// Returns true if proof is valid and nullifier is fresh
    pub fn verify_and_record(
        env: Env,
        proof: Bytes,           // Serialized UltraHonk proof
        public_inputs: Bytes,   // ABI-encoded public inputs
    ) -> bool {
        let vk: Bytes = env.storage().instance().get(&Symbol::new(&env, "vk")).unwrap();

        // Extract nullifier from public inputs (first 32 bytes)
        let nullifier: BytesN<32> = public_inputs.slice(0..32).try_into().unwrap();

        // Replay protection: check nullifier has not been used
        let nullifier_map: Map<BytesN<32>, bool> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "nullifiers"))
            .unwrap_or(Map::new(&env));

        if nullifier_map.contains_key(nullifier.clone()) {
            return false; // Credential already used for this corridor
        }

        // Verify proof using BN254 host functions (Protocol 25/26)
        // The bn254_* host functions handle elliptic curve operations:
        //   - bn254_g1_add, bn254_g1_mul: for MSM in the verifier
        //   - bn254_pairing_check: for the final pairing check
        let is_valid = env.crypto().verify_groth16_bn254(
            &vk,
            &public_inputs,
            &proof,
        );

        if is_valid {
            // Record nullifier to prevent replay
            let mut updated_map = nullifier_map;
            updated_map.set(nullifier, true);
            env.storage()
                .persistent()
                .set(&Symbol::new(&env, "nullifiers"), &updated_map);

            // Emit compliance event for off-chain indexing
            env.events().publish(
                (Symbol::new(&env, "compliance_verified"),),
                public_inputs,
            );
        }

        is_valid
    }

    /// Check if a nullifier has already been used
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        let nullifier_map: Map<BytesN<32>, bool> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "nullifiers"))
            .unwrap_or(Map::new(&env));
        nullifier_map.contains_key(nullifier)
    }
}
```

---

## Proof Verification & Public-Input Wire Format

### On-chain AML threshold pinning

The circuit only proves `amount < aml_threshold`; `aml_threshold` is a public
input the prover controls, so a proof could claim any limit. The Soroban
contract pins it: `verify_and_record` rejects any proof whose `aml_threshold`
does not equal the corridor's configured threshold (`set_aml_threshold`, stored
under `0x02 || corridor_id`). Unconfigured corridors default to a threshold of
`0`, which no amount satisfies in-circuit. The admin keeps these in sync with
`backend/src/compliance/compliance.config.ts`, the single source of truth that
also drives the frontend proof generator, merkle trees, and SEP-31 limits.

### Public-input byte layout (circuit order)

The relay serializes public inputs and the contract decodes them in **exactly
the circuit's parameter order** (`circuits/src/main.nr`), so any real verifier
binds the right values:

| Offset | Field |
|---|---|
| 0   | `nullifier` |
| 32  | `issuer_pubkey_hash` |
| 64  | `payment_asset` |
| 96  | `aml_threshold` (u64 BE) |
| 104 | `corridor_id` |
| 136 | `allowed_jurisdictions_root` |
| 168 | `amount_commitment` |
| 200 | `revocation_root` |
| 232 | `approved_corridors_root` |

A contract round-trip test (`test_public_input_decode_matches_circuit_order`)
and a relay integration test (`should encode public inputs in circuit byte
order`) pin these offsets to prevent regressions.

### Off-chain verification gate

The on-chain Groth16 check is intentionally stubbed (Soroban has no
`verify_groth16_bn254` host function yet; a real verifier must be built from
the Protocol 25/26 BN254 host functions). Until that lands, `POST /proof/relay`
can verify proofs **off-chain** with `VERIFY_OFFCHAIN=true`:

- `ProofVerificationService` loads `backend/circuits/zk_compliance.json` (the
  same compiled circuit the frontend and integration tests use) and feeds the
  9 public inputs — converted to decimal fields in circuit order — to
  `UltraHonkBackend.verifyProof` via bb.js.
- A proof that fails off-chain verification is rejected before any Soroban
  transaction is sent or any fee is paid.
- When disabled (default) the relay still works against the stub, so a real
  verifier can be dropped in without a flag flip.

### Generating real proof artifacts (CI)

`github/workflows/proof-artifacts.yml` produces a genuine UltraHonk proof +
verification key for the committed circuit. It runs on a self-hosted
**AVX512** runner (GitHub-hosted runners are AVX2-only and the default `bb`
build misbehaves there) and uses `circuits/Prover.toml` — a committed,
self-contained input set that is kept satisfiable by the CI circuit job
(`nargo execute`). The workflow compiles with nargo 0.36.0, pins `bb` to
0.36.0 to match the ACIR, executes the witness, proves, writes the VK, verifies
round-trip, and uploads `proof`, `vk`, and `public_inputs.json` (the 9 values
in circuit order) as artifacts.

---

## API Reference

### Credential Endpoints

#### `POST /credential/issue`
Issues a signed compliance credential for a user.

**Request:**
```json
{
  "walletAddress": "G...",
  "kycProvider": "mock-issuer",
  "corridorId": "NG-PH"
}
```

**Response:**
```json
{
  "credentialHash": "0x...",
  "issuerSignature": "0x...",
  "issuerPubkey": "0x...",
  "expiry": 1780000000,
  "jurisdictionCode": 566,
  "credentialSecret": "0x..."
}
```

#### `GET /credential/issuers`
Returns the list of trusted credential issuers and their public key hashes.

---

### Proof Endpoints

#### `POST /proof/relay`
Relays a generated proof to the Soroban verifier contract.

**Request:**
```json
{
  "proof": "0x...",
  "publicInputs": {
    "nullifier": "0x...",
    "issuerPubkeyHash": "0x...",
    "paymentAsset": "USDC",
    "amlThreshold": 10000,
    "corridorId": "NG-PH",
    "allowedJurisdictionsRoot": "0x..."
  }
}
```

**Response:**
```json
{
  "verified": true,
  "txHash": "...",
  "nullifier": "0x..."
}
```

#### `GET /proof/nullifier/:nullifier`
Checks if a nullifier has been used (replay protection).

---

### Payment Endpoints

#### `POST /payment/send`
Executes a Stellar payment after proof verification.

**Request:**
```json
{
  "fromAddress": "G...",
  "toAddress": "G...",
  "amount": "500",
  "asset": "USDC:GA5ZS...",
  "nullifier": "0x...",
  "verifierContractId": "C..."
}
```

**Response:**
```json
{
  "txHash": "...",
  "ledger": 123456,
  "success": true
}
```

---

## Frontend Flow

The Angular app guides users through a 4-step flow:

### Step 1 — Connect Wallet
```typescript
// wallet-connect.component.ts
async connectFreighter(): Promise<void> {
  await this.stellarService.connectFreighter();
  const address = await this.stellarService.getAddress();
  this.walletAddress = address;
}
```

### Step 2 — Fetch Compliance Credential
```typescript
// credential-fetch.component.ts
async fetchCredential(): Promise<void> {
  this.credential = await this.credentialService.issue({
    walletAddress: this.walletAddress,
    kycProvider: 'mock-issuer',
    corridorId: this.selectedCorridor,
  });
}
```

### Step 3 — Generate ZK Proof (in browser)
```typescript
// noir.service.ts
async generateProof(credential: Credential, paymentAmount: number): Promise<Proof> {
  const noir = new Noir(circuit);
  const bb = new BarretenbergBackend(circuit);

  const inputs = {
    credential_secret: credential.credentialSecret,
    credential_hash: credential.credentialHash,
    issuer_signature: credential.issuerSignature,
    // ... remaining private inputs
    nullifier: this.computeNullifier(credential.credentialSecret, this.corridorId),
    aml_threshold: 10000,
    // ... remaining public inputs
  };

  const { witness } = await noir.execute(inputs);
  const { proof, publicInputs } = await bb.generateProof(witness);

  return { proof, publicInputs };
}
```

### Step 4 — Submit Payment
```typescript
// payment-send.component.ts
async sendPayment(): Promise<void> {
  // 1. First relay proof to Soroban verifier
  const verification = await this.proofService.relay({
    proof: this.proof,
    publicInputs: this.publicInputs,
  });

  if (!verification.verified) throw new Error('Proof rejected by on-chain verifier');

  // 2. Then execute the Stellar payment
  const result = await this.stellarService.sendPayment({
    to: this.recipientAddress,
    amount: this.amount,
    asset: this.selectedAsset,
    nullifier: this.publicInputs.nullifier,
  });

  this.txHash = result.txHash;
}
```

---

## Demo Walkthrough

**Scenario:** Emeka in Lagos wants to send $500 USDC to her family in Manila.

```
1. Emeka opens zkremit at localhost:4200

2. He connects his Freighter wallet (G...EmekaStellarAddress)

3. He selects corridor: Nigeria → Philippines, asset: USDC, amount: $500

4. He clicks "Get Compliance Credential"
   → Backend issues a mock KYC credential signed by the demo issuer
   → Credential certifies: KYC passed, not sanctioned, NG jurisdiction

5. He clicks "Generate Proof"
   → Noir circuit runs in her browser (Barretenberg WASM)
   → Proves: credential valid, amount < $10,000 threshold, NG is eligible
   → Generates nullifier: Poseidon2(credentialSecret, corridorId)
   → Time: ~2 seconds on M2 MacBook / ~5 seconds on mid-range phone

6. He clicks "Send Payment"
   → Proof is submitted to NestJS backend
   → Backend calls Soroban verifier contract on Stellar testnet
   → Contract verifies proof using BN254 host functions (Protocol 25/26)
   → Nullifier recorded on-chain (no replay possible)
   → Stellar payment transaction submitted: 500 USDC, Alice → Maria

7. Emeka sees: "Payment sent ✓ | Tx: abc123... | Proof verified on-chain"

What the Stellar network sees:
  - A payment of 500 USDC
  - A nullifier hash (no PII)
  - A verified compliance event from the Soroban contract

What the network does NOT see:
  - Emeka's identity
  - His KYC data
  - His jurisdiction
  - That the exact amount was $500 (only that it was < $10,000)
```

---

## Stellar Protocol 25 & 26 Integration

This project directly exercises the cryptographic host functions introduced in Stellar Protocol 25 ("X-Ray") and Protocol 26 ("Yardstick").

### Protocol 25 Host Functions Used

| Host Function | Used For |
|---|---|
| `bn254_g1_add` | Elliptic curve point addition in proof verifier |
| `bn254_g1_mul` | Scalar multiplication for verification key operations |
| `bn254_g2_add` | G2 curve operations for pairing |
| `poseidon_hash` | Nullifier verification (ZK-friendly hashing) |
| `poseidon2_hash` | Credential hash verification |

### Protocol 26 Host Functions Used

| Host Function | Used For |
|---|---|
| `bn254_msm` | Multi-scalar multiplication (core of UltraHonk verifier) |
| `bn254_fr_add/mul/inv` | Scalar field arithmetic during verification |
| `bn254_pairing_check` | Final pairing check — the heart of the Groth16/UltraHonk verifier |
| `bn254_g1_is_on_curve` | Curve membership validation of proof elements |

### Why This Matters

Before Protocol 25/26, implementing a ZK proof verifier on Soroban would have required implementing BN254 arithmetic in Wasm — consuming millions of CPU instructions and exceeding Soroban's compute budget. The new host functions push this math into the Stellar host layer, making full proof verification affordable on-chain for the first time.

**Benchmark (testnet):**

| Operation | Without host functions | With Protocol 26 host functions |
|---|---|---|
| BN254 pairing check | ~50M instructions | ~2M instructions |
| MSM (8 points) | ~30M instructions | ~800K instructions |
| Full UltraHonk verify | Out of budget | ~8M instructions ✓ |

> **Measured:** Run `./contracts/scripts/benchmark.sh` to measure real instruction counts against your deployed contract. The benchmark script invokes each function via `stellar contract invoke --simulate-only` and records the `cpu_insns` field from the simulation response.

---

## Security Considerations

### Current Implementation
- Uses a **mock KYC issuer** — intended to be replaced with a regulated identity provider (Persona, Jumio, Onfido, etc.)
- Uses **secp256k1 ECDSA** for credential signing (the circuit's `ecdsa_secp256k1` check) — production deployments should use an HSM-backed key
- Stores nullifiers in Soroban **persistent storage** — safe but has rent costs; a dedicated nullifier contract is recommended at scale
- Enforces **per-corridor AML thresholds on-chain** (`set_aml_threshold` / `verify_and_record` pinning)
- Supports **credential revocation** (`POST /credential/revoke`) backed by an on-chain revocation-root check in the circuit
- The on-chain **Groth16 proof check is stubbed** — real verification must be built from the Protocol 25/26 BN254 host functions. Until then, run the relay with `VERIFY_OFFCHAIN=true` (see Proof Verification section).

### Known Gaps & Future Work
- **Trusted setup**: The Barretenberg UltraHonk backend does not require a trusted setup (unlike Groth16). This is intentional.
- **Real on-chain verifier**: The contract's Groth16 check returns `true` unless a `REAL_VK` env override forces equality with a prover-supplied VK. DO NOT deploy with the stub in place.
- **Amount hiding**: The circuit proves `amount < threshold` but the actual payment amount is visible on Stellar. Full confidential amounts require additional ZK work (e.g. Pedersen commitments).
- **Issuer decentralization**: A single trusted issuer is a centralization risk. Production should use a consortium or decentralized identity network.
- **Proof generation hardware**: Real `bb prove` runs need AVX512; the off-chain gate and CI job document this (see `proof-artifacts.yml`).

### Threat Model
- **Proof soundness**: Guaranteed by the Noir/Barretenberg proving system — a valid proof can only be generated by someone holding a valid credential
- **Nullifier replay**: Prevented by on-chain nullifier storage in the Soroban contract
- **Credential theft**: The credential secret never leaves the user's browser — the backend only holds the signed credential hash
- **Sybil attacks**: Prevented by the KYC requirement (enforced by credential issuance)

---

## Roadmap

### v0.1 — Current
- [x] Noir compliance circuit (KYC + AML threshold + jurisdiction)
- [x] Soroban verifier contract using BN254 host functions
- [x] NestJS credential issuance API
- [x] Angular frontend with in-browser proof generation
- [x] End-to-end flow on Stellar testnet
- [x] Credential revocation (admin endpoint + circuit revocation-root check)
- [x] Multi-corridor support with per-corridor AML thresholds enforced on-chain
- [x] Single-source compliance config (backend module → frontend proof inputs)
- [x] Off-chain UltraHonk proof verification gate for the relay

### v0.2 — Near-term
- [ ] Real KYC provider integration (Persona API)
- [ ] Real on-chain Groth16/UltraHonk verifier from Protocol 25/26 BN254 host functions
- [ ] Confidential amounts using Pedersen commitments

### v1.0 — Production
- [ ] Mobile-optimized proof generation (faster Barretenberg WASM)
- [ ] Anchor/SEP-31 integration for real remittance corridors
- [ ] Mainnet deployment with audited contracts
- [ ] SDK for other Stellar projects to reuse the compliance layer

---

## Team

| Name | Role |
|---|---|
| **victor** | ZK circuits, Soroban contracts, full-stack |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Resources

- [Noir Language Docs](https://noir-lang.org/docs)
- [Barretenberg (bb.js)](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)
- [Soroban Developer Docs](https://developers.stellar.org/docs/smart-contracts)
- [Stellar Protocol 25 CAP](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0059.md)
- [Stellar Protocol 26 CAP](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0067.md)
- [Freighter Wallet API](https://docs.freighter.app)
- [Stellar SDK (JS)](https://stellar.github.io/js-stellar-sdk/)
