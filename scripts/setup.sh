#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

section() { echo; echo -e "${YELLOW}==== $1 ====${NC}"; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ──────────────────────────────────────────────
# Section 1 — Prerequisites Check
# ──────────────────────────────────────────────
section "Prerequisites Check"

# Node.js >= 20
if command -v node &>/dev/null; then
  NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
  if [ "$NODE_VERSION" -lt 20 ]; then
    error "Node.js >= 20 required (found $(node --version)). Install from https://nodejs.org"
  fi
  info "Node.js $(node --version) found"
else
  error "Node.js not found. Install from https://nodejs.org"
fi

# Rust + Cargo
if command -v cargo &>/dev/null; then
  info "Rust/Cargo found ($(cargo --version | cut -d' ' -f2))"
else
  error "Rust/Cargo not found. Install from https://rustup.rs"
fi

# wasm32 target
if rustup target list --installed | grep -q wasm32-unknown-unknown; then
  info "wasm32-unknown-unknown target already installed"
else
  info "Adding wasm32-unknown-unknown target..."
  rustup target add wasm32-unknown-unknown
fi

# stellar-cli
if command -v stellar &>/dev/null; then
  info "stellar-cli found ($(stellar --version | head -1))"
else
  warn "stellar-cli not found. Install with: cargo install --locked stellar-cli"
fi

# nargo (Noir)
if command -v nargo &>/dev/null; then
  info "nargo found ($(nargo --version | head -1))"
else
  info "Installing noirup..."
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
  export PATH="$HOME/.nargo/bin:$PATH"
  noirup
  info "nargo installed"
fi

# bb (Barretenberg)
if command -v bb &>/dev/null; then
  info "bb found ($(bb --version 2>/dev/null || echo 'version unknown'))"
else
  info "Installing bbup..."
  curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
  export PATH="$HOME/.bb:$PATH"
  bbup
  info "bb installed"
fi

# ──────────────────────────────────────────────
# Section 2 — Install Node Dependencies
# ──────────────────────────────────────────────
section "Installing Node Dependencies"

info "Installing backend dependencies..."
cd "$ROOT_DIR/backend" && npm install

info "Installing frontend dependencies..."
cd "$ROOT_DIR/frontend" && npm install

cd "$ROOT_DIR"

# ──────────────────────────────────────────────
# Section 3 — Build Rust Contracts
# ──────────────────────────────────────────────
section "Building Rust Contracts"

info "Building Soroban verifier contract..."
cd "$ROOT_DIR/contracts/verifier"
cargo build --target wasm32-unknown-unknown --release 2>&1 | tail -5
cd "$ROOT_DIR"

# ──────────────────────────────────────────────
# Section 4 — Compile Noir Circuit
# ──────────────────────────────────────────────
section "Compiling Noir Circuit"

info "Compiling compliance circuit..."
cd "$ROOT_DIR/circuits"
nargo compile 2>&1 | tail -5
cd "$ROOT_DIR"

# ──────────────────────────────────────────────
# Section 5 — Copy Env Files
# ──────────────────────────────────────────────
section "Environment Files"

copy_env() {
  local src="$1" dst="$2"
  if [ ! -f "$dst" ]; then
    cp "$src" "$dst"
    info "Created $dst from template"
  else
    warn "$dst already exists — skipping"
  fi
}

copy_env "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
copy_env "$ROOT_DIR/backend/.env.example" "$ROOT_DIR/backend/.env"
copy_env "$ROOT_DIR/frontend/src/environments/environment.example.ts" "$ROOT_DIR/frontend/src/environments/environment.ts"

# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────
echo
echo -e "${GREEN}┌─────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}│  zkremit Setup Complete                      │${NC}"
echo -e "${GREEN}│  • Node dependencies installed                │${NC}"
echo -e "${GREEN}│  • Rust contract compiled                     │${NC}"
echo -e "${GREEN}│  • Noir circuit compiled                      │${NC}"
echo -e "${GREEN}│  • Environment files copied                   │${NC}"
echo -e "${GREEN}│  Next: docker compose up -d                    │${NC}"
echo -e "${GREEN}└─────────────────────────────────────────────┘${NC}"
