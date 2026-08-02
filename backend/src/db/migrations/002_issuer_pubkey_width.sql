-- Issuer public keys are now full secp256k1 points (x || y, 64 bytes), so
-- the '0x' + 128 hex characters no longer fit in VARCHAR(66).
ALTER TABLE credentials ALTER COLUMN issuer_pubkey TYPE VARCHAR(130);
