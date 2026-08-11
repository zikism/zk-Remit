#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env, IntoVal, Val,
};

/// Soroban charges rent on ledger entries: a persistent entry whose TTL runs
/// out is garbage-collected, and an expired contract instance is deactivated.
/// The nullifier and compliance-record keys are the security boundary of this
/// contract - their expiry would silently re-enable replay of a spent proof -
/// so every write and the hot read paths extend the TTL to keep entries alive
/// for the full window below. `extend_ttl` is only a no-op when the entry's
/// TTL is already above `TTL_THRESHOLD`, so re-extending on each read is cheap.
const TTL_THRESHOLD: u32 = 1_000_000;
const TTL_EXTEND_TO: u32 = 5_000_000;

fn extend_to(env: &Env) -> u32 {
    // `extend_ttl` errors if `threshold > extend_to` and overflows on
    // `ledger_seq + extend_to`; clamp against the network cap so a valid call
    // can never panic, even on a short-lived network.
    let max_live = env.ledger().max_live_until_ledger();
    let current = env.ledger().sequence();
    core::cmp::min(TTL_EXTEND_TO, max_live.saturating_sub(current))
}

fn extend_persistent_ttl(env: &Env, key: &impl IntoVal<Env, Val>) {
    let extend_to = extend_to(env);
    if extend_to > TTL_THRESHOLD {
        env.storage().persistent().extend_ttl(key, TTL_THRESHOLD, extend_to);
    }
}

fn extend_instance_ttl(env: &Env) {
    let extend_to = extend_to(env);
    if extend_to > TTL_THRESHOLD {
        env.storage().instance().extend_ttl(TTL_THRESHOLD, extend_to);
    }
}

#[contracttype]
pub struct ComplianceRecord {
    pub nullifier: BytesN<32>,
    pub issuer_pubkey_hash: BytesN<32>,
    pub payment_asset: BytesN<32>,
    pub corridor_id: BytesN<32>,
    pub aml_threshold: u64,
    pub amount_commitment: BytesN<32>,
    pub revocation_root: BytesN<32>,
    pub approved_corridors_root: BytesN<32>,
    pub allowed_jurisdictions_root: BytesN<32>,
    pub verified_at: u64,
}

#[contract]
pub struct ComplianceVerifier;

fn decode_bytes_n<const N: usize>(env: &Env, bytes: &Bytes, start: u32) -> BytesN<N> {
    let mut arr = [0u8; N];
    for i in 0..N {
        arr[i] = bytes.get(start + i as u32).unwrap();
    }
    BytesN::from_array(env, &arr)
}

fn decode_u64(bytes: &Bytes, start: u32) -> u64 {
    let mut arr = [0u8; 8];
    for i in 0..8 {
        arr[i] = bytes.get(start + i as u32).unwrap();
    }
    u64::from_be_bytes(arr)
}

#[contractimpl]
impl ComplianceVerifier {
    pub fn initialize(
        env: Env,
        vk: Bytes,
        admin: Address,
        allowed_jurisdictions_root: BytesN<32>,
        approved_corridors_root: BytesN<32>,
        revocation_root: BytesN<32>,
    ) {
        assert!(
            !env.storage().instance().has(&symbol_short!("init")),
            "Already initialized"
        );

        env.storage().instance().set(&symbol_short!("init"), &true);
        env.storage().instance().set(&symbol_short!("vk"), &vk);
        env.storage().instance().set(&symbol_short!("admin"), &admin);
        env.storage()
            .instance()
            .set(&symbol_short!("jur_root"), &allowed_jurisdictions_root);
        env.storage()
            .instance()
            .set(&symbol_short!("cor_root"), &approved_corridors_root);
        env.storage()
            .instance()
            .set(&symbol_short!("rev_root"), &revocation_root);
        extend_instance_ttl(&env);
    }

    pub fn verify_and_record(env: Env, proof: Bytes, public_inputs: Bytes) -> bool {
        // Offsets MUST match the circuit's public parameter order in main.nr:
        // nullifier, issuer_pubkey_hash, payment_asset, aml_threshold,
        // corridor_id, allowed_jurisdictions_root, amount_commitment,
        // revocation_root, approved_corridors_root. A real verifier binds the
        // proof's public inputs in this order, so any other offset here would
        // decode every field past corridor_id as the wrong value.
        let nullifier: BytesN<32> = decode_bytes_n(&env, &public_inputs, 0);
        let issuer_pubkey_hash: BytesN<32> = decode_bytes_n(&env, &public_inputs, 32);
        let payment_asset: BytesN<32> = decode_bytes_n(&env, &public_inputs, 64);
        let aml_threshold: u64 = decode_u64(&public_inputs, 96);
        let corridor_id: BytesN<32> = decode_bytes_n(&env, &public_inputs, 104);
        let allowed_jurisdictions_root: BytesN<32> = decode_bytes_n(&env, &public_inputs, 136);
        let amount_commitment: BytesN<32> = decode_bytes_n(&env, &public_inputs, 168);
        let revocation_root: BytesN<32> = decode_bytes_n(&env, &public_inputs, 200);
        let approved_corridors_root: BytesN<32> = decode_bytes_n(&env, &public_inputs, 232);

        let stored_revoc_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&symbol_short!("rev_root"))
            .unwrap();
        let stored_corr_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&symbol_short!("cor_root"))
            .unwrap();
        let stored_juris_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&symbol_short!("jur_root"))
            .unwrap();

        if revocation_root != stored_revoc_root {
            return false;
        }
        if approved_corridors_root != stored_corr_root {
            return false;
        }
        if allowed_jurisdictions_root != stored_juris_root {
            return false;
        }

        // The circuit only proves `amount < aml_threshold`; `aml_threshold` is
        // a public input the prover controls, so a proof can claim any limit
        // it likes. Pin it to the configured threshold for the proven corridor
        // so the effective per-corridor AML limit is enforced on-chain. An
        // unconfigured corridor defaults to 0, which no amount can satisfy
        // in-circuit, so its proofs are rejected here regardless.
        let configured_threshold: u64 = {
            let key = Self::corridor_threshold_key(&env, &corridor_id);
            if env.storage().persistent().has(&key) {
                extend_persistent_ttl(&env, &key);
            }
            env.storage().persistent().get(&key).unwrap_or(0)
        };
        if aml_threshold != configured_threshold {
            return false;
        }

        if env.storage().persistent().has(&nullifier) {
            return false;
        }

        let vk: Bytes = env
            .storage()
            .instance()
            .get(&symbol_short!("vk"))
            .unwrap();

        // TODO(contract): the Groth16 check is intentionally stubbed to true so
        // the crate compiles and the surrounding flow (nullifier replay
        // protection, root staleness) is testable. Soroban has no
        // `verify_groth16_bn254` host function; real verification must be built
        // from the Stellar Protocol 25 BN254 host functions
        // (g1_add/g1_mul/pairing_check, see stellar/soroban-examples
        // groth16_verifier). DO NOT deploy with this stub in place.
        let _ = &vk;
        let _ = &proof;
        let is_valid = true;
        if !is_valid {
            return false;
        }

        env.storage().persistent().set(&nullifier, &true);
        extend_persistent_ttl(&env, &nullifier);

        let record = ComplianceRecord {
            nullifier: nullifier.clone(),
            issuer_pubkey_hash,
            payment_asset,
            corridor_id: corridor_id.clone(),
            aml_threshold,
            amount_commitment: amount_commitment.clone(),
            revocation_root,
            approved_corridors_root,
            allowed_jurisdictions_root,
            verified_at: env.ledger().timestamp(),
        };

        let mut record_key = [0u8; 33];
        record_key[0] = 0x01;
        record_key[1..33].copy_from_slice(&nullifier.to_array());
        let record_key_n = BytesN::<33>::from_array(&env, &record_key);
        env.storage().persistent().set(&record_key_n, &record);
        extend_persistent_ttl(&env, &record_key_n);

        env.events().publish(
            (symbol_short!("compliant"),),
            (nullifier, corridor_id, amount_commitment.clone()),
        );

        true
    }

    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        let used = env.storage().persistent().has(&nullifier);
        if used {
            extend_persistent_ttl(&env, &nullifier);
        }
        used
    }

    fn corridor_threshold_key(env: &Env, corridor_id: &BytesN<32>) -> BytesN<33> {
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[1..33].copy_from_slice(&corridor_id.to_array());
        BytesN::<33>::from_array(env, &key)
    }

    /// Admin-only: set the maximum amount (exclusive) allowed per corridor.
    /// `verify_and_record` rejects any proof whose `aml_threshold` public input
    /// does not equal this value, so the per-corridor AML limit is enforceable
    /// on-chain even though the Groth16 check is stubbed.
    pub fn set_aml_threshold(
        env: Env,
        caller: Address,
        corridor_id: BytesN<32>,
        threshold: u64,
    ) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .unwrap();
        if caller != admin {
            panic!("Caller is not admin");
        }
        let key = Self::corridor_threshold_key(&env, &corridor_id);
        env.storage().persistent().set(&key, &threshold);
        extend_persistent_ttl(&env, &key);
        env.events()
            .publish((symbol_short!("aml_thrsh"),), (corridor_id, threshold));
    }

    pub fn get_aml_threshold(env: Env, corridor_id: BytesN<32>) -> u64 {
        let key = Self::corridor_threshold_key(&env, &corridor_id);
        if env.storage().persistent().has(&key) {
            extend_persistent_ttl(&env, &key);
        }
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    pub fn get_compliance_record(
        env: Env,
        nullifier: BytesN<32>,
    ) -> Option<ComplianceRecord> {
        let mut record_key = [0u8; 33];
        record_key[0] = 0x01;
        record_key[1..33].copy_from_slice(&nullifier.to_array());
        let record_key_n = BytesN::<33>::from_array(&env, &record_key);
        if env.storage().persistent().has(&record_key_n) {
            extend_persistent_ttl(&env, &record_key_n);
        }
        env.storage().persistent().get(&record_key_n)
    }

    pub fn get_verifier_key(env: Env) -> Bytes {
        env.storage()
            .instance()
            .get(&symbol_short!("vk"))
            .unwrap()
    }

    pub fn update_roots(
        env: Env,
        caller: Address,
        new_revocation_root: BytesN<32>,
        new_approved_corridors_root: BytesN<32>,
        new_allowed_jurisdictions_root: BytesN<32>,
    ) {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .unwrap();
        if caller != admin {
            panic!("Caller is not admin");
        }
        env.storage()
            .instance()
            .set(&symbol_short!("rev_root"), &new_revocation_root);
        env.storage()
            .instance()
            .set(&symbol_short!("cor_root"), &new_approved_corridors_root);
        env.storage()
            .instance()
            .set(&symbol_short!("jur_root"), &new_allowed_jurisdictions_root);
        extend_instance_ttl(&env);

        env.events().publish((symbol_short!("roots_upd"),), ());
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env};

    fn setup_test_env_full() -> (Env, ComplianceVerifierClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ComplianceVerifier);
        let client = ComplianceVerifierClient::<'static>::new(&env, &contract_id);
        let admin = Address::generate(&env);

        let vk = Bytes::from_array(&env, &[1u8; 64]);
        let root = BytesN::<32>::from_array(&env, &[0u8; 32]);

        client.initialize(&vk, &admin, &root, &root, &root);

        (env, client, admin, contract_id)
    }

    fn setup_test_env() -> (Env, ComplianceVerifierClient<'static>, Address) {
        let (env, client, admin, _) = setup_test_env_full();
        (env, client, admin)
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ComplianceVerifier);
        let client = ComplianceVerifierClient::<'static>::new(&env, &contract_id);
        let admin = Address::generate(&env);

        let vk = Bytes::from_array(&env, &[2u8; 64]);
        let root_a = BytesN::<32>::from_array(&env, &[1u8; 32]);
        let root_b = BytesN::<32>::from_array(&env, &[2u8; 32]);
        let root_c = BytesN::<32>::from_array(&env, &[3u8; 32]);

        client.initialize(&vk, &admin, &root_a, &root_b, &root_c);

        let stored_vk = client.get_verifier_key();
        assert_eq!(stored_vk, vk);

        let used = client.is_nullifier_used(&root_a);
        assert!(!used);
    }

    #[test]
    fn test_verify_valid_proof() {
        let (_env, client, _admin) = setup_test_env();

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let pi = Bytes::from_array(&_env, &[0u8; 264]);

        let result = client.verify_and_record(&proof, &pi);
        assert!(result);
    }

    #[test]
    fn test_duplicate_nullifier() {
        let (_env, client, _admin) = setup_test_env();

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let pi = Bytes::from_array(&_env, &[0u8; 264]);

        let first = client.verify_and_record(&proof, &pi);
        assert!(first);

        let second = client.verify_and_record(&proof, &pi);
        assert!(!second);
    }

    #[test]
    fn test_stale_revocation_root() {
        let (_env, client, _admin) = setup_test_env();

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let mut pi_bytes = [0u8; 264];
        // Set a different revocation root at offset 200 (circuit order)
        pi_bytes[200] = 0xFF;
        let pi = Bytes::from_array(&_env, &pi_bytes);

        let result = client.verify_and_record(&proof, &pi);
        assert!(!result);
    }

    #[test]
    fn test_update_roots() {
        let (_env, client, admin) = setup_test_env();

        let new_revoc = BytesN::<32>::from_array(&_env, &[0xAAu8; 32]);
        let new_corr = BytesN::<32>::from_array(&_env, &[0xBBu8; 32]);
        let new_juris = BytesN::<32>::from_array(&_env, &[0xCCu8; 32]);

        client.update_roots(&admin, &new_revoc, &new_corr, &new_juris);

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let mut pi_bytes = [0u8; 264];
        // Circuit-order offsets: allowed_jurisdictions_root @136,
        // revocation_root @200, approved_corridors_root @232.
        pi_bytes[136..168].copy_from_slice(&[0xCCu8; 32]);
        pi_bytes[200..232].copy_from_slice(&[0xAAu8; 32]);
        pi_bytes[232..264].copy_from_slice(&[0xBBu8; 32]);
        let pi = Bytes::from_array(&_env, &pi_bytes);

        let result = client.verify_and_record(&proof, &pi);
        assert!(result);
    }

    #[test]
    fn test_public_input_decode_matches_circuit_order() {
        let (_env, client, admin) = setup_test_env();

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let mut pi_bytes = [0u8; 264];
        // Fill each 32-byte field with a distinct pattern so a decode error
        // (wrong offset) is detectable; aml_threshold is the 8-byte exception.
        pi_bytes[0..32].copy_from_slice(&[0x11u8; 32]);
        pi_bytes[32..64].copy_from_slice(&[0x22u8; 32]);
        pi_bytes[64..96].copy_from_slice(&[0x33u8; 32]);
        pi_bytes[96..104].copy_from_slice(&10_000u64.to_be_bytes());
        pi_bytes[104..136].copy_from_slice(&[0x55u8; 32]);
        pi_bytes[136..168].copy_from_slice(&[0x66u8; 32]);
        pi_bytes[168..200].copy_from_slice(&[0x77u8; 32]);
        pi_bytes[200..232].copy_from_slice(&[0x88u8; 32]);
        pi_bytes[232..264].copy_from_slice(&[0x99u8; 32]);

        // corridor 0x55..55 is unconfigured, so its effective threshold is 0
        // and this proof would be rejected by the AML pin. The record is never
        // stored, so assert on the decode by verifying the pin is reached with
        // the correct value: set the corridor threshold and then assert the
        // recorded values round-trip field-for-field.
        let corridor_id = BytesN::<32>::from_array(&_env, &[0x55u8; 32]);
        client.set_aml_threshold(&admin, &corridor_id, &10_000);

        // Rotate the stored roots to match the non-zero patterns used below so
        // the record round-trips field-for-field without tripping the
        // staleness checks.
        client.update_roots(
            &admin,
            &BytesN::<32>::from_array(&_env, &[0x88u8; 32]),
            &BytesN::<32>::from_array(&_env, &[0x99u8; 32]),
            &BytesN::<32>::from_array(&_env, &[0x66u8; 32]),
        );

        let pi = Bytes::from_array(&_env, &pi_bytes);
        assert!(client.verify_and_record(&proof, &pi));

        let rec = client
            .get_compliance_record(&BytesN::<32>::from_array(&_env, &[0x11u8; 32]))
            .expect("record stored");
        assert_eq!(rec.nullifier, BytesN::<32>::from_array(&_env, &[0x11u8; 32]));
        assert_eq!(
            rec.issuer_pubkey_hash,
            BytesN::<32>::from_array(&_env, &[0x22u8; 32])
        );
        assert_eq!(
            rec.payment_asset,
            BytesN::<32>::from_array(&_env, &[0x33u8; 32])
        );
        assert_eq!(rec.aml_threshold, 10_000);
        assert_eq!(
            rec.corridor_id,
            BytesN::<32>::from_array(&_env, &[0x55u8; 32])
        );
        assert_eq!(
            rec.allowed_jurisdictions_root,
            BytesN::<32>::from_array(&_env, &[0x66u8; 32])
        );
        assert_eq!(
            rec.amount_commitment,
            BytesN::<32>::from_array(&_env, &[0x77u8; 32])
        );
        assert_eq!(
            rec.revocation_root,
            BytesN::<32>::from_array(&_env, &[0x88u8; 32])
        );
        assert_eq!(
            rec.approved_corridors_root,
            BytesN::<32>::from_array(&_env, &[0x99u8; 32])
        );
    }

    #[test]
    fn test_get_compliance_record() {
        let (_env, client, _admin) = setup_test_env();

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let pi = Bytes::from_array(&_env, &[0u8; 264]);

        client.verify_and_record(&proof, &pi);

        let nullifier = BytesN::<32>::from_array(&_env, &[0u8; 32]);
        let record = client.get_compliance_record(&nullifier);
        assert!(record.is_some());

        let rec = record.unwrap();
        assert_eq!(rec.aml_threshold, 0);
    }

    fn corridor_bytes_n(env: &Env, value: u8) -> BytesN<32> {
        BytesN::<32>::from_array(env, &[value; 32])
    }

    fn pi_with_threshold(env: &Env, corridor_id: &BytesN<32>, threshold: u64) -> Bytes {
        let mut pi_bytes = [0u8; 264];
        pi_bytes[104..136].copy_from_slice(&corridor_id.to_array());
        pi_bytes[96..104].copy_from_slice(&threshold.to_be_bytes());
        Bytes::from_array(env, &pi_bytes)
    }

    #[test]
    fn test_aml_threshold_is_pinned_to_configured_corridor_threshold() {
        let (_env, client, admin) = setup_test_env();

        let corridor_id = corridor_bytes_n(&_env, 0xAB);
        client.set_aml_threshold(&admin, &corridor_id, &10_000);

        assert_eq!(client.get_aml_threshold(&corridor_id), 10_000);

        // Matching threshold passes (roots are the zero roots from setup).
        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        let pi_ok = pi_with_threshold(&_env, &corridor_id, 10_000);
        assert!(client.verify_and_record(&proof, &pi_ok));

        // Same corridor with a different aml_threshold must be rejected,
        // otherwise a prover could claim any limit (e.g. u64::MAX).
        let pi_wrong = pi_with_threshold(&_env, &corridor_id, 9_999);
        assert!(!client.verify_and_record(&proof, &pi_wrong));
    }

    #[test]
    fn test_unconfigured_corridor_rejected() {
        let (_env, client, _admin) = setup_test_env();

        let proof = Bytes::from_array(&_env, &[0u8; 128]);
        // Corridor not configured, so its effective threshold is 0. A nonzero
        // claim must be rejected (and no amount can satisfy threshold 0).
        let corridor_id = corridor_bytes_n(&_env, 0xCD);
        assert_eq!(client.get_aml_threshold(&corridor_id), 0);
        let pi = pi_with_threshold(&_env, &corridor_id, 10_000);
        assert!(!client.verify_and_record(&proof, &pi));
    }

    #[test]
    fn test_set_aml_threshold_requires_admin() {
        let (env, client, _admin) = setup_test_env();

        let attacker = Address::generate(&env);
        env.mock_all_auths();
        let corridor_id = corridor_bytes_n(&env, 0xAB);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.set_aml_threshold(&attacker, &corridor_id, &100);
        }));
        assert!(result.is_err());
    }

    fn expected_extended_ttl(env: &Env) -> u32 {
        let max_live = env.ledger().max_live_until_ledger();
        let current = env.ledger().sequence();
        // `extend_ttl` sets live_until = ledger_seq + extend_to, and the
        // testutils get_ttl reports the number of ledgers remaining, so the
        // observed TTL equals extend_to (clamped by the network cap).
        core::cmp::min(TTL_EXTEND_TO, max_live.saturating_sub(current))
    }

    #[test]
    fn test_ttl_extended_on_nullifier_and_record() {
        let (env, client, _admin, contract_id) = setup_test_env_full();

        let proof = Bytes::from_array(&env, &[0u8; 128]);
        let pi = Bytes::from_array(&env, &[0u8; 264]);
        assert!(client.verify_and_record(&proof, &pi));

        let nullifier = BytesN::<32>::from_array(&env, &[0u8; 32]);
        let expected = expected_extended_ttl(&env);
        assert!(
            expected > TTL_THRESHOLD,
            "test env must allow a real TTL window, got {expected}"
        );

        // The nullifier replay-protection entry is the security boundary; its
        // TTL must be the extended window, not the default.
        let ttl = env.as_contract(&contract_id, || env.storage().persistent().get_ttl(&nullifier));
        assert_eq!(ttl, expected);

        // The compliance record (0x01-prefixed key) gets the same extension.
        let mut record_key = [0u8; 33];
        record_key[0] = 0x01;
        record_key[1..33].copy_from_slice(&nullifier.to_array());
        let record_key_n = BytesN::<33>::from_array(&env, &record_key);
        let ttl = env.as_contract(&contract_id, || {
            env.storage().persistent().get_ttl(&record_key_n)
        });
        assert_eq!(ttl, expected);
    }

    #[test]
    fn test_ttl_extended_on_threshold_write_and_reads() {
        let (env, client, admin, contract_id) = setup_test_env_full();

        let corridor_id = corridor_bytes_n(&env, 0xAB);
        client.set_aml_threshold(&admin, &corridor_id, &10_000);

        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[1..33].copy_from_slice(&corridor_id.to_array());
        let key = BytesN::<33>::from_array(&env, &key);
        let expected = expected_extended_ttl(&env);
        let ttl = env.as_contract(&contract_id, || env.storage().persistent().get_ttl(&key));
        assert_eq!(ttl, expected);

        // The hot read paths (is_nullifier_used, get_aml_threshold,
        // get_compliance_record) re-extend as long as the entry is live, and
        // must never panic on a never-written key.
        assert!(!client.is_nullifier_used(&corridor_id));
        assert_eq!(client.get_aml_threshold(&corridor_id), 10_000);
        assert!(client.get_compliance_record(&corridor_id).is_none());

        let missing = corridor_bytes_n(&env, 0xCD);
        assert_eq!(client.get_aml_threshold(&missing), 0);
    }

    #[test]
    fn test_instance_ttl_extended_on_initialize_and_update_roots() {
        let (env, client, admin, contract_id) = setup_test_env_full();

        let expected = expected_extended_ttl(&env);
        let ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
        assert_eq!(ttl, expected);

        client.update_roots(
            &admin,
            &BytesN::<32>::from_array(&env, &[0xAAu8; 32]),
            &BytesN::<32>::from_array(&env, &[0xBBu8; 32]),
            &BytesN::<32>::from_array(&env, &[0xCCu8; 32]),
        );
        let ttl = env.as_contract(&contract_id, || env.storage().instance().get_ttl());
        assert_eq!(ttl, expected);
    }
}
