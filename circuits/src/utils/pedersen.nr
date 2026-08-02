use dep::std::hash::poseidon2::Poseidon2;

pub fn compute_amount_commitment(amount: u64, blinding_factor: Field) -> Field {
    Poseidon2::hash([(amount as Field), blinding_factor], 2)
}

pub fn verify_amount_range(amount: u64, threshold: u64) -> bool {
    amount < threshold
}

#[test]
fn test_commitment_deterministic() {
    let c1 = compute_amount_commitment(500, 12345);
    let c2 = compute_amount_commitment(500, 12345);
    assert(c1 == c2, "Commitment should be deterministic");
}

#[test]
fn test_different_blinding() {
    let c1 = compute_amount_commitment(500, 12345);
    let c2 = compute_amount_commitment(500, 67890);
    assert(c1 != c2, "Different blinding should give different commitments");
}

#[test]
fn test_range_below_threshold() {
    assert(verify_amount_range(500, 10000), "500 < 10000 should be true");
}

#[test]
fn test_range_at_threshold() {
    assert(!verify_amount_range(10000, 10000), "10000 < 10000 should be false");
}

#[test]
fn test_range_above_threshold() {
    assert(!verify_amount_range(20000, 10000), "20000 < 10000 should be false");
}
