use dep::std::hash::poseidon2::Poseidon2;

fn compute_merkle_root_from_path(leaf: Field, path: [Field; 10], indices: [u1; 10]) -> Field {
    let mut root = leaf;
    for i in 0..10 {
        if indices[i] == 1 {
            root = Poseidon2::hash([path[i], root], 2);
        } else {
            root = Poseidon2::hash([root, path[i]], 2);
        }
    }
    root
}

pub fn assert_not_revoked(
    credential_hash: Field,
    revocation_root: Field,
    candidate_leaf: Field,
    candidate_path: [Field; 10],
    candidate_indices: [u1; 10],
) {
    let computed_root = compute_merkle_root_from_path(candidate_leaf, candidate_path, candidate_indices);
    assert(computed_root == revocation_root, "Invalid revocation Merkle path");
    assert(candidate_leaf != credential_hash, "Credential has been revoked");
}

#[test]
fn test_not_revoked_passes() {
    let credential_hash: Field = 12345;
    let candidate_leaf: Field = 67890;
    let mut path: [Field; 10] = [0; 10];
    let mut indices: [u1; 10] = [0; 10];

    let revocation_root = compute_merkle_root_from_path(candidate_leaf, path, indices);

    assert_not_revoked(credential_hash, revocation_root, candidate_leaf, path, indices);
}

#[test(should_fail)]
fn test_revoked_fails() {
    let credential_hash: Field = 12345;
    let candidate_leaf: Field = 12345;
    let mut path: [Field; 10] = [0; 10];
    let mut indices: [u1; 10] = [0; 10];

    let revocation_root = compute_merkle_root_from_path(candidate_leaf, path, indices);

    assert_not_revoked(credential_hash, revocation_root, candidate_leaf, path, indices);
}
