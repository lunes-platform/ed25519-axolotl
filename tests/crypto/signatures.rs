#[test]
fn fast_sign() {
    use ed25519_axolotl::crypto::keys::KeyPair;
    use ed25519_axolotl::crypto::signatures::{fast_signature, validate_signature};
    use ed25519_axolotl::utils::random::random_bytes;

    let keys = KeyPair::new(Some(vec![1; 32]));
    let msg = "Lunes"
        .as_bytes()
        .iter()
        .map(|x| *x as u32)
        .collect::<Vec<u32>>();
    let signature = fast_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

    assert_eq!(true, validate_signature(keys.pubk, msg, signature));
}

#[test]
fn full_sign() {
    use ed25519_axolotl::crypto::keys::KeyPair;
    use ed25519_axolotl::crypto::signatures::{full_signature, validate_signature};
    use ed25519_axolotl::utils::random::random_bytes;

    let keys = KeyPair::new(Some(vec![1; 32]));
    let msg = "Lunes"
        .as_bytes()
        .iter()
        .map(|x| *x as u32)
        .collect::<Vec<u32>>();

    let signature = full_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

    assert_eq!(true, validate_signature(keys.pubk, msg, signature));
}

#[test]
fn decoded() {
    use ed25519_axolotl::crypto::keys::KeyPair;
    use ed25519_axolotl::crypto::signatures::{decode_signature, full_signature};
    use ed25519_axolotl::utils::random::random_bytes;

    let keys = KeyPair::new(Some(vec![1; 32]));
    let msg = "Lunes"
        .as_bytes()
        .iter()
        .map(|x| *x as u32)
        .collect::<Vec<u32>>();

    let signature = full_signature(keys.prvk, msg.clone(), Some(random_bytes(64)));

    assert_eq!(msg, decode_signature(keys.pubk, signature))
}
