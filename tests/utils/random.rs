#[test]
fn verify_bytes() {
    use ed25519_axolotl::utils::random::random_bytes;

    let x = [1; 32];
    assert_eq!(x.len(), random_bytes(32).len());
    assert_eq!(
        true,
        random_bytes(10000).iter().all(|x| x.ge(&&0) && x.le(&&255))
    );
}
