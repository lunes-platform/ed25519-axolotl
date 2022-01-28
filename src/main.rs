fn main() {
    use ed25519_axolotl::{random_bytes, str_to_vec32, vec32_to_str, KeyPair};

    // ------------------- Generate New Key Pair ------------------
    let keys = KeyPair::new();

    println!("public key: {:?}", keys.prvk);
    println!("private key: {:?}", keys.pubk);
    // --------------------------- END ----------------------------

    // ---------------------- Sign Message ------------------------
    let random = random_bytes(64);
    let msg = str_to_vec32("Hello Axolotl".to_string());
    let sign = KeyPair::sign(&keys.prvk, &msg, &random);

    let validate = KeyPair::verify(&keys.pubk, &msg, &sign);
    println!("signature: {:?}", sign.len());
    println!("validated? {:?}", validate);
    // --------------------------- END ----------------------------

    // ------------------------------------------------------------
    let mut sign_msg = KeyPair::sign_message(&keys.prvk, &msg, &random);
    let unpacked_msg = KeyPair::open_message(&keys.pubk, &mut sign_msg);

    println!("signature: {:?}", sign_msg.len());
    println!("message vec: {:?}", unpacked_msg);
    println!("message unpacked: {:?}", vec32_to_str(&unpacked_msg));
    // ------------------------------------------------------------
}
