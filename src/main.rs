fn main() {
    use ed25519_axolotl::{
        open_message, random_bytes, sign, sign_message, str_to_vec32, vec32_to_str, verify, Keys,
    };

    // ------------------------------------------------------------
    // random seed
    let seed = random_bytes(32);

    println!("seed = {:?}", seed);

    // generate key pair
    let keys = Keys::generate_key_pair(&seed);

    println!("public_key = {:?}", keys.public_key);
    println!("private_key = {:?}", keys.private_key);
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    let rnd = random_bytes(64);

    println!("rnd = {:?}", rnd);

    let msg = str_to_vec32("Hello Axolotl".to_string());

    println!("msg = {:?}", msg);

    let sig = sign(&keys.private_key, &msg, &rnd);

    println!("sig = {:?}", sig);

    let res = verify(&keys.public_key, &msg, &sig);
    let res1 = verify(&keys.private_key, &msg, &sig);
    // ------------------------------------------------------------

    // ------------------------------------------------------------
    println!("res = {:?}", res);
    println!("res1 = {:?}", res1);

    let mut sigmsg = sign_message(&keys.private_key, &msg, &rnd);
    let msg2 = open_message(&keys.public_key, &mut sigmsg);

    println!("sigmsg = {:?}", sigmsg);
    println!("msg2 = {:?}", msg2);
    println!("msg_8 = {:?}", vec32_to_str(&msg2));
    // ------------------------------------------------------------
}
