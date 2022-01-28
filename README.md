# Curve25519 signatures like in the early Axolotl


## Import
```rs
use ed25519_axolotl::{
    random_bytes,
    str_to_vec32,
    vec32_to_str,
    KeyPair
};
```


## Generate New Key Pair
```rs
let keys = KeyPair::new();

println!("private key: {:?}", keys.prvk);
println!("public key: {:?}", keys.pubk);
```


## Sign Message
```rs
let random = random_bytes(64);
let msg = str_to_vec32("Hello Axolotl".to_string());
let sign = KeyPair::sign(&keys.prvk, &msg, &random);

let validate = KeyPair::verify(&keys.pubk, &msg, &sign);
println!("verify signature: {:?}", validate);
```

## Agreement Message
```rs
let mut sign_msg = KeyPair::sign_message(&keys.prvk, &msg, &random);
let unpacked_msg = KeyPair::open_message(&keys.pubk, &mut sign_msg);

println!("message: {:?}", vec32_to_str(&unpacked_msg));
```


# Credits
- Ported to Rust by Miguel Sandro Lucero, miguel.sandro@gmail.com, 2021.09.11.

- You can use it under MIT or CC0 license.

- Curve25519 signatures idea and math by Trevor Perrin, see [here](https://moderncrypto.org/mail-archive/curves/2014/000205.html)

- Derived from axlsign.js written by Dmitry Chestnykh, see [here](https://github.com/wavesplatform/curve25519-js)
