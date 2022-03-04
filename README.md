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
// seed: Vec<u32>
// let keys = KeyPair::new(Some(seed));
let keys = KeyPair::new(None);

println!("{}", keys);
```


## Fast Signature
- 64 byte signature
- quick to sign and verify
- don't possible to decode signature back to message
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let signature = KeyPair::fast_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);

assert_eq!(KeyPair::verify(keys.pubk, msg, signature), true);
println!("ok");
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let signature = KeyPair::full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);

assert_eq!(KeyPair::verify(keys.pubk, msg, signature), true);
println!("ok");
```

## Decode Message
- possible only for full_signature function
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let mut sign_msg = KeyPair::full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
let decoded_msg = KeyPair::decode_message(keys.pubk, &mut sign_msg);

assert_eq!(msg, decoded_msg);
println!("ok");
```


# Credits
- Ported to Rust by Miguel Sandro Lucero, miguel.sandro@gmail.com, 2021.09.11.

- You can use it under MIT or CC0 license.

- Curve25519 signatures idea and math by Trevor Perrin, see [here](https://moderncrypto.org/mail-archive/curves/2014/000205.html)

- Derived from axlsign.js written by Dmitry Chestnykh, see [here](https://github.com/wavesplatform/curve25519-js)
