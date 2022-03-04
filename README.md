# Curve25519 signatures like in the early Axolotl


# Rust
## Import
```rs
use ed25519_axolotl::{
    fast_signature,
    full_signature,
    decode_message,
    random_bytes,
    str_to_vec32,
    vec32_to_str,
    KeyPair
    verify,
};
```


## Generate New `KeyPair`
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
let signature = fast_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);

assert_eq!(verify(keys.pubk, msg, signature), true);
println!("ok");
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let signature = full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);

assert_eq!(verify(keys.pubk, msg, signature), true);
println!("ok");
```

## Decode Message
- possible only for full_signature function
```rs
let keys = KeyPair::new(None);

let msg = str_to_vec32("hello e25519 axolotl".to_string());
let mut sign_msg = full_signature(
    keys.prvk,
    msg.clone(),
    Some(random_bytes(64))
);
let decoded_msg = decode_message(keys.pubk, &mut sign_msg);

assert_eq!(msg, decoded_msg);
println!("ok");
```

# NodeJs (WebAssembly)
## Import
```js
import * as wasm from "ed25519_axolotl";
```
or 
```js
const wasm = require("ed25519_axolotl")
```


## Generate New `KeyPair`
```js
const keys = new wasm.KeyPair()

console.log(keys.privateKey) // Uint32Array
console.log(keys.publiKey) // Uint32Array
```


## Fast Signature
- 64 byte signature
- quick to sign and verify
- don't possible to decode signature back to message
```js
const keys = new wasm.KeyPair()

console.log(keys.privateKey) // Uint32Array
console.log(keys.publiKey) // Uint32Array

const msg = wasm.stringToUint32Array("hello lunes")
console.log(msg) // Uint32Array

const signature = wasm.fastSignature(k.privateKey, msg, wasm.randomBytes(64))
console.log(signature) // Uint32Array
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```js
const keys = new wasm.KeyPair()

console.log(keys.privateKey) // Uint32Array
console.log(keys.publiKey) // Uint32Array

const msg = wasm.stringToUint32Array("hello lunes")
console.log(msg) // Uint32Array

const signature = wasm.fullSignature(k.privateKey, msg, wasm.randomBytes(64))
console.log(signature) // Uint32Array
```

## Decode Message
- possible only for full_signature function
```js
const keys = new wasm.KeyPair()

console.log(keys.privateKey) // Uint32Array
console.log(keys.publiKey) // Uint32Array

const msg = wasm.stringToUint32Array("hello lunes")
console.log(msg) // Uint32Array

const signature = wasm.fullSignature(k.privateKey, msg, wasm.randomBytes(64))
console.log(signature) // Uint32Array

const dmsg = wasm.uint32ArrayToString(
    wasm.decode_message(k.publiKey, fl)
)
console.log(dmsg) // String
```

# Python (C/C++)
## Import
```js
```


## Generate New `KeyPair`
```js
```


## Fast Signature
- 64 byte signature
- quick to sign and verify
- don't possible to decode signature back to message
```js
```

## Full Signature
- (64 + message length) byte signature
- slow to sign and verify
- it is possible to decode the signature back to the message
```js
```

## Decode Message
- possible only for full_signature function
```js
```


# Credits
- Ported to Rust by Miguel Sandro Lucero, miguel.sandro@gmail.com, 2021.09.11.

- You can use it under MIT or CC0 license.

- Curve25519 signatures idea and math by Trevor Perrin, see [here](https://moderncrypto.org/mail-archive/curves/2014/000205.html)

- Derived from axlsign.js written by Dmitry Chestnykh, see [here](https://github.com/wavesplatform/curve25519-js)
