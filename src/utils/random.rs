/**
# Return a vector with *`n`* random numbers

- The function takes three random numbers in the range from 0 to 255

## Example

```rust
use ed25519_axolotl::utils::random::random_bytes;

let x = [1;32];
assert_eq!(x.len(), random_bytes(32).len());

assert_eq!(
    true,
    // 0 <= x <= 255
    random_bytes(10000).iter().all(|x| x.ge(&&0) && x.le(&&255))
);
```
*/
pub fn random_bytes(size: usize) -> Vec<u32> {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    (0..size)
        .map(|_| rng.gen_range(0..255))
        .collect::<Vec<u32>>()
}
