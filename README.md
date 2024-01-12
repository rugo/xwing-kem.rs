# Xwing KEM for Rust

This is a Rust implementation of the hybrid Xwing KEM using Kyber768 (post-quantum) and x25519 (pre-quantum).

The details of Xwing are specified in the:

* [Paper](https://eprint.iacr.org/2024/039)
* [IETF Draft](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)

## Examples
Two examples are included, [alice](examples/alice.rs) uses Xwing directly with buffers, [bob](examples/bob.rs) uses wrapper structs.

To run an example call:

```sh
cargo run --example bob
```