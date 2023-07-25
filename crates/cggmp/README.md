# Wamu CGGMP

A Rust implementation of [CGGMP20](https://eprint.iacr.org/2021/060.pdf) with augmentations as described by the [Wamu protocol](https://wamu.tech/specification) for building [threshold signature](https://academy.binance.com/en/articles/threshold-signatures-explained) wallets controlled by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/).

It uses the [Wamu Core (wamu-core)](https://github.com/wamutech/wamu-rs/tree/master/crates/core) crate for [Wamu](https://wamu.tech/specification)'s core sub-protocols and augmentations, and [Webb tool's cggmp-threshold-ecdsa](https://github.com/webb-tools/cggmp-threshold-ecdsa) crate for the [CGGMP20](https://eprint.iacr.org/2021/060.pdf) implementation that it wraps and augments.

**NOTE:** 🚧 This project is still work in progress, check back over the next few weeks for regular updates.

## Installation

Run the following Cargo command in your project directory

```shell
cargo add wamu-cggmp
```

## Documentation

[https://docs.rs/wamu-cggmp/latest/wamu_cggmp/](https://docs.rs/wamu-cggmp/latest/wamu_cggmp/)

Or you can access documentation locally by running the following command from the project root

```shell
cargo doc -p wamu-cggmp --open
```

## Testing

You can run unit tests for all the core functionality by running the following command from the project root

```shell
cargo test -p wamu-cggmp
```

## License

Licensed under [GPL-3.0](https://github.com/wamutech/wamu-rs/tree/master/LICENSE-GPL).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the GPL-3.0 license, shall be
dual licensed as above, without any additional terms or conditions.
