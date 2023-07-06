# Wamu

A Rust implementation of the core [Wamu protocol](https://wamu.tech/specification) for building [threshold signature](https://academy.binance.com/en/articles/threshold-signatures-explained) wallets controlled by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/).

**NOTE:** 🚧 This project is still work in progress, check back over the next few weeks for regular updates.

## Installation

Run the following Cargo command in your project directory

```shell
cargo add wamu-core
```

## Documentation

[https://docs.rs/wamu-core/latest/wamu_core/](https://docs.rs/wamu-core/latest/wamu_core/)

Or you can access documentation locally by running the following command from the project root

```shell
cargo doc -p wamu-core --open
```

## Testing

You can run unit tests for all the core functionality by running the following command from the project root

```shell
cargo test -p wamu-core
```

## License

Licensed under either [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) license at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
