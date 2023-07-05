# Wamu

A collection of modular Rust libraries for implementing the [Wamu protocol](https://wamu.tech/specification) for building [threshold signature](https://academy.binance.com/en/articles/threshold-signatures-explained) wallets controlled by multiple [decentralized identities](https://ethereum.org/en/decentralized-identity/).

**NOTE:** 🚧 This project is still work in progress, check back over the next few weeks for regular updates.

## Installation and Usage

Check the readme of each crate for installation and usage instructions and links to documentation.

- Wamu Core (wamu-core): [/crates/core](/crates/core)

## Documentation

- Wamu Core ([wamu-core](/crates/core)): [https://docs.rs/wamu-core/latest/wamu_core/](https://docs.rs/wamu-core/latest/wamu_core/)

Or you can access documentation locally by running the following command from the project root

```shell
cargo doc --open
```

To open crate specific docs, see instructions in the readme in each crate's directory.

## Testing

You can run unit tests for all the core functionality by running the following command from the project root

```shell
cargo test
```

**NOTE:** To run only tests for a single crate, add a `-p <crate_name>` argument to the above command e.g.
```shell
cargo test -p wamu-core
```

## License

| Crate                                 | License                                                                                                                    |
|---------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| Wamu Core ([wamu-core](/crates/core)) | Licensed under either [MIT](/crates/core/LICENSE-MIT) or [Apache-2.0](/crates/core/LICENSE-APACHE) license at your option. |

## Contribution

| Crate                                 | Guidelines                                                                                                                                                                                                                           |
|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Wamu Core ([wamu-core](/crates/core)) | Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. |

## Acknowledgements

🌱 Funded by: the [Ethereum Foundation](https://esp.ethereum.foundation/).