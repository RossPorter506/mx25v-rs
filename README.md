# mx25v-rs
Platform-agnostic Rust driver for the macronix MX25V NOR flash using the [embedded-hal](https://github.com/rust-embedded/embedded-hal).

This driver implements most commands available to the MX25V chip series, but currently only single I/O mode is implemented.
These drivers are low-level, to allow the user to write custom implementations as required.

Based on previous work from [mx25r-rs](https://github.com/xgroleau/mx25r-rs).

I have tested basic blocking functionality on the MX25V16066, but it's possible there are bugs. Any bug reports or contributions are welcome.

## Usage
You can see an example of the usage for the `nRF52840-DK` in the [nrf52840 directory](./nrf52840).

### Nix
A [nix flake](https://nixos.wiki/wiki/Flakes) is available to ease development and dependencies for the examples.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
