# authenticode-rs

This repo contains tools for working with authenticode signatures as
defined in the [PE format]. There are two Rust packages:
* [`authenticode`] - A no-std library for working with authenticode.
* [`authenticode-tool`] - A command-line utility for viewing authenticode data.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.

[PE format]: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
[`authenticode`]: ./authenticode
[`authenticode-tool`]: ./authenticode-tool
