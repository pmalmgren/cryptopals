[cryptopals](https://cryptopals.com/) written in Rust.

## Code organization

Everything is a bit of a mess. Some of the challenges (like PKCS #7 padding) are there, but only exist through data structures and unit tests.

In general, you can run a challenge with the command `cargo run -- challenge[xyz]`.
