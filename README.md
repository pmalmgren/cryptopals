[cryptopals](https://cryptopals.com/) written in Rust.

## Code organization

Everything is a bit of a mess. Some of the challenges (like PKCS #7 padding) are there, but only exist through data structures and unit tests.

In general, you can run a challenge with the command `cargo run -- challenge[xyz]`.

## Non-cryptopals code

There is also some code in here related to some exercises in [A Graduate Course in Applied Cryptography](http://toc.cryptobook.us/), particularly around breaking one time pad encryption where the same pad is reused.
