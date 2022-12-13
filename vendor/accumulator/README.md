# accumulator
Cryptographic accumulators in Rust, implemented over a generic group interface. Batteries (RSA and
class group implementations) included! Forked from original repository. Main changes are optimisations, a different
and more performant hash_to_prime, and using Rayon to parallelise wherever possible.

## Installation
```toml
# Cargo.toml
[dependencies]
accumulator = { git = "https://github.com/cambrian/accumulator.git", tag = "v0.2.1" }
```

## Docs
Available [here](https://cambrian.dev/accumulator/docs), and feel free to reach out with any
questions.

## Demo
We have a [proof-of-concept](https://github.com/cambrian/accumulator-demo) for stateless Bitcoin
nodes.

## Contributing
Please see our
[contribution guide](https://github.com/cambrian/accumulator/blob/master/CONTRIBUTING.md). We are
looking for long-term maintainers!
