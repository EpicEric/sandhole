default:
  just --list

test $RUST_LOG="sandhole=debug":
  cargo test

install-dev-deps:
  cargo install mdbook to-html

book:
  mdbook serve book --open

cli:
  to-html --no-prompt "cargo run --quiet -- --help" > cli.html

clippy:
  cargo clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all

clippy-nightly:
  cargo +nightly clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all

