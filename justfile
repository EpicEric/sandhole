default:
  just --list

test $RUST_LOG="sandhole=debug":
  cargo test

clippy:
  cargo clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all

clippy-nightly:
  cargo +nightly clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all

book:
  mdbook serve book --open

cli:
  to-html --no-prompt "cargo run --quiet -- --help" > cli.html

flamegraph-test test:
  cargo flamegraph --dev --test {{test}}

install-dev-deps: install-book-deps install-profiling-deps

install-book-deps:
  cargo install mdbook mdbook-mermaid to-html

install-profiling-deps:
  cargo install flamegraph
