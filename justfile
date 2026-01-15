default:
    just --list

test $RUST_LOG="sandhole=debug":
    cargo nextest run --no-fail-fast

clippy:
    cargo clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all

clippy-nightly:
    cargo +nightly clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all

book:
    mdbook serve book --open

cli:
    to-html --no-prompt "cargo run --quiet -- --help" > cli.html

nixos-docs:
    nix build .#_docs
    echo "# NixOS module options" > book/src/nixos_options.md
    echo "" >> book/src/nixos_options.md
    cat result >> book/src/nixos_options.md

flamegraph-test test:
    cargo flamegraph --profile bench --test integration -- {{ test }}

minica:
    minica -ca-cert tests/data/ca/rootCA.pem -ca-key tests/data/ca/rootCA-key.pem -domains 'localhost'
    mv localhost/cert.pem tests/data/certificates/localhost/fullchain.pem
    mv localhost/key.pem tests/data/certificates/localhost/privkey.pem
    minica -ca-cert tests/data/ca/rootCA.pem -ca-key tests/data/ca/rootCA-key.pem -domains 'foobar.tld,*.foobar.tld'
    mv foobar.tld/cert.pem tests/data/certificates/foobar.tld/fullchain.pem
    mv foobar.tld/key.pem tests/data/certificates/foobar.tld/privkey.pem
    minica -ca-cert tests/data/ca/rootCA.pem -ca-key tests/data/ca/rootCA-key.pem -domains 'sandhole.com.br'
    mv sandhole.com.br/cert.pem tests/data/custom_certificate/fullchain.pem
    mv sandhole.com.br/key.pem tests/data/custom_certificate/privkey.pem

install-dev-deps: install-book-deps install-profiling-deps install-test-deps

install-book-deps:
    cargo install mdbook mdbook-mermaid to-html

install-profiling-deps:
    cargo install flamegraph

install-test-deps:
    cargo install cargo-nextest
