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
    nix-build ./nix -A packages._cli
    echo "# Command-line interface options" > book/src/cli.md
    echo "" >> book/src/cli.md
    echo "Sandhole exposes several options, which you can see by running \`sandhole --help\`." >> book/src/cli.md
    echo "" >> book/src/cli.md
    echo "---" >> book/src/cli.md
    echo "" >> book/src/cli.md
    cat result >> book/src/cli.md

nixos-docs:
    nix-build ./nix -A packages._docs
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
