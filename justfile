default:
  just --list

test:
  cargo test

install-dev-deps:
  cargo install mdbook to-html

book:
  mdbook serve book --open

cli:
  to-html --no-prompt "cargo run --quiet -- --help" > cli.html
