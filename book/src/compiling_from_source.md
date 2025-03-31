# Compiling from source

To build the project, [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) and Rust must be installed.

If you're compiling from a separate workstation than the one that will be running Sandhole, then grab the source files, build the binary, and copy it over:

```bash
git clone https://github.com/EpicEric/sandhole
cd sandhole
cargo build --locked --release
scp target/release/sandhole user@sandhole.com.br:/usr/local/bin/sandhole
```

If you're compiling on the machine where you'll run Sandhole, you can install it directly with `cargo install`.

```bash
# Install from latest release
cargo install --locked sandhole
#
# -- OR --
#
# Install the current development version
cargo install --locked --git https://github.com/EpicEric/sandhole
```

Cargo should automatically add the binary to your `PATH`.
