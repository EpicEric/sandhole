# Compiling from source

For this, you'll require [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) and Rust to be installed.

If you're compiling from a separate workstation than the one that will be running Sandhole, then grab the source files, build the binary, and copy it over:

```bash
git clone https://github.com/EpicEric/sandhole
cd sandhole
cargo build --release
scp target/release/sandhole user@sandhole.com.br:/usr/local/bin/sandhole
```

If you're compiling on the machine that'll be running Sandhole, you can install it directly with `cargo install`. This should also add `sandhole` to your `PATH`:

```bash
cargo install --git https://github.com/EpicEric/sandhole
# -- OR --
git clone https://github.com/EpicEric/sandhole
cargo install --path sandhole
# -- OR --
cargo install sandhole  # Installs from latest release sources uploaded to crates.io
```

Once this is all done, you can start running Sandhole! Just make sure that it points to your own domain:

```bash
sandhole --domain sandhole.com.br
```

By default, this will expose ports 80 (for HTTP), 443 (for HTTPS), and 2222 (for SSH). If it all succeeds, you should see the following:

```log
[2024-11-03T13:10:51Z INFO  sandhole] Starting Sandhole...
[2024-11-03T13:10:51Z INFO  sandhole] Key file not found. Creating...
[2024-11-03T13:10:51Z INFO  sandhole] Listening for HTTP connections on port 80.
[2024-11-03T13:10:51Z INFO  sandhole] Listening for HTTPS connections on port 443.
[2024-11-03T13:10:51Z INFO  sandhole] Listening for SSH connections on port 2222.
[2024-11-03T13:10:51Z INFO  sandhole] Sandhole is now running.
```

Now you're ready to dig sandholes like a crab!
