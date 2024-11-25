# Quick start

In order to run Sandhole, you'll need:

- A server with public addresses.
- A domain pointing to said server (in this example, `server.com`).

Then, install the Sandhole binary in your server. Currently, the only ways to do so are [through Docker Compose](./docker_compose.md) or to compile it yourself.

If you're compiling from a separate workstation, grab the source files, build the binary, and copy it over:

```shell
git clone https://github.com/EpicEric/sandhole
cd sandhole
cargo build --release
scp target/release/sandhole you@server.com:
```

If you're compiling on the machine that's running Sandhole, you can install it directly. This will also add `sandhole` to your `PATH`:

```shell
cargo install --git https://github.com/EpicEric/sandhole
# -- OR --
git clone https://github.com/EpicEric/sandhole
cargo install --path sandhole
```

Once this is all done, you can start running Sandhole! Just make sure it points to your own domain:

```shell
sandhole --domain server.com
```

By default, this will expose ports 80 (for HTTP), 443 (for HTTPS), and 2222 (for SSH). If it all succeeds, you should see the following:

```log
[2024-11-23T13:10:51Z INFO  sandhole] Key file not found. Creating...
[2024-11-23T13:10:51Z INFO  sandhole] sandhole is now running.
```

Now you're ready to dig sandholes like a real crab!
