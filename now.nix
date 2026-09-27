{ lib, runner, ... }:
let
  inputs = import ./.tack;

  pkgs = import inputs.nixpkgs {
    overlays = [ (import inputs.rust-overlay) ];
  };

  msrv = (lib.importTOML ./Cargo.toml).package.rust-version;
in
{
  jobs = {
    test.steps = [
      {
        env.RUST_LOG = "debug";
        path = [
          pkgs.cargo-nextest
          pkgs.rust-bin.beta.latest.default
        ];
        run = ''
          cargo nextest run --no-fail-fast
        '';
      }
    ];

    clippy.steps = [
      {
        path = [ pkgs.rust-bin.stable.${msrv}.default ];
        run = ''
          cargo clippy --all-targets --fix --allow-dirty --allow-staged && cargo fmt --all
        '';
      }
    ];

    book.steps = [
      {
        path = [ pkgs.mdbook ];
        run = ''
          mdbook serve book --open
        '';
      }
    ];

    cli.steps = [
      (runner.steps.upload {
        name = "cli";
        deriv = (import ./nix { }).packages._cli;
      })
      {
        env.CLI = runner.download "cli";
        run = ''
          echo "# Command-line interface options" > book/src/cli.md
          echo "" >> book/src/cli.md
          echo "Sandhole exposes several options, which you can see by running \`sandhole --help\`." >> book/src/cli.md
          echo "" >> book/src/cli.md
          echo "---" >> book/src/cli.md
          echo "" >> book/src/cli.md
          sed 's/class="terminal"/style="white-space:pre-wrap;word-break:keep-all;"/' $CLI/cli.html >> book/src/cli.md
        '';
      }
    ];

    nixos-docs.steps = [
      (runner.steps.upload {
        name = "docs";
        deriv = (import ./nix { }).packages._docs;
      })
      {
        env.DOCS = runner.download "docs";
        run = ''
          echo "# NixOS module options" > book/src/nixos_options.md
          echo "" >> book/src/nixos_options.md
          cat $DOCS >> book/src/nixos_options.md
        '';
      }
    ];

    flamegraph-test.steps = [
      {
        path = [
          pkgs.cargo-flamegraph
          pkgs.rust-bin.beta.latest.default
        ];
        env.TEST = runner.var "TEST";
        run = ''
          cargo flamegraph --profile bench --test integration -- $TEST
        '';
      }
    ];

    minica.steps = [
      {
        path = [ pkgs.minica ];
        run = ''
          minica -ca-cert tests/data/ca/rootCA.pem -ca-key tests/data/ca/rootCA-key.pem -domains 'localhost'
          mv localhost/cert.pem tests/data/certificates/localhost/fullchain.pem
          mv localhost/key.pem tests/data/certificates/localhost/privkey.pem
          minica -ca-cert tests/data/ca/rootCA.pem -ca-key tests/data/ca/rootCA-key.pem -domains 'foobar.tld,*.foobar.tld'
          mv foobar.tld/cert.pem tests/data/certificates/foobar.tld/fullchain.pem
          mv foobar.tld/key.pem tests/data/certificates/foobar.tld/privkey.pem
          minica -ca-cert tests/data/ca/rootCA.pem -ca-key tests/data/ca/rootCA-key.pem -domains 'sandhole.com.br'
          mv sandhole.com.br/cert.pem tests/data/custom_certificate/fullchain.pem
          mv sandhole.com.br/key.pem tests/data/custom_certificate/privkey.pem
        '';
      }
    ];
  };
}
