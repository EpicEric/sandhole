# Copy of nixpkgs/nixos/tests/common/acme/server/generate-certs.nix
# to generate wildcard certificates with the directory
# structure expected by Sandhole.
{
  pkgs,
  domain,
  minica ? pkgs.minica,
  mkDerivation ? pkgs.stdenv.mkDerivation,
}:

let
  caKey = ../../../tests/data/ca/rootCA-key.pem;
  caCert = ../../../tests/data/ca/rootCA.pem;
in

mkDerivation {
  name = "sandhole-generate-certs";
  nativeBuildInputs = [ minica ];
  dontUnpack = true;

  buildPhase = ''
    minica \
      --ca-key ${caKey} \
      --ca-cert ${caCert} \
      --domains '${domain},*.${domain}'
  '';

  installPhase = ''
    mkdir -p $out/${domain}
    cp ${caKey} $out/ca.key.pem
    cp ${caCert} $out/ca.cert.pem
    cp ${domain}/key.pem $out/${domain}/privkey.pem
    cp ${domain}/cert.pem $out/${domain}/fullchain.pem
  '';
}
