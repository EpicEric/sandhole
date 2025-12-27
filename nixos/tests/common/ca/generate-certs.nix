{
  pkgs,
  domain,
  minica ? pkgs.minica,
  mkDerivation ? pkgs.stdenv.mkDerivation,
}:
mkDerivation {
  name = "test-certs";
  buildInputs = [
    (minica.overrideAttrs (old: {
      prePatch = ''
        sed -i 's_NotAfter: time.Now().AddDate(2, 0, 30),_NotAfter: time.Now().AddDate(20, 0, 0),_' main.go
      '';
    }))
  ];
  dontUnpack = true;

  buildPhase = ''
    minica \
      --ca-key rootCA-key.pem \
      --ca-cert rootCA.pem \
      --domains '${domain},*.${domain}'
  '';

  installPhase = ''
    mkdir -p $out/${domain}
    mv rootCA*.pem $out
    mv ${domain}/key.pem $out/${domain}/privkey.pem
    mv ${domain}/cert.pem $out/${domain}/fullchain.pem
  '';
}
