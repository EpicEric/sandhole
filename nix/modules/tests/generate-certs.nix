# sandhole: Expose HTTP/SSH/TCP services through SSH port forwarding
# Copyright (C) 2024-2026 Eric Rodrigues Pires
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
# more details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.

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
