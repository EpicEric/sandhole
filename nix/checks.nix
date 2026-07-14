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

{
  pkgs,
  sandhole,
  ...
}:
{
  sandhole-module-test-blacklist = pkgs.testers.runNixOSTest (
    import ./modules/tests/blacklist.nix { inherit pkgs sandhole; }
  );

  sandhole-module-test-with-container = pkgs.testers.runNixOSTest (
    import ./modules/tests/with-container.nix { inherit pkgs sandhole; }
  );

  sandhole-module-test-websites = pkgs.testers.runNixOSTest (
    import ./modules/tests/websites.nix { inherit pkgs sandhole; }
  );
}
