{ lib, buildGoModule }:

buildGoModule rec {
  pname = "vuls";
  version = "0.23.2";
  src = lib.cleanSource ./.;
  vendorSha256 = "sha256-jBZCcmPo9R6dUdL9e20Nyzd/U2Bz2FP63D1ORBwmSaE=";
  proxyVendor = true;
}
