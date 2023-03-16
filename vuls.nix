{ lib, buildGoModule }:

buildGoModule rec {
  pname = "vuls";
  version = "0.22.1";
  src = lib.cleanSource ./.;
  vendorSha256 = "sha256-kPWk54w3za9j1bQSKsYejyoE+xhhJ7/FM3pUVPjxAWE=";
  proxyVendor = true;
}
