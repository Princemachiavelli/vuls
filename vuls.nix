{ lib, buildGoModule }:

buildGoModule rec {
  pname = "vuls";
  version = "1.0.0";
  src = lib.cleanSource ./.;
  vendorSha256 = "sha256-1lVN5HMbxSvtWK6S/9n4gniieQFdSt+7Vs2/YV08FG8=";
  proxyVendor = true;
}
