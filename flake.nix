{
  nixConfig.allowUnfree = true;
  nixConfig.extra-substituters = "https://sansorganes.cachix.org https://nrdxp.cachix.org https://nix-community.cachix.org https://nixpkgs-wayland.cachix.org https://cuda-maintainers.cachix.org";
  nixConfig.extra-trusted-public-keys = "cuda-maintainers.cachix.org-1:0dq3bujKpuEPMCX6U4WylrUDZ9JyUG0VpVZa7CNfq5E= nrdxp.cachix.org-1:Fc5PSqY2Jm1TrWfm88l6cvGWwz3s93c6IOifQWnhNW4= nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs= sansorganes.cachix.org-1:BfAh1MMvAleiV+INE0/R3g8ZgiJQHUNN5vDd3oGoicc= nixpkgs-wayland.cachix.org-1:3lwxaILxMRkVhehr5StQprHdEo4IrE8sRho9R9HOLYA=";
  inputs = {
    nixpkgs.url = "github:Princemachiavelli/nixpkgs/unstable-good";
    flake-utils.url = "github:numtide/flake-utils";
    mach-nix.url = "github:DavHau/mach-nix";
  };

outputs = { self, nixpkgs, flake-utils, mach-nix, ... }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      vuls = pkgs.callPackage ./vuls.nix { };
    in {
      packages = {
        inherit vuls ;
        default = vuls;
      };
    });
}
