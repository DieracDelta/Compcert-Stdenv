{
  description = "CompCert as a nixpkgs stdenv, with proved hardening patches, and packages built with it";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              overlays = [ self.overlays.default ];
              # CompCert is under the INRIA non-commercial license.
              config.allowUnfreePredicate = p: (p.pname or "") == "compcert";
            }
          )
        );
    in
    {
      # Adds attributes only; see overlay.nix for the list.
      overlays.default = import ./overlay.nix;

      packages = forAllSystems (pkgs: {
        inherit (pkgs)
          compcert-hardened
          compcert-hardened-tests
          compcert-hardening-check
          compcertCC
          hello-compcert
          sqlcipher-compcert
          signal-desktop-compcert
          ;
        default = pkgs.compcert-hardened;
      });

      legacyPackages = forAllSystems (pkgs: {
        inherit (pkgs) compcertStdenv;
      });

      checks = forAllSystems (pkgs: {
        inherit (pkgs) compcert-hardening-check hello-compcert;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell.override { stdenv = pkgs.compcertStdenv; } { };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
