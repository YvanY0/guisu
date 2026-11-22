{
  pkgs ? import <nixpkgs> { },
}:
{
  guisu = pkgs.callPackage ./nix/package.nix { };
}
