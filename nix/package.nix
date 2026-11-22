{
  lib,
  rustPlatform,
  pkg-config,
  libgit2,
  libssh2,
  openssl,
  zlib,
}:

let
  workspace = (lib.importTOML ../Cargo.toml).workspace.package;
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "guisu";
  inherit (workspace) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../.cargo
      ../crates
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [
    "-p"
    "guisu"
    "--bin"
    "guisu"
  ];
  cargoCheckType = "debug";
  cargoTestFlags = [
    "--workspace"
    "--all-features"
  ];

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    libgit2
    libssh2
    openssl
    zlib
  ];

  # The packaged source has no .git directory.
  env.VERGEN_IDEMPOTENT = "1";

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    "$out/bin/guisu" --version | grep -Fx 'guisu ${finalAttrs.version}'
    runHook postInstallCheck
  '';

  meta = {
    description = "Manage dotfiles across multiple machines";
    homepage = workspace.repository;
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "guisu";
  };
})
