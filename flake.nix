{
  description = "eBPF tracer and analyzer for io_uring";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        uringscope = pkgs.stdenv.mkDerivation {
          pname = "uringscope";
          # The flake source has no .git, so the Makefile's `git describe`
          # falls through to its hardcoded constant. Keep these two in step
          # when tagging a release.
          version = "0.3.0";
          src = self;

          # clang compiles the BPF objects, bpftool generates the skeleton
          # header from them. Neither is needed at runtime.
          nativeBuildInputs = with pkgs; [ clang bpftools ];
          buildInputs = with pkgs; [ libbpf elfutils zlib ];

          # The Makefile invokes $(CLANG) with -target bpf directly. nix's
          # compiler wrapper injects hardening flags (stack protector,
          # fortify, PIE) that the bpf target does not accept, so they have
          # to be off for this derivation.
          hardeningDisable = [ "all" ];

          installFlags = [ "PREFIX=${placeholder "out"}" ];

          doCheck = true;
          # Findings unit tests: pure userspace, no kernel or BTF needed, so
          # they run inside the nix sandbox. The fault injection suite
          # cannot -- it loads BPF and wants root.
          checkTarget = "test-offline";

          meta = with pkgs.lib; {
            description = "eBPF tracer and analyzer for io_uring";
            longDescription = ''
              Attaches to any process using io_uring and reconstructs what
              each request did: per-opcode latency, async-worker punts,
              batching efficiency, SQPOLL stalls, plus findings that name
              the problem and suggest a fix. Needs a kernel with
              CONFIG_DEBUG_INFO_BTF and CAP_BPF + CAP_PERFMON (or root).
            '';
            homepage = "https://github.com/rch0wdhury/uringscope";
            # Userspace is MIT; the BPF programs are GPL-2.0-only OR BSD-3.
            license = with licenses; [ mit gpl2Only bsd3 ];
            platforms = [ "x86_64-linux" "aarch64-linux" ];
            mainProgram = "uringscope";
          };
        };
        default = uringscope;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          hardeningDisable = [ "all" ];
          packages = with pkgs; [
            clang bpftools libbpf elfutils zlib gnumake gcc
            # for the test injector and the fio benchmark workloads
            liburing fio
          ];
        };
      });
    };
}
