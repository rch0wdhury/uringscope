# AUR packaging

`uringscope-bin/` is the AUR recipe for the static release binary. It lives
here so it is versioned with the code; the AUR itself is a separate git
remote that has to be pushed to by hand.

> **The `.SRCINFO` in this directory was hand-written**, because the machine
> it was prepared on had no Arch container to run `makepkg` in. The AUR
> validates `.SRCINFO` server-side and rejects a mismatch, so **regenerate it
> before the first push** (step 3 below) rather than trusting this copy.

## Publishing it the first time

You need an AUR account (https://aur.archlinux.org/register) with an SSH
key added to it; the AUR is SSH-only.

```sh
# 1. clone the (empty) AUR repo for the package name
git clone ssh://aur@aur.archlinux.org/uringscope-bin.git
cd uringscope-bin

# 2. copy the recipe in
cp /path/to/uringscope/packaging/aur/uringscope-bin/PKGBUILD .

# 3. regenerate .SRCINFO with the real tool, on Arch
#    (or: docker run --rm -v "$PWD":/pkg -w /pkg archlinux bash -c \
#         'pacman -Sy --noconfirm base-devel && useradd -m b && chown -R b . \
#          && su b -c "makepkg --printsrcinfo" > .SRCINFO')
makepkg --printsrcinfo > .SRCINFO

# 4. sanity-build before publishing anything
makepkg -f            # builds the package
pacman -Qlp *.pkg.tar.zst   # confirm /usr/bin/uringscope + man page + license

# 5. publish
git add PKGBUILD .SRCINFO
git commit -m "uringscope-bin 0.3.0-1"
git push
```

## On each new release

1. Bump `pkgver` (and reset `pkgrel=1`).
2. Refresh the checksums for both arches. `updpkgsums` does this
   automatically, or compute them by hand:
   ```sh
   curl -sL .../releases/download/v$VER/uringscope-x86_64 | sha256sum
   curl -sL .../releases/download/v$VER/uringscope-aarch64 | sha256sum
   ```
   Note the release workflow publishes a `.sha256` next to each binary, so
   the value can be cross-checked rather than trusted blindly.
3. Regenerate `.SRCINFO`, rebuild, commit, push.

Keep this directory and the AUR repo in sync — the copy here is the one
that gets reviewed alongside code changes.
