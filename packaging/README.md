# Packaging

How `bussard` reaches a user who is not a Rust developer: a shell installer
for each platform and a Homebrew tap. Both serve the binaries that
`.github/workflows/release.yml` already builds, so nothing here compiles
anything.

| Route | User runs | Source of truth |
| --- | --- | --- |
| Shell installer | `curl -fsSL https://raw.githubusercontent.com/tmbo/bussard/main/install.sh \| sh` | `install.sh` on `main` |
| PowerShell installer | `irm https://raw.githubusercontent.com/tmbo/bussard/main/install.ps1 \| iex` | `install.ps1` on `main` |
| Homebrew | `brew install tmbo/tap/bussard` | `Formula/bussard.rb` in `tmbo/homebrew-tap` |

## Release flow

Pushing a version tag (`0.2.0` or `v0.2.0`) runs `release.yml`:

1. `create-release` checks that the tag matches the workspace version and opens
   the GitHub Release.
2. `build` compiles five binaries (`bussard-linux-x64`, `bussard-linux-arm64`,
   `bussard-macos-arm64`, `bussard-macos-x64`, `bussard-windows-x64.exe`) and
   uploads each with a `.sha256` file.
3. `homebrew` renders `Formula/bussard.rb` with the new version and the four
   checksums and commits it to `tmbo/homebrew-tap`.

The shell installers need no release step: they read the release from the
GitHub API at install time, so they pick up a new version the moment it is
published.

Step 3 needs a token for a repository outside this one. Without the secret the
job prints a notice and does nothing, so a release never fails because
packaging is not set up yet.

Windows users install with the PowerShell script; a winget package was
considered and dropped, since the direct download does the same job.

## One-time setup

### Homebrew tap

1. The public repository `tmbo/homebrew-tap` exists (done). The name matters:
   `brew install tmbo/tap/bussard` expands to `github.com/tmbo/homebrew-tap`.
   The release job creates `Formula/bussard.rb` on its first run.
2. Create a fine-grained personal access token with **Contents: read and write**
   on `tmbo/homebrew-tap` only.
3. Add it to this repository as the secret `HOMEBREW_TAP_TOKEN`
   (Settings, Secrets and variables, Actions).

The next release commits the rendered formula to the tap.

## How the formula is updated

`Formula/bussard.rb` in this repository is a **template**. It carries
`@VERSION@`, `@TAG@` and one `@SHA256_...@` placeholder per platform. The
`homebrew` job downloads the four `.sha256` files from the release, substitutes
them, fails if any placeholder survives, and pushes the result to the tap. The
template is therefore not installable as it stands; the installable copy is the
one in `tmbo/homebrew-tap`.

To render it locally for a published release:

```console
$ tag=0.2.0
$ mkdir dist && cd dist
$ gh release download "$tag" --repo tmbo/bussard --pattern '*.sha256'
$ cd ..
$ sha() { cut -d ' ' -f 1 < "dist/bussard-$1.sha256"; }
$ sed -e "s|@VERSION@|${tag#v}|g" -e "s|@TAG@|$tag|g" \
    -e "s|@SHA256_MACOS_ARM64@|$(sha macos-arm64)|" \
    -e "s|@SHA256_MACOS_X64@|$(sha macos-x64)|" \
    -e "s|@SHA256_LINUX_X64@|$(sha linux-x64)|" \
    -e "s|@SHA256_LINUX_ARM64@|$(sha linux-arm64)|" \
    Formula/bussard.rb > /tmp/bussard.rb
$ brew install --formula /tmp/bussard.rb
```

## Testing

`.github/workflows/installers.yml` runs on every pull request that touches
these files. It shellchecks `install.sh` as POSIX `sh`, parses `install.ps1`,
then installs the latest published release on ubuntu, macOS and Windows runners
and asserts that `bussard --version` prints. Before the first non-draft release
exists the install steps skip with a notice, because there is nothing to
download.

Locally:

```console
$ shellcheck --shell=sh install.sh
$ sh -n install.sh
$ BUSSARD_INSTALL_DIR=/tmp/bussard-test sh ./install.sh
$ BUSSARD_VERSION=0.1.0 BUSSARD_INSTALL_DIR=/tmp/bussard-test sh ./install.sh
```

Notes:

- A draft release is invisible to `releases/latest`. The installers and the CI
  job only see a published release.
- Release tags are pushed as `0.2.0` or `v0.2.0`. The installers probe both
  spellings, using the small `.sha256` file as the probe.
- Binaries fetched with `curl` or `Invoke-WebRequest` carry no macOS quarantine
  attribute, so Gatekeeper does not block them. A binary a user downloads with a
  browser does, which is one more reason to point people at the installer.

## Download page

The download page belongs on the `website` branch, which already builds the
landing page and the GitHub Pages deployment. Nothing in this directory
generates it.

A static page needs no build step to link the newest assets: the GitHub API
serves the latest release as JSON, from any origin, with no token.

```
https://api.github.com/repos/tmbo/bussard/releases/latest
```

The response has `tag_name`, `html_url`, `published_at` and an `assets` array
of `{ name, browser_download_url, size }`. Unauthenticated calls are rate
limited per IP (60 an hour), which is ample for a download page.

```html
<div id="downloads">
  <a href="https://github.com/tmbo/bussard/releases/latest">Latest release</a>
</div>

<script>
  const ASSETS = {
    "bussard-macos-arm64": "macOS (Apple silicon)",
    "bussard-macos-x64": "macOS (Intel)",
    "bussard-linux-x64": "Linux (x86-64)",
    "bussard-linux-arm64": "Linux (arm64)",
    "bussard-windows-x64.exe": "Windows (x64)",
  };

  fetch("https://api.github.com/repos/tmbo/bussard/releases/latest")
    .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
    .then((release) => {
      const el = document.getElementById("downloads");
      el.innerHTML = `<p>Latest version: ${release.tag_name}</p>`;
      const list = document.createElement("ul");
      for (const asset of release.assets) {
        const label = ASSETS[asset.name];
        if (!label) continue; // skip the .sha256 files
        const item = document.createElement("li");
        const link = document.createElement("a");
        link.href = asset.browser_download_url;
        link.textContent = `${label} - ${(asset.size / 1e6).toFixed(1)} MB`;
        item.append(link);
        list.append(item);
      }
      el.append(list);
    })
    .catch(() => {
      /* leave the static link to the releases page in place */
    });
</script>
```

Keep the static link to
`https://github.com/tmbo/bussard/releases/latest` in the markup, so the page
still works when the API call fails or JavaScript is off. The page should lead
with the one-line installers and offer the direct downloads below them, in the
same order as the README.
