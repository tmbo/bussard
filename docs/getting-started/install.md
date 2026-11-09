# Install bussard

bussard is a single binary. Use an installer, download it by hand, or build it from source.

## Use an installer

Pick one. Each installer puts `bussard` on your `PATH` and checks the download against its SHA-256 checksum.

=== "Homebrew (macOS, Linux)"

    ```console
    $ brew tap tmbo/tap
    $ brew trust tmbo/tap
    $ brew install tmbo/tap/bussard
    ```

    Homebrew 7 loads a formula from a third-party tap only after `brew trust`;
    older versions accept the install without it. `brew upgrade bussard`
    updates it later.

=== "Shell script (macOS, Linux)"

    The script downloads the binary for your machine and verifies its checksum. The output below is illustrative:

    ```console
    $ curl -fsSL https://raw.githubusercontent.com/tmbo/bussard/main/install.sh | sh
    Downloading bussard <version> (bussard-macos-arm64)
    Checksum verified
    Installed /usr/local/bin/bussard

    Next: bussard --help
    ```

    It installs to `/usr/local/bin` when it can write there, otherwise to `~/.local/bin`, and tells you how to add that to your `PATH`. Set `BUSSARD_VERSION` to pin a version and `BUSSARD_INSTALL_DIR` to choose the directory.

=== "PowerShell (Windows)"

    ```console
    $ irm https://raw.githubusercontent.com/tmbo/bussard/main/install.ps1 | iex
    Downloading bussard <version> (bussard-windows-x64.exe)
    Checksum verified
    ```

    It puts `bussard.exe` in `%LOCALAPPDATA%\Programs\bussard`. Windows shows a SmartScreen warning, because the binary is not signed.

## Download the binary by hand

Pick the file for your machine on the [download page](https://bussard.tmbo.dev/#download). Then make it executable and put it on your `PATH`:

=== "macOS"

    ```console
    $ chmod +x bussard-macos-arm64
    $ xattr -d com.apple.quarantine bussard-macos-arm64
    $ mv bussard-macos-arm64 /usr/local/bin/bussard
    ```

    The `xattr` line removes the quarantine flag once: the binary is not notarized, so macOS blocks it otherwise.

    Optional: check the download against the checksum file next to it first.

    ```console
    $ shasum -a 256 -c bussard-macos-arm64.sha256
    bussard-macos-arm64: OK
    ```

=== "Linux"

    ```console
    $ chmod +x bussard-linux-x64
    $ sudo mv bussard-linux-x64 /usr/local/bin/bussard
    ```

    Optional: check the download against the checksum file next to it first.

    ```console
    $ sha256sum -c bussard-linux-x64.sha256
    bussard-linux-x64: OK
    ```

=== "Windows"

    Rename `bussard-windows-x64.exe` to `bussard.exe` and move it into a folder on your `PATH`, for example `%LOCALAPPDATA%\Programs\bussard`. Windows shows a SmartScreen warning the first time, because the binary is not signed.

    Optional: compare the hash with the content of the `.sha256` file next to the download.

    ```console
    > certutil -hashfile bussard.exe SHA256
    ```

## Build from source

With Rust 1.89 or newer:

```console
$ git clone https://github.com/tmbo/bussard
$ cd bussard
$ cargo install --path crates/bussard-cli
```

## Next steps

- [Your first project](first-model.md): import an ETS export or start empty, then watch the bus.
- [Connect an assistant](assistant.md): let an LLM read and edit your project over MCP.
