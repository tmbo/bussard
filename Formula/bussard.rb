# Homebrew formula for bussard.
#
# This copy is the template. On a version tag the release workflow fills in the
# version, tag and checksums of the published release and pushes the result to
# the tap repository `tmbo/homebrew-tap`, which is what
# `brew install tmbo/tap/bussard` reads. The `@...@` placeholders below are
# substituted there, so this file is not installable as it stands.
#
# See packaging/README.md for the release flow and the one-time tap setup.
class Bussard < Formula
  desc "Program, monitor and decode a KNX building bus from the command line"
  homepage "https://github.com/tmbo/bussard"
  version "@VERSION@"
  license "MIT"

  # The release publishes bare binaries, one per platform, so the formula picks
  # the matching asset instead of building from source.
  on_macos do
    on_arm do
      url "https://github.com/tmbo/bussard/releases/download/@TAG@/bussard-macos-arm64"
      sha256 "@SHA256_MACOS_ARM64@"
    end
    on_intel do
      url "https://github.com/tmbo/bussard/releases/download/@TAG@/bussard-macos-x64"
      sha256 "@SHA256_MACOS_X64@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/tmbo/bussard/releases/download/@TAG@/bussard-linux-arm64"
      sha256 "@SHA256_LINUX_ARM64@"
    end
    on_intel do
      url "https://github.com/tmbo/bussard/releases/download/@TAG@/bussard-linux-x64"
      sha256 "@SHA256_LINUX_X64@"
    end
  end

  def install
    # The download is a single binary named after its platform, not an archive.
    bin.install Dir["bussard-*"].first => "bussard"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bussard --version")
  end
end
