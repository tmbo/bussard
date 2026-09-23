#!/bin/sh
# bussard installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/tmbo/bussard/main/install.sh | sh
#
# It downloads the release binary for this machine, verifies the published
# SHA-256 checksum, and puts `bussard` on your disk. Nothing is compiled and
# nothing outside the install directory is touched.
#
# Environment variables:
#   BUSSARD_VERSION      version to install, e.g. 0.1.0 (default: latest release)
#   BUSSARD_INSTALL_DIR  where to put the binary (default: /usr/local/bin when
#                        writable, otherwise ~/.local/bin)
#
# POSIX sh only: no bashisms, so it also runs under dash, ash and busybox sh.

set -eu

REPO="tmbo/bussard"
RELEASES_URL="https://github.com/${REPO}/releases"
API_URL="https://api.github.com/repos/${REPO}/releases"

TMPDIR_BUSSARD=""

say() {
	printf '%s\n' "$*"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

cleanup() {
	if [ -n "$TMPDIR_BUSSARD" ] && [ -d "$TMPDIR_BUSSARD" ]; then
		rm -rf "$TMPDIR_BUSSARD"
	fi
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1
}

# Fetch a URL to stdout. Fails (non-zero) on HTTP errors, not just on a dead
# socket, so a 404 never ends up written to disk as a "binary".
fetch_stdout() {
	if [ "$DOWNLOADER" = "curl" ]; then
		curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$1"
	else
		wget -qO- "$1"
	fi
}

# Fetch a URL into a file. Returns non-zero if the URL is missing.
fetch_file() {
	if [ "$DOWNLOADER" = "curl" ]; then
		curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$2" "$1"
	else
		wget -qO "$2" "$1"
	fi
}

detect_target() {
	uname_s="$(uname -s)"
	uname_m="$(uname -m)"

	case "$uname_s" in
	Linux) os="linux" ;;
	Darwin) os="macos" ;;
	*)
		die "unsupported operating system '$uname_s'. \
bussard ships binaries for Linux, macOS and Windows; \
see ${RELEASES_URL}/latest or build from source with cargo."
		;;
	esac

	case "$uname_m" in
	x86_64 | amd64) arch="x64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*)
		die "unsupported CPU architecture '$uname_m'. \
bussard ships x86-64 and arm64 binaries; build from source with cargo instead."
		;;
	esac

	ASSET="bussard-${os}-${arch}"
}

resolve_version() {
	if [ -n "${BUSSARD_VERSION:-}" ]; then
		VERSION="${BUSSARD_VERSION}"
		return
	fi

	# The GitHub API reports the newest non-draft, non-prerelease release.
	latest_json="$(fetch_stdout "${API_URL}/latest" 2>/dev/null)" || latest_json=""
	VERSION="$(printf '%s' "$latest_json" |
		grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' |
		head -n 1 |
		sed 's/.*"\([^"]*\)"$/\1/')"

	if [ -z "$VERSION" ]; then
		die "could not determine the latest bussard release. \
GitHub may be rate-limiting this machine. \
Pick a version from ${RELEASES_URL} and retry with \
BUSSARD_VERSION=x.y.z sh install.sh"
	fi
}

# Release tags are pushed either as `0.1.0` or `v0.1.0`. Try both, using the
# small checksum file as the probe, and remember which one exists.
download_checksum() {
	bare="${VERSION#v}"
	for candidate in "$bare" "v${bare}"; do
		if fetch_file "${RELEASES_URL}/download/${candidate}/${ASSET}.sha256" \
			"${TMPDIR_BUSSARD}/${ASSET}.sha256" 2>/dev/null; then
			TAG="$candidate"
			return 0
		fi
	done
	die "no download found for ${ASSET} in release '${VERSION}'. \
Check ${RELEASES_URL} for the versions and platforms that are published."
}

verify_checksum() {
	expected="$(cut -d ' ' -f 1 <"${TMPDIR_BUSSARD}/${ASSET}.sha256")"
	if [ -z "$expected" ]; then
		die "the published checksum file for ${ASSET} is empty"
	fi

	# sha256sum is the Linux spelling, shasum the macOS one.
	if need_cmd sha256sum; then
		actual="$(sha256sum "${TMPDIR_BUSSARD}/${ASSET}" | cut -d ' ' -f 1)"
	elif need_cmd shasum; then
		actual="$(shasum -a 256 "${TMPDIR_BUSSARD}/${ASSET}" | cut -d ' ' -f 1)"
	else
		die "need sha256sum or shasum to verify the download; neither is installed"
	fi

	if [ "$expected" != "$actual" ]; then
		die "checksum mismatch for ${ASSET}: \
expected ${expected}, got ${actual}. The download was corrupted or tampered \
with; nothing was installed."
	fi
}

pick_install_dir() {
	if [ -n "${BUSSARD_INSTALL_DIR:-}" ]; then
		INSTALL_DIR="${BUSSARD_INSTALL_DIR}"
		return
	fi
	if [ -w /usr/local/bin ] 2>/dev/null; then
		INSTALL_DIR="/usr/local/bin"
		return
	fi
	INSTALL_DIR="${HOME}/.local/bin"
}

path_contains() {
	case ":${PATH}:" in
	*":$1:"*) return 0 ;;
	*) return 1 ;;
	esac
}

main() {
	if need_cmd curl; then
		DOWNLOADER="curl"
	elif need_cmd wget; then
		DOWNLOADER="wget"
	else
		die "need curl or wget to download bussard; neither is installed"
	fi

	detect_target
	resolve_version

	TMPDIR_BUSSARD="$(mktemp -d 2>/dev/null || mktemp -d -t bussard)"
	trap cleanup EXIT INT TERM

	download_checksum
	say "Downloading bussard ${TAG} (${ASSET})"
	fetch_file "${RELEASES_URL}/download/${TAG}/${ASSET}" \
		"${TMPDIR_BUSSARD}/${ASSET}" ||
		die "failed to download ${RELEASES_URL}/download/${TAG}/${ASSET}"

	verify_checksum
	say "Checksum verified"

	pick_install_dir
	if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
		die "cannot create ${INSTALL_DIR}. \
Set BUSSARD_INSTALL_DIR to a directory you can write to, \
for example: BUSSARD_INSTALL_DIR=\$HOME/bin sh install.sh"
	fi
	if [ ! -w "$INSTALL_DIR" ]; then
		die "${INSTALL_DIR} is not writable. \
Set BUSSARD_INSTALL_DIR to a directory you can write to, \
for example: BUSSARD_INSTALL_DIR=\$HOME/bin sh install.sh"
	fi

	chmod 755 "${TMPDIR_BUSSARD}/${ASSET}"
	# Move into place in one step so a running bussard is never half-replaced.
	# mv across filesystems falls back to a copy, hence the cp fallback.
	mv -f "${TMPDIR_BUSSARD}/${ASSET}" "${INSTALL_DIR}/bussard" 2>/dev/null ||
		cp -f "${TMPDIR_BUSSARD}/${ASSET}" "${INSTALL_DIR}/bussard" ||
		die "could not install to ${INSTALL_DIR}/bussard"

	say "Installed ${INSTALL_DIR}/bussard"
	say ""
	"${INSTALL_DIR}/bussard" --version

	if ! path_contains "$INSTALL_DIR"; then
		say ""
		say "${INSTALL_DIR} is not on your PATH. Add it:"
		say ""
		say "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile"
		say ""
		say "then open a new terminal, or run bussard by its full path:"
		say "  ${INSTALL_DIR}/bussard --help"
	else
		say ""
		say "Next: bussard --help"
	fi
}

main "$@"
