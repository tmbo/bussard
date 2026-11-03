- `bussard keys enroll` takes KNX Secure device certificates from a phone
  (#729): it prints a link, its QR code and a fingerprint, and one line per
  label the phone scans. The label travels end to end encrypted (X25519,
  HKDF-SHA256, AES-256-GCM, `dev/enroll-protocol.md`) through a mailbox relay
  named by `--relay` or `[enroll] relay` in `bussard.toml`; the page's server
  and the relay see only ciphertext, and no key reaches the output. bussard
  also carries an in-process relay with the same API for tests and local
  mode. Each label is stored as `keys add-certificate` stores it (#728).
