- The repository no longer names the maintainer's network: the gateway
  address and MAC in tests, docs and the synthetic captures are RFC 5737 and
  RFC 7042 documentation values, the ETS sweep reads the VM's host and user
  from `.env`, and CI refuses a private path, LAN address, home directory or
  real MAC in a tracked file (`scripts/check-no-private-data.sh`).
