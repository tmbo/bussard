- `tests-support/product-corpus/fetch.sh` no longer reports every fetch after
  the first as failed: `import-product` stores `products/manufacturers.toml`
  next to the archives, and the copy into the cache now skips it (#865).
