- `import-product --order-number` accepts a vendor download served as a ZIP
  that bundles several products when the index entry's size and SHA-256
  describe one inner `.knxprod` (Ekinex EK-E72): the matching inner file is
  stored and the others are ignored. No match still fails, naming the URL,
  the served ZIP and how many inner products were tried (#711).
