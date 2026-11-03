- Golden request streams over the synthetic product catalogue (epic #596,
  step 7): bussard's flash of every synthetic product into knx-sim, and its
  apply where the catalogue has a `links` or `partial` variant, normalized by
  `knxtrace ops`, is committed under
  `tests-support/synthetic-products/<product>/requests/` and compared in the
  `sim-conformance` CI job, so a change to a write path is a reviewable diff;
  `BUSSARD_UPDATE_GOLDENS=1` regenerates them.
