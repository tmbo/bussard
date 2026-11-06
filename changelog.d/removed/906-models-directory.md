- `.bussard/models/` is no longer written or read: product models are generated
  JSON under `.bussard/model-cache/`, rebuilt from `products/` on the next command.
  An old `.bussard/models/` folder can be deleted (#906).
