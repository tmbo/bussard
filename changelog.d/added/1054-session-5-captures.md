- More ETS references are gated in CI: a hidden parameter in a data-less
  segment (`syn-relseg-dataless-hidden`: ETS writes its octets as `00`),
  two partial downloads in one ETS session (`partial-twice`, #1091), a link
  and a parameter changed before one partial download (`apply-params`,
  #1095) and a secure download after ETS's unload (`syn-secure-fill`
  `unload-reload`: no factory reset, #1081). The ETS sweep driver no longer
  records a radio option it could not read as an empty value (#1049).
