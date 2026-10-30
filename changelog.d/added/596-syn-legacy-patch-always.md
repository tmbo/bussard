- Synthetic product `syn-legacy-patch-always` (Twig patcher, `NEST-PATCH`):
  `syn-minimal` with a hidden `LegacyPatchAlways` parameter whose default
  differs from the template, in a `DownloadInvisibleParameters="Background"`
  application, captured with ETS (#604 row 20): ETS writes the default, and so
  does bussard (regression row for #450).
