- The group-object table leaves out a reached, unlinked object whose flags are all
  disabled, as ETS does (#474): the Zennio Flat push buttons no longer enable the
  4 or 5 "dummy" objects behind `Flat_AlwaysFALSE`. The `<choose>` that reaches them
  still takes its default branch, as ETS does on the ABB and Busch-Jaeger steering
  parameters of the same shape.
