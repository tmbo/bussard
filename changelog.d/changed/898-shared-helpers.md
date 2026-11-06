- The hex, date, HTML-escape, slug and edit-distance helpers live once in
  `bussard_model::text` and `bussard_model::timefmt` instead of as private
  copies in each crate (#898). A hex payload such as `+1` or a non-ASCII
  character is now refused instead of decoded or panicking, and the
  installation documentation escapes `'` as `&#39;`.
