- A property write that carries `InlineData` and comes before the procedure
  declares the property now carries the values of the parameters placed in
  it, as ETS writes them, instead of the `InlineData` defaults; the
  parameter-only download lowers it the same way. The Hager TYMS646R
  (`M-0009_A-E802-13-7620`) downloaded "Emission" of object 9 at its default
  and reported the write verified, and `apply` did not see the change
  (#1049). A program whose parameters all hold their defaults plans as
  before. A plan is refused, naming the parameter, only when a parameter set
  away from its default cannot be placed with certainty: no write of known
  extent to its property carries it, it names the object by type where the
  procedure names it by index, or the parameter-only procedure writes its
  property without the parameters' value.
