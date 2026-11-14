- A property write that carries `InlineData` and comes before the procedure
  declares the property now carries the values of the parameters placed in
  it, as ETS writes them, instead of the `InlineData` defaults; the System 7
  and property-only planners follow the same rule. The Hager TYMS646R
  (`M-0009_A-E802-13-7620`) downloaded "Emission" of object 9 at its default
  and reported the write verified, and `apply` did not see the change. Such
  a write is refused when it would drop a placed parameter (outside its
  extent, or beside one placed under the object's type) (#1049).
