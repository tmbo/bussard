- knx-sim places a simulated IP interface's KNXnet/IP parameter object at the
  lowest free object index, where ETS's object walk finds it, not after the
  last object: the ise smart connect devices have application object 8, the
  parameter object went to 9, and ETS stopped at the absent object 6 (#422).
