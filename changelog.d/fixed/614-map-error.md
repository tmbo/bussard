- `bussard flash` plans the 27 Siemens 07B0 applications whose product
  procedure wraps the unload of object 5 in `LdCtrlMapError` (#614). The op is
  typed: the unload goes to object 5 and a device without that object (count 0
  answer) completes it; any other failure still fails the step. A procedure
  that lists its `par` and `grp` downloads after the complete one runs only
  the complete one, its table segments on LSM 1 to 3 take the table images,
  and `LdCtrlCompareProp` reads the element its `StartElement` names.
