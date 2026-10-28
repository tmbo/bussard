- `apply` on a System B device reloads the group-object table when it differs
  from the one a full flash writes (#540). Before, a link to an object the
  last flash left unlinked was written and verified, but the object's
  communication flag stayed off and the device ignored the link. `plan` reads
  the table with the device's product data and names each descriptor that
  changes; `apply`, `apply --line` and the MCP apply reload the table before
  the link tables and read it back. Without product data `plan` names the
  newly linked objects whose flag it could not check.
