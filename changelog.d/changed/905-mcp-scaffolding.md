- The MCP server's plan-confirm scaffolding exists once (#905): one store
  for every plan digest (device, line, restore, restart, add, replace,
  commission and the Home Assistant plans), one digest builder, one job
  runner and one `claim`, one set of reply helpers and one bus-ready check,
  and one table of tools and their tiers. A digest that is unknown, expired or
  already used is refused with the same sentence by every tool, so the
  Home Assistant, commissioning and restart refusals now read like the
  device plan's.
