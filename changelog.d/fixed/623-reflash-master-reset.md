- A re-flash of a device that already holds the application no longer skips
  an object the product's own `LdCtrlMasterReset` then erases (erase code 4
  and every other code that resets a loaded object). Such a plan takes no
  resident-MCB skip and re-downloads every object, so the read-back verifies
  instead of finding the application unloaded (#623).
