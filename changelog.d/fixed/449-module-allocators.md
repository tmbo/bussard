- The Dynamic evaluator models ETS module allocation (#449): a `<Repeat>`
  instantiates its modules as often as its parameter says, and a module argument
  fed by an `<Allocator>` takes the allocator's next value (submodules count from
  their parent's allocators, plus a `BaseValue`). The Zennio DALI BOX v3 channel,
  the DALI BOX Broadcast and X2 channels, the AmbianceBOX and the ABB Modbus RTU
  Gateway's signals are now written, and the MDT AKR-IO logic module no longer
  lands on the application's own parameters; all match ETS. A module argument
  without a value now refuses the image instead of resolving to 0.
