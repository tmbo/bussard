- knxtrace names APCI `0x3D0` `A_MemoryBit_Write` instead of `A_ADC_Read`,
  decodes `A_ADC_Read`/`A_ADC_Response` (`0x180`/`0x1C0`, channel in the low
  six bits) and knows the remaining services of the 03_03_07 APCI table (#510).
