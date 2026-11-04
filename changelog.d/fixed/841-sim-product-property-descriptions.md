- knx-sim describes a property a product's load procedure writes as the
  product declares it: its size from the step's `InlineData`, else from the
  parameters the product stores in the property, else `Count`; a scalar PDT
  where those parameters give one (`PDT_UNSIGNED_CHAR` for the Enertex PID 211
  of object type 50001), else the generic PDT of the element size; write
  level 2. It described the Enertex property as `PDT_VARIABLE_LENGTH` with
  write level 0, under a constant misnamed `PDT_GENERIC_01` (#841).
