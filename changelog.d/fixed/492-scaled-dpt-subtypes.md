- Scaled DPT sub-types are decoded and written in their unit (#492): 8.010
  percent in 0.01 % (7FFFh is invalid), 7.003/7.004 and 8.003/8.004 time
  periods in 10 ms / 100 ms steps, 13.002 flow rate in 0.0001 m³/h. The
  monitor shows `50.00 %` instead of `5000`, and `bussard write <ga> 50` on
  an 8.010 address sends `13 88` instead of 0.50 %. Home Assistant maps
  7.003, 7.004 and 13.002 to their own sensor types.
