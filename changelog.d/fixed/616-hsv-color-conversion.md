- An `HSV` colour parameter (`TypeColor Space="HSV"`) is written as ETS
  writes it: the `#RRGGBB` value is converted to hue, saturation and value
  octets (`#FF0000` is `00 FF FF`) instead of being placed as the RGB octets.
  Read-back and `bussard device` show the held octets as an RGB value that
  converts to the same octets. Pinned by three synthetic ETS captures (#616).
