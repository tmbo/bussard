- A flash writes a vendor default that lies outside its parameter type's range
  as declared, as ETS does, with a warning naming the parameter, instead of
  refusing the image. The ABB/Busch-Jaeger ventilation programs `A-A074` and
  `A-A075` ("Vent Dummy Prio Ende", default 1, type 129..129) flash again. A
  value set in the model outside its type is still refused (#405).
