- A text parameter starts from its `InitialValue`, translated into the model's
  language, as ETS starts a new device (#473): the Busch-Wächter PRO 2800's device
  name is "Busch-Wächter Pro" in a German project, not the English "Busch-Watchdog
  Pro". A value set in the model still wins. The ETS sweep's oracle models import
  in de-DE, the sweep project's language.
