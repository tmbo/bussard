- `knx_setup` and `knx_import_file` take the ETS project password from a
  form bussard serves on this computer when the chat app supports URL
  elicitation, so the password never passes through the chat. bussard
  stores it as `BUSSARD_PROJECT_PASSWORD` in the `.env` next to the project
  folder, creating the file with mode 0600, and asks again on the page when
  it is wrong (#818).
