- The certificate enrolment page for the phone, `https://bussard.tmbo.dev/enroll/`
  (#730): it opens the link `bussard keys enroll` shows, displays the session
  code, scans certificate QR codes with the camera (`BarcodeDetector`, or the
  vendored jsQR on iOS) or takes the typed 36 characters with the same
  normalization and check as bussard, sends each certificate encrypted to the
  relay, and shows bussard's result per label. Serials stay visible, keys are
  never shown again after sending.
