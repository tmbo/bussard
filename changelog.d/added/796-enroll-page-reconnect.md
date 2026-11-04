- The enrolment page comes back as the same phone after a reload or a
  network switch: it keeps its phone key for the session in IndexedDB as a
  non-extractable key (deleted when the session ends or after 4 hours),
  shows the earlier results again, and shows "Reconnecting…" while it
  retries (#796).
