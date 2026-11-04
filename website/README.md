# Website

`bussard.tmbo.dev` is built from this directory and deployed to GitHub Pages by
`.github/workflows/site.yml` on every push to `main` that touches `website/` or
`docs/`.

- `index.html`: the landing page. One static file, English and German in the
  same document, switched by a language toggle and the browser language.
- `mkdocs.yml`, `hooks.py`, `overrides/`: the documentation site, rendered from
  `../docs` with MkDocs Material and served under `/docs/`.
- `enroll/index.html`: a plain notice at `/enroll/`, without script, that
  the certificate enrolment page moved. The page itself (`../web/enroll/`) is
  served by the relay Worker at `https://bussard-relay.tmbo.dev/enroll/`, on
  the relay's origin and with its own security headers (#797); see
  `services/enroll-relay/README.md`.
- `requirements.in`: the docs toolchain; `requirements.txt` is generated from
  it with every package pinned to its hashes, and CI installs it with
  `--require-hashes`. Regenerate it after changing `requirements.in`:

  ```console
  $ cd website && uv pip compile requirements.in --generate-hashes --universal --python-version 3.12 -o requirements.txt
  ```

Preview the docs locally:

```console
$ uvx --from mkdocs-material mkdocs serve -f website/mkdocs.yml
```

Build both parts the way CI does:

```console
$ mkdir -p _site && cp website/index.html _site/ && cp -R website/enroll _site/enroll
$ uvx --from mkdocs-material mkdocs build --strict -f website/mkdocs.yml -d "$PWD/_site/docs"
```

`--strict` turns a broken relative link in the docs into a build failure. Links
to files outside `docs/` are rewritten to GitHub by `hooks.py`.
