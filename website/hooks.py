"""MkDocs hook for the docs site.

Two jobs:

* Heading anchors follow GitHub's slug rules, so the ``#...`` links written
  for GitHub keep working on the site.
* Some pages link to files outside ``docs/`` (``../README.md``,
  ``../knx-sim/README.md``). Those have no page on the site, so the links are
  rewritten to the file on GitHub. Links that stay inside ``docs/`` are left
  for MkDocs to resolve, so a broken one still fails ``mkdocs build --strict``.
"""

import posixpath
import re

REPO_BLOB = "https://github.com/tmbo/bussard/blob/main/"

# GitHub keeps letters, digits, underscores, hyphens and spaces; everything
# else is dropped and spaces become hyphens. Runs of hyphens are kept.
_NOT_SLUG = re.compile(r"[^\w\- ]")


def gfm_slugify(value, separator="-"):
    """Slugify a heading the way GitHub does."""
    return _NOT_SLUG.sub("", value.lower()).replace(" ", separator)


def on_config(config):
    config["mdx_configs"].setdefault("toc", {})["slugify"] = gfm_slugify
    return config

# [text](../something) but not ![image](../something)
_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\((\.\.[^)\s]*)\)")


def on_page_markdown(markdown, page, config, files):
    page_dir = posixpath.dirname(page.file.src_uri)

    def rewrite(match):
        text, href = match.group(1), match.group(2)
        path, _, fragment = href.partition("#")
        resolved = posixpath.normpath(posixpath.join("docs", page_dir, path))
        if resolved.startswith("docs/"):
            return match.group(0)
        url = REPO_BLOB + resolved + (f"#{fragment}" if fragment else "")
        return f"[{text}]({url})"

    return _LINK.sub(rewrite, markdown)
