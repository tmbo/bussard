# Agent brief

The standing instructions for an implementation agent on bussard. A
coordinator pastes a pointer to this file into every agent prompt, followed
by the task itself (issue number, worktree path, and any investigation report
to start from). Keep the task part short; everything that does not change
between tasks belongs here.

## Where you work

- Only in the worktree the prompt names, never in the main checkout
  (`/Users/tmbo/projects/bussard`) and never in another agent's worktree.
- Never write under `knx/`, `captures/` or `shared-with-windows/`. They are
  the owner's installation, in use by other processes.
- Never contact a real gateway. `bussard.yaml` defaults to the owner's house,
  so every bus test uses the `bussard-testkit` mocks on `127.0.0.1:0`, and
  every CLI invocation in a test passes an explicit loopback `--gateway`.

## Commands

Each crate's integration tests are one `it` binary since #329, so filter by
test name, not by binary:

```
cargo nextest run -p <crate> -E 'test(/<pattern>/)'    # while iterating
cargo nextest run -p <crate> --profile ci                # once, before the PR
cargo clippy -p <crate> --all-targets -- -D warnings
cargo fmt --all
cargo test -p <crate> --doc                              # only if you touched doc examples
cargo deny check                                         # only if you touched dependencies
```

Crate-scoped only. CI runs the workspace gate; do not duplicate it locally.
Which tests check bussard against ETS and knx-sim, and which of them need
uncommitted data, is in `dev/testing.md` ("ETS, bussard and knx-sim: the
triangle"); the synthetic product catalogue that ungates them is #596.
Filter output before it reaches your transcript (aim for under 50 lines per
command). Keep `[profile.dev] debug = "line-tables-only"`.

## Time budget

- Stop any single cargo command that runs longer than 15 minutes and report
  it instead of waiting. nextest's slow-timeout already kills a hung test.
- When the coordinator sends "status?", answer in three lines: the step you
  are on, what is left, and the longest-running command so far.
- If the brief turns out to be wrong about the code (a file moved, a helper
  has a different signature), say so in the report and continue with what is
  there; do not stop to ask.

## Code rules

CLAUDE.md applies in full. The ones agents most often miss:

- No `.unwrap()` or `.expect()` anywhere but a binary's `main`; tests return
  `Result` and use `?`.
- Doc comments on every public item; no wildcard imports outside test modules.
- No new dependency without a one-line justification in the PR body, and
  never a copyleft or git dependency.
- Changelog: never edit `CHANGELOG.md`. Add a fragment under
  `changelog.d/<section>/<issue>-<slug>.md` (see `changelog.d/README.md`).
- Unit tests in `#[cfg(test)]` at the bottom of the file, integration tests in
  the crate's `tests/it/`. Name them `test_<function>_<scenario>`.

## Issues and labels

Issues are the project's memory: edit the body (`gh issue edit --body-file`),
never add comments. A body states the problem, the evidence (capture, measurement,
spec clause with document and section, decision with its date), what "done" means,
and the related issues and PRs. Close with the reason written into the body first
(`gh issue close -r completed|"not planned"`). Quote at most a short phrase of the
KNX Standard; the repository is public and the standard is licensed.

Every issue carries one type label and the area labels that apply:

| label | use it when |
|---|---|
| `bug` / `enhancement` / `documentation` / `question` | the type; exactly one |
| `epic` | an umbrella with a checklist of linked issues; closed when every item and every done-when clause is settled |
| `mcp` | the MCP server or how the assistant uses it |
| `knx-sim` | the simulator or the sim catalog loop |
| `secure` | KNX Data Secure, KNXnet/IP Secure, the key store |
| `oracle` | the offline oracle, ETS captures, the capture plan, rows files |
| `performance` | wall-clock or request-count work; bound by the Speed Changes rules in `CLAUDE.md` |
| `spec-review` | a finding of the review against the KNX Standard 3.0.0 (umbrella #550) |
| `ets-sweep` | a finding or task of the ETS sweep over the product catalog (`tools/ets-sweep`) |
| `follow-up` | an open point a merged PR left behind; the body names the PR |
| `needs-capture` | blocked on an ETS capture or a live recording only the owner can make; the body names the capture and it is listed in the owner's capture plan (#572) |
| `needs-decision` | blocked on an owner decision named in the body (a convention, a scope, a live run) |

`needs-capture` and `needs-decision` mark why an issue is not being worked on; an
agent that picks up such an issue implements what the evidence already settles and
leaves the rest as a `## Status` section in the body. A PR that fixes an issue says
`Closes #n`; a PR that does part of it says `Refs #n` and adds the status.

## Commit and PR

1. Commit with the `Co-Authored-By` trailer your own system sets. Do not
   change it to another model's line.
2. `gh pr create` with a title in the imperative and a body that states what
   changed, why, how it was tested, and `Closes #<issue>`.
3. `gh pr merge --auto --squash`, then stop. Do not watch CI, do not rebase
   onto a moving main, do not touch other branches. If the push or the
   auto-merge command is blocked, say so in the report; the coordinator runs
   it.

## Final report

At most 150 words, in this shape:

```
PR: <url>, auto-merge on|off (<why if off>)
Gates: fmt ok, clippy ok, nextest <crate>: N passed (<profile>), doc-tests ok|skipped
Deviations from the brief: <one line each, or "none">
Open points: <one line each, or "none">
Files: <paths, one per line>
```

No narration of what you tried first, no restating the issue, no praise of
the design. A behaviour change the coordinator must know about is a
deviation; a thing you chose not to do is an open point.
