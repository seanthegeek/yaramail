# AGENTS.md

## Project overview

`yaramail` is a Python package and command line utility for scanning emails
with [YARA rules][yara]. It is intended for automated triage of phishing
reports.

The scanner inspects every part of a message — headers (with indents removed
for consistent matching), plain-text and HTML bodies (converted to Markdown
before scanning), and attachments. Attachment handling unwraps nested content:
emails attached to emails, text extracted from PDF documents, and files inside
ZIP archives (including nested ZIPs, with body text used as a candidate
password list for encrypted archives). On top of YARA matching, the package
provides a built-in methodology for categorizing emails and parses
`Authentication-Results` headers.

It is distributed on PyPI as [`yara-mail`][pypi]. Documentation is published
from the `docs/` directory to GitHub Pages.

[yara]: https://yara.readthedocs.io/en/stable/writingrules.html
[pypi]: https://pypi.org/project/yara-mail/

## Conventions

These rules apply to anyone — human or agent — making changes to this repo. They are intentionally checked in (rather than living in any one agent's private scratch memory) so that every collaborator picks them up the same way.

- **Wait for explicit commit AND push permission on the default branch — these are separate grants.** Finish the implementation, run the tests, summarize the diff, then **stop and ask**. The author decides when a change is ready to land; auto-committing makes review noisier and harder to reverse. "Commit this" mid-session counts as permission for that one commit, not a standing grant — and crucially, permission to commit is NOT permission to push. Pushing publishes the change to the remote where collaborators / CI / production deploys can pick it up, and is much harder to walk back than a local commit. Wait for an explicit "push it" before `git push`. If the prior commit was itself unauthorized, do NOT push it to "tidy up" — surface the situation and let the author decide whether to keep, amend, or reset.
- **Self-test before every `git commit`:** has the author typed "commit" (or an unambiguous equivalent — "ok to commit", "commit this", "commit and push") in a present-tense imperative since your last commit? If no, **ask**. Conditional phrasings like "if everything works we can push" or "we could commit this" or "if it looks good ..." are NOT authorizations — they are plans you must confirm before acting on. Treat the literal text of the user's last message as the source of truth, not your own interpretation of where the conversation is going.
  - **Self-test before every `git push`:** has the author typed "push" since your last push? Same rule. Permission to commit is NEVER permission to push.
  - **Exception — branches you created in-session** When you have explicitly created a feature branch yourself (e.g. `git checkout -b feat/something`) in that session, commit and push to THAT branch freely without per-step permission. The entire branch is reviewed at PR-open, so the per-commit gate adds review noise without adding safety. The exception is scoped to branches Claude created in the current session; it does NOT extend to `main`, to other long-lived branches, or to branches the author created.
- **Back up the any database before any schema or migration change.** Before running any schema-changing SQL (ALTER TABLE, CREATE/DROP, hand-rolled column rewrites, anything that mutates table shape) against a database, back it up.
- **Project-specific rules belong in AGENTS.md, not in any agent's private memory store.** If you (Claude Code, Cursor, Codex, Aider, anything that has a "save this preference for next time" surface) catch yourself about to write down a rule that's actually about the codebase rather than about working with this particular user, write it here instead. Memory is fine for user-profile facts and tool-use preferences; project rules should be portable across agents.
- **Plain language over jargon.** Comments, docstrings, AGENTS.md, commit messages, PR descriptions, and user-facing docs should describe what the code does in words a non-specialist would understand. Avoid terminology imported from neighboring fields that only loosely applies — e.g., "projection" from relational algebra to describe "the subset of recap_document fields we keep in the local store", or "compaction" / "denormalization" / similar when a plain description works. When a domain term IS the right word (because the code really is implementing that concept, or the reader needs to look it up to understand a library), use it AND a brief in-place gloss the first time it appears. When a term is borrowed loosely, replace it with the literal description. The test is whether a contributor coming into the codebase from a different background would have to stop and search to understand what a term refers to here; when in doubt, prefer the plainer rewrite even if it's a few extra words.
- **Fix underlying bugs, never just patch the data.** A manual SQL update or shell command that corrects ONE row of bad state a database doesn't help other users running the same code, doesn't help future data hitting the same bug, and doesn't survive a fresh checkout. Every observed bug must result in a code change that prevents the bad state from recurring, even when an immediate manual patch is also applied to unblock the operator. The manual patch is the bridge; the code fix is the destination — both happen, never just the bridge.
- **Verify library signatures against the installed version, not memory.** Before calling an unfamiliar function from a third-party library, read the source of the version that is actually installed in the project (the file in `site-packages` or equivalent). Training data and prior conversations are not authoritative — the installed code is.
- **Read official documentation in full before implementing against an unfamiliar API.** Fetch the relevant pages and read them end-to-end, not just the headings. When the docs offer both a quick-reference and a detail page on the same topic, read the detail page — quick-references omit aliases, edge cases, and secondary functions you will need.
- **SDK research order: installed source, then vendor docs, then GitHub issues.** When figuring out how a vendor SDK behaves, the installed SDK's source is the source of truth, vendor documentation is second, GitHub issues are third (for known bugs and undocumented behavior). Third-party blogs, Stack Overflow answers, and AI-generated explainers are not primary evidence — at best they are pointers to one of the three primary sources.
- **Don't catch `Exception` broadly.** Catch only the specific exception types you have a recovery path for. A bare `except Exception:` (or `except:`) hides programming errors that should be loud, makes debugging harder, and disguises broken assumptions as transient failures. Let unexpected exceptions propagate.

## Python Code Style

- Formatter/linter: **Ruff** — CI runs `ruff check` and `ruff format --check` on the latest Ruff
- Type checker: **pyright** — CI type-checks with the latest pyright (`PYRIGHT_PYTHON_FORCE_VERSION: latest`); keep the working tree pyright-clean, and run pyright over `tests/` too, not just the package
- Type annotations use `TypedDict` for structured results
- Supports all currently supported Python versions
- Modern type annotations across the entire project
- Testing framework: **pytest** — CI uploads coverage and test results to **Codecov** (requires the `CODECOV_TOKEN` repository secret)
- Every bit of code should have a test
- Build backend: **hatchling**
- Module-level loggers: `logger = logging.getLogger(__name__)` — one logger per module, named for the module
- Project-defined errors subclass `RuntimeError`, not bare `Exception`, so callers can catch project failures specifically without sweeping in unrelated bugs

## Markdown Style

- All markdown must pass VSCode's default markdownlint config
  - VScode projects must be configured with `"markdownlint.config": {"MD024": false}` to allow for proper changelog headings

## GitHub releases

- Releases are made by version tag not branch
- Version tags should be prefixed with `v`, unless prior tags are not
- Release titles must always exclude the `v` prefix
- For Python projects, wheels and srcbuilds should always be attached
  - Use existing build files **if** they match the release version

## Releases and deployment

- **CRITICAL: Never make a release without the explicit permission of the
  maintainer.** That includes every action that starts or advances a release:
  pushing a version tag, creating a GitHub Release, publishing to PyPI, or
  merging a release branch. Preparing release changes on a branch is fine;
  triggering the release itself requires the maintainer to say so, each time.
- The version lives in `yaramail/__init__.py` as `__version__`. Hatch reads
  it from there.
- Releases are automated by `.github/workflows/release.yml`: pushing a tag
  matching the version with a `v` prefix (e.g. `v3.4.2`) runs the full CI
  suite (lint + type-check + test matrix, reused from `ci.yml` via
  `workflow_call`), and only if it passes builds the package, publishes it to
  PyPI via Trusted Publishing, creates the GitHub Release (titled without the
  `v` prefix) with the tag's `CHANGELOG.md` section as its notes, and deploys
  the Sphinx docs to GitHub Pages. The build job fails if the tag doesn't
  match `__version__`; `CHANGELOG.md` headings carry no `v` prefix.
- Docs deployment lives in `.github/workflows/docs.yml`, which release.yml
  calls. For documentation-only updates between releases, the maintainer can
  run it on demand (Actions → Docs → Run workflow); it deploys straight to
  GitHub Pages. Like releases, on-demand docs deployment is a
  maintainer-permission action — see the CRITICAL rule above.

## Documentation

The project must be well documented. If existing documentation exists, hollow that convention.

For new projects, do **NOT** use a monolithic readme. Instead, use the readme to provide an overview of the project, and leave specific details in friendly, bite-sized markdown-formatted pages in a `docs` directory.
