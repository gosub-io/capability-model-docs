# Gosub Extension Capability Model

Design specification for Gosub's extension **capability model** — how browser
extensions declare, hold, and compose authority, expressed as an
effect-based capability system rather than an API-namespace permission list.

The model is engine-wide: it spans network filtering (Sonar), the extension
broker, the renderer, manifest translation, and the capability registry. The
[`gosub-baleen`](https://github.com/gosub-io/gosub-baleen) filter engine is only
§14 (the matching core) of it.

## Layout

```
spec/       the versioned specification and its plain-language guide
redteam/    adversarial review passes that drove each revision
viewer/     build tooling for the HTML version browser (see viewer/README.md)
```

### `spec/`

- `gosub-extension-capability-model-v*.md` — one file per version, `v2.0.0`
  through the current `v2.1.11`. Each version's changelog (at the end of the
  file) records what changed and why.
- `guide-v2.md` — a plain-language "translation" of the model, mapped to the
  spec section-by-section. `guide.md` is an older draft.
- `architecture-v2.1.10.md` — architecture notes.

**Start with the newest version** (`v2.1.11`); read older versions only to trace
how a decision evolved. The `redteam/` files are the source of most revisions —
each names the version it attacked.

## The version viewer

A single self-contained HTML page browses every version side-by-side, pairing
each section (and each subsection of §5) with its plain-language translation,
and splitting the large §5 and §19 into navigable subsections.

    cd viewer && make viewer      # writes ../capability-model-viewer.html

The generated HTML is a build artifact (git-ignored); regenerate it after
editing a spec. See [`viewer/README.md`](viewer/README.md) for details.
Requires Python 3 with `markdown`.

## Hosting (GitHub Pages)

The viewer deploys to GitHub Pages automatically on every push to `main`, via
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) — the workflow
builds the viewer and publishes it as the site's `index.html`, so the HTML is
never committed. Live at:

    https://gosub-io.github.io/capability-model-docs/

**One-time setup** (repo → **Settings → Pages**): set **Source** to
**GitHub Actions**. The first push to `main` then builds and deploys; the
workflow can also be run by hand from the **Actions** tab.

## Versioning

Versions are whole-file snapshots (`…-v2.1.11.md`) in RFC style, so the viewer
can diff them and the red-team history stays legible. New versions are added as
new files rather than editing prior ones in place.
