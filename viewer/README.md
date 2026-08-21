# Capability Model — version viewer

Tooling that builds a single self-contained HTML page for browsing every
version of the Gosub extension capability specification, with each section (and
each subsection of §5) paired to a collapsible plain-language translation from
`guide-v2`.

This folder is **just the build pipeline**. The spec lives in `../spec/`.

## Inputs (from `../spec/`, override with `SPECS_DIR=/path`)

- `gosub-extension-capability-model-v*.md` — one file per version
  (`v2.0.0`, `v2.1.0` … `v2.1.11`); versions are sorted naturally.
- `guide-v2.md` — the plain-language guide, mapped to the spec by section
  number. Its §5 subsections (Effect / Axis 1 / Axis 2 / The principal) are
  matched to the official §5 subsections and shown inline.

## Output

- `../capability-model-viewer.html` — one self-contained page (no external
  assets), ~2.5 MB. This is **generated**; treat it as a build artifact, not
  source (see `.gitignore`).
- `data.json` — intermediate, regenerated each run. Ignored by git.

## Build

    make viewer          # data.json, then the HTML viewer
    make data            # just re-extract data.json
    make clean           # remove data.json

    # spec/output elsewhere:
    make viewer SPECS_DIR=/path/to/specs OUT_DIR=/path/to/output

Requires Python 3 with `markdown` (`pip install markdown`).

## How it works

1. `build_data.py` parses every spec version into sections. It:
   - splits `##` sections, keeping Part context for the nav;
   - turns §19's `-- Group --` registry dividers into real subsection
     headings (so the registry becomes navigable), plus a "Registry deltas"
     heading for the trailing paragraph;
   - breaks the wall-of-text version preface into one paragraph per version
     note;
   - matches guide-v2 subsections to official §5 subsections by a keyword
     signature (`effect` / `axis1` / `axis2` / `principal`), so the pairing
     survives wording drift between the two documents;
   - renders Markdown to HTML with python-markdown (mermaid blocks are kept as
     labelled source). Result -> `data.json`.
2. `build_html.py` wraps that data in the viewer shell (version switcher,
   section TOC with subsection sub-nav, per-section/-subsection plain-language
   toggles, light/dark theme) and writes the self-contained HTML.

## Publishing

The viewer is currently shared as a private Claude Artifact. If you republish
from a different file path than before, it claims a **new** URL — keep the same
output path (or pass the existing artifact URL) to update in place. For a
team-hosted copy, GitHub Pages regenerating this in CI on spec changes works
well; do not commit the generated HTML.
