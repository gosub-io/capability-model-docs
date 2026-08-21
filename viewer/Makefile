# Regenerate the capability-model version viewer.
#
#   make viewer    -> build data.json, then the self-contained HTML viewer
#                     (mermaid inlined -> diagrams render; this is the Pages build)
#   make artifact  -> same, but WITHOUT the inlined mermaid library, for the
#                     Claude Artifact (its CSP rejects the bundle; diagrams show
#                     as labelled source)
#   make data      -> just re-extract data.json from the spec .md files
#   make clean     -> remove generated data.json (viewer is left in place)
#
# Inputs  : ../spec/*.md
#           (override the spec location with:  make viewer SPECS_DIR=/path)
# Output  : ../capability-model-viewer.html
#           (override with:  make viewer OUT_DIR=/path)

PY ?= python3

.PHONY: viewer artifact data clean
viewer: data
	$(PY) build_html.py

artifact: data
	EMBED_MERMAID=0 $(PY) build_html.py

data:
	$(PY) build_data.py

clean:
	rm -f data.json
