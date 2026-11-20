PYTHON ?= python

.PHONY: corpus test

# render the fake-secret corpus files (git-ignored) from their templates
corpus:
	$(PYTHON) demo-apps/generate_corpus.py

test: corpus
	$(PYTHON) -m pytest -q

.PHONY: bench
bench:
	$(PYTHON) bench/run_bench.py

.PHONY: smoke
smoke:
	$(PYTHON) scripts/smoke.py
