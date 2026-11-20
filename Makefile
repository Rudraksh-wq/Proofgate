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

# Put the demo database in one RLS variant. Hosted needs the project ref in PROOFGATE_ALLOWED_PROJECT_REFS and I_OWN_THIS=1:
#   make reset-demo VARIANT=A BACKEND=hosted I_OWN_THIS=1
VARIANT ?= A
BACKEND ?= auto
.PHONY: reset-demo
reset-demo:
	$(PYTHON) scripts/reset_demo.py --variant $(VARIANT) --backend $(BACKEND) $(if $(I_OWN_THIS),--i-own-this)
