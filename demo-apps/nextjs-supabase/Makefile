VARIANT ?= A

.PHONY: reset-demo variant-a variant-b variant-c start dev

# replay all migrations on the local Supabase stack with the chosen RLS variant:  make reset-demo VARIANT=C
reset-demo:
	npm run reset-demo -- $(VARIANT)

variant-a variant-b variant-c:
	npm run variant -- $(shell echo $@ | tail -c 2 | tr a-z A-Z)

start:
	supabase start

dev:
	npm run dev
