COMPOSE = docker compose -f deploy/docker-compose.yml
CLI     = $(COMPOSE) run --rm -T saferotate

.PHONY: test lint demo-up demo-rotate demo-stale demo-chaos demo-report demo-down

test:
	go test ./...

lint:
	go vet ./...

demo-up:            ## start Postgres, two apps under load, Prometheus
	$(COMPOSE) up -d --build --wait postgres app1 app2 loadgen prometheus

demo-rotate:        ## rotate the DB password under load and check zero failed requests
	./scripts/demo.sh rotate

demo-stale:         ## an app that never reloads blocks the revoke; expect rollback
	./scripts/demo.sh stale

demo-chaos:         ## errors rise during the rotation; expect rollback
	./scripts/demo.sh chaos

demo-report:        ## print the audit report
	$(CLI) report

demo-down:
	$(COMPOSE) --profile stale --profile tools down -v
