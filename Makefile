.PHONY: help up down build run migrate fmt vet test test-integration demo clean

BIN := bin/s2s
ENV := S2S_MYSQL_DSN='s2s:s2spw@tcp(127.0.0.1:3308)/s2s?parseTime=true&multiStatements=true&loc=UTC' \
       S2S_REDIS_ADDR=127.0.0.1:6381 \
       S2S_SERVER_ADMIN_API_KEY=dev-admin-key-change-me \
       S2S_LOG_FORMAT=text

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

up:        ## Start MySQL and Redis
	docker compose -f deploy/docker-compose.yml up -d
	@echo "waiting for mysql..."
	@until docker exec rotating-s2s-mysql mysqladmin ping -h localhost -prootpw --silent 2>/dev/null; do sleep 1; done
	@echo "ready"

down:      ## Stop and remove containers
	docker compose -f deploy/docker-compose.yml down

build:     ## Build the binary
	go build -o $(BIN) .

migrate: build  ## Apply migrations
	@$(ENV) $(BIN) migrate up

run: build ## Run the server
	@$(ENV) $(BIN) serve

fmt:       ## Format
	gofmt -w .

vet:       ## Vet
	go vet ./...

test:      ## Run unit and SDK tests with the race detector
	go test -race $$(go list ./... | grep -v /test)
	cd sdk && go test -race ./...

test-integration: ## Run integration tests against the running MySQL and Redis
	@$(ENV) S2S_TEST_MYSQL_DSN='s2s:s2spw@tcp(127.0.0.1:3308)/s2s?parseTime=true&multiStatements=true&loc=UTC' \
	  S2S_TEST_REDIS_ADDR=127.0.0.1:6381 go test -race -count=1 -v ./test/...

demo:      ## Run the two-service example against a running issuer
	@cd examples && ./demo.sh

clean:     ## Remove build artefacts
	rm -rf bin/
