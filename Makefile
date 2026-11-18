.PHONY: help build test cover lint run-demo

DEMO := examples/demo-account

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

build: ## Build the scanner binary into bin/
	CGO_ENABLED=0 go build -trimpath -o bin/scanner ./cmd/scanner

test: ## Run all tests with the race detector
	go test -race -count=1 ./...

cover: ## Run tests and print coverage per function
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint: ## Run golangci-lint
	golangci-lint run

run-demo: ## Verify the demo account's Prowler findings
	go run ./cmd/scanner --prowler $(DEMO)/prowler.ocsf.json --inventory $(DEMO)/aws --fail-on never
