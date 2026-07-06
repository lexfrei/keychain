GO ?= go
GOLANGCI_LINT ?= golangci-lint
MARKDOWNLINT ?= markdownlint-cli2

.DEFAULT_GOAL := help

##@ Testing

test: ## Run all tests
	$(GO) test ./...

test-race: ## Run all tests with the race detector
	$(GO) test -race ./...

test-coverage: ## Run tests with a coverage profile (coverage.out)
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...

test-integration: ## Run gated integration tests against the real OS store
	$(GO) test -race -tags=keychain_integration ./...

##@ Linting

lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run --timeout=5m

lint-fix: ## Run golangci-lint with autofix
	$(GOLANGCI_LINT) run --timeout=5m --fix

lint-md: ## Lint Markdown
	$(MARKDOWNLINT) '**/*.md'

##@ Meta

ci-go: ## Run the Go CI gates locally (race tests + lint)
	$(GO) test -race ./... && $(GOLANGCI_LINT) run --timeout=5m

tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

.PHONY: test test-race test-coverage test-integration lint lint-fix lint-md ci-go tidy help
