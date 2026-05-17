.PHONY: test lint hooks

test:
	go test -race ./...

lint:
	golangci-lint run ./...

hooks:
	git config core.hooksPath .githooks
	@echo "pre-commit hook installed (git config core.hooksPath .githooks)"
