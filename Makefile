.PHONY: test lint fmt hooks

test:
	go test -race ./...

fmt:                   ## gofmt -w .
	gofmt -w .

lint:
	golangci-lint run ./...

hooks:
	git config core.hooksPath .githooks
	@echo "pre-commit hook installed (git config core.hooksPath .githooks)"
