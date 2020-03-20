test:
	@go test ./...
.PHONY: test

test-race:
	@go test -race ./...
.PHONY: test-race

all-v:
	@go test ./... -v
	@go test -coverprofile=cover.out
