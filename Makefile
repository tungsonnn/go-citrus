SHELL=/bin/bash
PROJ_ROOT= $(shell pwd)

export COVERAGE_EXCLUSION="vendor|main.go"
export GOFLAGS := -mod=vendor

.PHONY: *

default: all

all: clean tools build test

clean:
	go clean
	rm -rf $(PROJ_ROOT)/bin
	rm -f $(PROJ_ROOT)/*.xml
	rm -f $(PROJ_ROOT)/*.log
	rm -f $(PROJ_ROOT)/*.out

tools:
	go install golang.org/x/lint/golint
	go install gotest.tools/gotestsum
	go install github.com/stretchr/testify/require

lint:
	golangci-lint run -c .golangci.yml --out-format checkstyle > cilint-report.xml

build: tools
	go build ./...

TEST_RUNNER := gotestsum --format testname -junitfile ./TEST-unit.xml --
TEST_OPTIONS := -coverprofile=./coverage.out -covermode=atomic -race -parallel 1 -timeout 30m -v
test: build
	$(TEST_RUNNER) $(TEST_OPTIONS) "$(TEST_SCOPE)"

vendor:
	go mod verify
	go mod tidy
	go mod vendor