.PHONY: install dev dev-debug test coverage coverage-html generate

install:
	go mod tidy
	go mod download

dev:
	GO_ENV=development reflex -r '\.go$$' -s -- go run ./main.go -c config.template.yaml

dev-debug:
	GO_ENV=development reflex -r '\.go$$' -s -- dlv debug --headless --listen=:2345 --api-version=2 --accept-multiclient ./main.go -- -c config.template.yaml

TEST_FLAGS ?=

test:
	go test $(TEST_FLAGS) ./...

coverage:
	go test $(TEST_FLAGS) -cover ./...

coverage-html:
	go test -coverprofile=coverage.out $(TEST_FLAGS) ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

generate:
	go generate ./...