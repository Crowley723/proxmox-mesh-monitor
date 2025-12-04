.PHONY: install dev dev-debug test coverage coverage-html generate bootstrap join run new-join-token validate-join-token

bootstrap:
	go run main.go --bootstrap --address 127.0.0.1 --config config.template.yaml --cert-dir ./certs

join:
	go run main.go -join -address <keymaster-addr> -join-token <token> -config config.template.yaml -cert-dir ./certs

run:
	go run main.go --config config.template.yaml --cert-dir ./certs

new-join-token:
	go run main.go --config config.template.yaml --generate-token --token-node-hostname node1

validate-join-token:
	go run main.go --config config.template.yaml --verify-token --token-node-hostname abc123 --token <token>

install:
	go mod tidy
	go mod download

dev:
	GO_ENV=development reflex -r '\.go$$' -s -- go run main.go -config config.template.yaml -cert-dir ./certs

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