.PHONY: demo measure test vet fmt build

demo: ## Run the end-to-end demonstration
	go run ./cmd/verity demo

measure: ## Print the endorsed reference measurement
	go run ./cmd/verity measure

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .
