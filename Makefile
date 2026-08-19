.PHONY: demo measure test race fuzz cover vet fmt build check

demo: ## Run the end-to-end demonstration
	go run ./cmd/verity demo

measure: ## Print the endorsed reference measurement
	go run ./cmd/verity measure

build:
	go build ./...

test:
	go test ./...

race: ## Run the suite under the race detector
	go test -race -count=1 ./...

fuzz: ## Short fuzz run over the attacker-controlled parsing surfaces
	go test ./internal/pdp -run '^$$' -fuzz FuzzPolicyParsing -fuzztime 30s
	go test ./internal/pdp -run '^$$' -fuzz FuzzRequestHashing -fuzztime 30s
	go test ./internal/pdp -run '^$$' -fuzz FuzzDecideNeverPanicsOrFailsOpen -fuzztime 30s

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: fmt vet test race demo ## Everything CI runs, minus the fuzz smoke
