REPOSITORY := github.com/np-guard/netpol-analyzer
EXE:=k8snetpolicy
COVERAGE:=netpolicy.coverprofile

mod: go.mod
	@echo -- $@ --
	go mod tidy
	go mod download

fmt:
	@echo -- $@ --
	goimports -local $(REPOSITORY) -w .

lint:
	@echo -- $@ --
	CGO_ENABLED=0 go vet ./...
	golangci-lint run

precommit: mod fmt lint

build:
	@echo -- $@ --
	CGO_ENABLED=0 go build -o ./bin/$(EXE) ./cmd/netpolicy

test:
	@echo -- $@ --
	go test ./... -v -coverpkg=./... -coverprofile $(COVERAGE)

coverage:
	go tool cover -html="$(COVERAGE)"

test-update: # overrides/ generates tests' expected output files for relevant tests 
# if the format is dot - generates also png files
	@echo -- $@ --
	go test ./pkg/netpol/connlist/ ./pkg/netpol/diff/ ./pkg/cli --args --update
