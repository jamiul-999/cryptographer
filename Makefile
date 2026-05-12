.PHONY: build run test clean deps

BINARY=cryptographer
CMD=./cmd/cryptographer

build:
	go build -o $(BINARY) $(CMD)

run:
	go run $(CMD)

test:
	go test ./...

clean:
	rm -f $(BINARY)

deps:
	go mod tidy
