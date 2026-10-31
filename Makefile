.PHONY: all build test vet check clean

all: check build

build:
	mkdir -p bin
	go build -o bin/proxy-server ./cmd/proxy-server
	go build -o bin/proxy-client ./cmd/proxy-client
	go build -o bin/proxy-token ./cmd/proxy-token

test:
	go test ./...

vet:
	go vet ./...

check: test vet

clean:
	rm -f bin/proxy-server bin/proxy-client bin/proxy-token
