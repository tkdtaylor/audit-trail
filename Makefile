.PHONY: build test fmt clean

build:
	go build -o bin/audit-trail ./...

test:
	go test ./...

fmt:
	go fmt ./...

clean:
	rm -rf bin
