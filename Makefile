.PHONY: build test check fmt clean fitness fitness-no-deps fitness-tamper-detection fitness-canonical-stability fitness-gofmt

build:
	go build -o bin/audit-trail ./...

test:
	go test ./...

check:
	go test ./...
	go build ./...

fmt:
	go fmt ./...

fitness: fitness-no-deps fitness-tamper-detection fitness-canonical-stability fitness-gofmt
	@echo "fitness: all wired checks passed"

fitness-no-deps:
	@if grep -Eq '^[[:space:]]*require([[:space:]]|$$)' go.mod; then \
		echo "fitness-no-deps: require directive found in go.mod"; \
		exit 1; \
	fi
	@echo "fitness-no-deps: no require directives found"

fitness-tamper-detection:
	go test ./... -run '^TestEmitVerifyAndTamperDetection$$'

fitness-canonical-stability:
	go test ./... -run '^TestCanonicalIsOrderIndependent$$'

fitness-gofmt:
	@tmp="$$(mktemp)"; \
	if ! gofmt -l $$(git ls-files '*.go') > "$$tmp"; then \
		rm -f "$$tmp"; \
		exit 1; \
	fi; \
	files="$$(cat "$$tmp")"; \
	rm -f "$$tmp"; \
	if [ -n "$$files" ]; then \
		printf '%s\n' "$$files"; \
		exit 1; \
	fi
	@echo "fitness-gofmt: go files are formatted"

clean:
	rm -rf bin
