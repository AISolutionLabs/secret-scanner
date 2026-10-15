VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo 1.0.0)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test bench validate release install clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/secretscan ./cmd/secretscan

test:
	go vet ./...
	go test -race -count=1 ./...

bench:
	go test -run xxx -bench . -benchmem ./internal/detect/

validate: build
	bin/secretscan validate -c examples/secretscan.toml

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/secretscan

release:
	@for os in linux darwin windows; do for arch in amd64 arm64; do \
		ext=$$( [ $$os = windows ] && echo .exe ); \
		echo "dist/secretscan-$$os-$$arch$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/secretscan-$$os-$$arch$$ext ./cmd/secretscan || exit 1; \
	done; done

clean:
	rm -rf bin dist
