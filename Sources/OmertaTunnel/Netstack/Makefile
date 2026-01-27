# Makefile for building netstack as a C archive for Swift integration

.PHONY: all clean test

# Output files
ARCHIVE = libnetstack.a
HEADER = libnetstack.h

# Build flags
CGO_ENABLED = 1
GOFLAGS = -buildmode=c-archive

# Detect platform
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    # macOS
    ifeq ($(UNAME_M),arm64)
        GOARCH = arm64
    else
        GOARCH = amd64
    endif
    GOOS = darwin
else
    # Linux
    ifeq ($(UNAME_M),aarch64)
        GOARCH = arm64
    else
        GOARCH = amd64
    endif
    GOOS = linux
endif

all: $(ARCHIVE)

$(ARCHIVE): tunnel_netstack.go cmd/main.go go.mod
	@echo "Building netstack C archive for $(GOOS)/$(GOARCH)..."
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(ARCHIVE) ./cmd
	@echo "Created $(ARCHIVE) and $(HEADER)"

# Download dependencies
deps:
	go mod download
	go mod tidy

# Run Go tests
test:
	go test -v ./...

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Clean build artifacts
clean:
	rm -f $(ARCHIVE) $(HEADER)

# Install to CNetstack directory for Swift
install: $(ARCHIVE)
	@mkdir -p ../../CNetstack
	cp $(ARCHIVE) ../../CNetstack/
	cp $(HEADER) ../../CNetstack/
	@echo "Installed to Sources/CNetstack/"

# Format code
fmt:
	go fmt ./...

# Lint
lint:
	go vet ./...
