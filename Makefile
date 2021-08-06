NAME=ejsonkms
PACKAGE=github.com/envato/ejsonkms
VERSION=$(shell cat VERSION)
GOFILES=$(shell find . -type f -name '*.go')

.PHONY: default all binaries clean

default: all
all: binaries
binaries: build/bin/linux-amd64  build/bin/linux-arm64 build/bin/darwin-amd64 build/bin/darwin-arm64

build/bin/linux-amd64: $(GOFILES)
	mkdir -p "$(@D)"
	GOOS=linux GOARCH=amd64 go build \
	-ldflags '-s -w -X main.version="$(VERSION)"' \
	-o "$@" \
	"$(PACKAGE)/cmd/$(NAME)"

build/bin/linux-arm64: $(GOFILES)
	mkdir -p "$(@D)"
	GOOS=linux GOARCH=arm64 go build \
	-ldflags '-s -w -X main.version="$(VERSION)"' \
	-o "$@" \
	"$(PACKAGE)/cmd/$(NAME)"

build/bin/darwin-amd64: $(GOFILES)
	GOOS=darwin GOARCH=amd64 go build \
	-ldflags '-s -w -X main.version="$(VERSION)"' \
	-o "$@" \
	"$(PACKAGE)/cmd/$(NAME)"

build/bin/darwin-arm64: $(GOFILES)
	GOOS=darwin GOARCH=arm64 go build \
	-ldflags '-s -w -X main.version="$(VERSION)"' \
	-o "$@" \
	"$(PACKAGE)/cmd/$(NAME)"

clean:
	rm -rf build
