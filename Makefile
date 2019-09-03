NAME=ejsonkms
VERSION=$(shell cat VERSION)
GOFILES=$(shell find . -type f -name '*.go')

.PHONY: default all binaries clean

default: all
all: binaries
binaries: build/bin/linux-amd64 build/bin/darwin-amd64

build/bin/linux-amd64: $(GOFILES)
	mkdir -p "$(@D)"
	GOOS=linux GOARCH=amd64 go build \
	-ldflags '-s -w -X main.version="$(VERSION)"' \
	-o "$@"

build/bin/darwin-amd64: $(GOFILES)
	GOOS=darwin GOARCH=amd64 go build \
	-ldflags '-s -w -X main.version="$(VERSION)"' \
	-o "$@"

clean:
	rm -rf build
