#
#
#

export GOPATH=/z/go

TARGET := ezio
BINARY := $(TARGET)

VER := $(shell git describe)
OS := $(shell go env | grep GOOS | sed -e 's/.*="\(.*\)"/\1/')
ARCH := $(shell go env | grep GOARCH | sed -e 's/.*="\(.*\)"/\1/')
RELEASE := ${OS}-${ARCH}-$(VER)

DEBUG := -tags debug

VERSION := -X main.version='$(VER)'
STRIP := -s -w
EXT := -Wl,--allow-multiple-definition

BUILD_LDFLAGS := -ldflags "$(VERSION) $(STRIP) -extldflags '$(EXT)'"
STATIC_LDFLAGS := -ldflags "$(VERSION) $(STRIP) -extldflags '-static $(EXT)'"
DEBUG_LDFLAGS := -ldflags "$(VERSION) -extldflags '$(EXT)'"

GO := go
export CC=gcc
export LD=ld


.PHONY: build
build:
	$(GO) build -v $(BUILD_LDFLAGS) -o $(BINARY)

.PHONY: static
static:
	$(GO) build -v $(STATIC_LDFLAGS) -o $(BINARY)

.PHONY: debug
debug:
	$(GO) build -v $(DEBUG) $(DEBUG_LDFLAGS) -o $(BINARY)

.PHONY: deps
deps:
	$(GO) get -v "github.com/akmistry/go-lz4"
	$(GO) get -v "github.com/dsnet/compress/bzip2"
#	$(GO) get -v "github.com/DataDog/zstd"
	$(GO) get -v "github.com/managata/zstd"
	$(GO) get -v "github.com/remyoudompheng/go-liblzma"
	$(GO) get -v "github.com/templexxx/reedsolomon"
	$(GO) get -v "github.com/jessevdk/go-flags"
	$(GO) get -v "golang.org/x/crypto/ssh/terminal"
	$(GO) get -v "golang.org/x/crypto/chacha20poly1305"
	$(GO) get -v "golang.org/x/crypto/hkdf"

.PHONY: dist
dist:
	make static
	- rm -rf $(TARGET)-$(RELEASE)
	mkdir $(TARGET)-$(RELEASE)
	cp -a $(BINARY) $(TARGET)-$(RELEASE)
	cp -a LICENSE $(TARGET)-$(RELEASE)
	cp -a LICENSES $(TARGET)-$(RELEASE)
	gtar cJ --owner=managata --group=ezio -f $(TARGET)-$(RELEASE).tar.xz $(TARGET)-$(RELEASE)
	rm -rf $(TARGET)-$(RELEASE)

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f $(BINARY)
	rm -f $(TARGET).exe
	rm -f test/key/*
	rm -rf $(TARGET)-*
