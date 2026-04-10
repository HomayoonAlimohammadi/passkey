BIN     := passkey
LDFLAGS := -s -w
OUT     := dist

TARGETS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

.PHONY: all clean

all: $(TARGETS)

$(TARGETS):
	$(eval OS   := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT  := $(if $(filter windows,$(OS)),.exe,))
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) \
		go build -ldflags "$(LDFLAGS)" -o $(OUT)/$(BIN)-$(OS)-$(ARCH)$(EXT) .

clean:
	rm -rf $(OUT)
