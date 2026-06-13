PLUGIN_NAME ?= privacyfilter
VERSION ?= 0.2.0
BUILD_DIR ?= .
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_LDFLAGS ?= -s -w -X main.pluginVersion=$(VERSION)

EXT_linux = so
EXT_freebsd = so
EXT_darwin = dylib
EXT_windows = dll
PLUGIN_EXT = $(or $(EXT_$(GOOS)),so)
PLUGIN_OUTPUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)
PLUGIN_HEADER = $(basename $(PLUGIN_OUTPUT)).h
GITLEAKS_RULES_URL ?= https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml

.PHONY: build clean update-rules

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "$(GO_LDFLAGS)" -o $(PLUGIN_OUTPUT) .
	rm -f $(PLUGIN_HEADER)

clean:
	rm -f $(BUILD_DIR)/$(PLUGIN_NAME).so
	rm -f $(BUILD_DIR)/$(PLUGIN_NAME).dylib
	rm -f $(BUILD_DIR)/$(PLUGIN_NAME).dll
	rm -f $(PLUGIN_HEADER)

update-rules:
	curl -fsSL $(GITLEAKS_RULES_URL) -o rules/gitleaks.toml
