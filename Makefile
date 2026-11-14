# GNU Make + Go are the only tools required to dispatch these commands.
# Recipes deliberately contain no POSIX-only shell constructs.
ifeq ($(OS),Windows_NT)
SHELL := cmd.exe
.SHELLFLAGS := /d /s /c
endif
.DEFAULT_GOAL := help
OUT_DIR ?= artifacts/ci
E2E_CONFIG ?=
EVIDENCE_DIR ?= evidence/local/ci
MSI_HOST ?=
MSI_SSH_ARGS ?=
WIX_DIR ?=
VERSION ?=
PRODUCT_CODE ?=
BUILD_DATE ?=
COMMIT ?=
TOOL = go run ./tools/build
BUILD_FLAGS = -out "$(OUT_DIR)" -version "$(VERSION)" -commit "$(COMMIT)" -date "$(BUILD_DATE)"
.PHONY: help deps unit test test-unit lint check frontend binaries build msi package test-e2e e2e integration clean publish
help:
	@$(TOOL) help
deps:
	$(TOOL) deps
unit test test-unit:
	$(TOOL) unit
lint:
	$(TOOL) lint
check: unit lint
frontend:
	$(TOOL) frontend
# binaries uses the checked-in/already-built embedded UI. build always rebuilds it.
binaries:
	$(TOOL) build $(BUILD_FLAGS)
build: frontend
	$(TOOL) build $(BUILD_FLAGS)
msi:
	$(TOOL) msi $(BUILD_FLAGS) -host "$(MSI_HOST)" -ssh-args "$(MSI_SSH_ARGS)" -wix "$(WIX_DIR)" -product-code "$(PRODUCT_CODE)"
package: build
	$(TOOL) msi $(BUILD_FLAGS) -host "$(MSI_HOST)" -ssh-args "$(MSI_SSH_ARGS)" -wix "$(WIX_DIR)" -product-code "$(PRODUCT_CODE)"
integration:
	$(TOOL) integration -config "$(E2E_CONFIG)"
test-e2e e2e:
	$(TOOL) e2e -config "$(E2E_CONFIG)" -evidence "$(EVIDENCE_DIR)"
clean:
	$(TOOL) clean -out "$(OUT_DIR)"

publish:
	$(TOOL) publish $(BUILD_FLAGS)
