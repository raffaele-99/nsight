BINARY_NAME=nsight
BINARY_PATH=./bin/$(BINARY_NAME)
SOURCE_DIR=./src
GO_FILES=$(SOURCE_DIR)/*.go

.PHONY: all build clean install run-example

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	@go build -o $(BINARY_PATH) $(GO_FILES)
	@echo "Build complete: $(BINARY_PATH)"

clean:
	@echo "Cleaning..."
	@rm -rf bin
	@go clean

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BINARY_PATH) /usr/local/bin/$(BINARY_NAME)
	@echo "Installation complete"

run-example: build
	@echo "Running example..."
	@$(BINARY_PATH) -h

# Development helpers
fmt:
	@echo "Formatting code..."
	@go fmt $(SOURCE_DIR)/...

vet:
	@echo "Running go vet..."
	@go vet $(SOURCE_DIR)/...

lint: fmt vet
	@echo "Linting complete"
