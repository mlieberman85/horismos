# Project configuration.
PROJECT_NAME = horismos
#General
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
# Docker.
TAG ?= 10m
DOCKERFILE = Dockerfile
DOCKER_ORG = ttl.sh
DOCKER_REPO = $(DOCKER_ORG)/$(PROJECT_NAME)
DOCKER_IMG = $(DOCKER_REPO):$(TAG)

.PHONY: build
build: modules ## go build the package
	@mkdir -p bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
	-o ./bin/horismos

.PHONY: modules
modules: ## go mod tidy
	@go mod tidy

.PHONY: clean
clean: ## Clean up bin folder
	@rm -rf ./bin

.PHONY: docker-build
docker-build: ## Build the docker image. Specifiy -u <github username> to store in ghrc.io/<github username> 
	@DOCKER_BUILDKIT=1 docker build -t $(DOCKER_IMG) -f $(DOCKERFILE) .
	@docker push $(DOCKER_IMG)

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort