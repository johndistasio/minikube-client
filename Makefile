GIT_REVISION = $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: default
default: build

.PHONY: build
build:
	go build -ldflags "-X 'main.revision=$(GIT_REVISION)'"

.PHONY: install
install:
	install minikube-client /usr/local/bin/minikube-client
