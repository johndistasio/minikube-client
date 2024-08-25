GIT_REVISION = $(shell git rev-parse HEAD 2>/dev/null)

.PHONY: default
default:
	go build -ldflags "-X 'main.revision=$(GIT_REVISION)'"
