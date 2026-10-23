GO := go
export GOTOOLCHAIN := go1.27.2
IMAGE ?= registry.cn-hangzhou.aliyuncs.com/0x0034/sentinel
VERSION ?= 0.2.0-rc.4

.PHONY: fmt check test build image push
fmt:
	$(GO) fmt ./...
check:
	test -z "$$($(GO) fmt ./...)"
	$(GO) vet ./...
test:
	$(GO) test -race ./...
build:
	$(GO) build -trimpath -ldflags="-X main.version=$(VERSION)" -o bin/sentinel ./cmd/sentinel
image:
	docker buildx build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) --load .
push:
	docker push $(IMAGE):$(VERSION)
