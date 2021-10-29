TARGETS = aws access-analyzer activity admin-checker cloudsploit guard-duty portscan
BUILD_TARGETS = $(TARGETS:=.build)
BUILD_CI_TARGETS = $(TARGETS:=.build-ci)
IMAGE_PUSH_TARGETS = $(TARGETS:=.push-image)
MANIFEST_CREATE_TARGETS = $(TARGETS:=.create-manifest)
MANIFEST_PUSH_TARGETS = $(TARGETS:=.push-manifest)
TEST_TARGETS = $(TARGETS:=.go-test)
LINT_TARGETS = $(TARGETS:=.lint)
BUILD_OPT=""
IMAGE_TAG=latest
MANIFEST_TAG=latest
IMAGE_PREFIX=aws
IMAGE_REGISTRY=local

.PHONY: all
all: build

.PHONY: install
install:
	brew install protobuf clang-format && \
	go get google.golang.org/grpc@v1.38.0 && \
	go get github.com/golang/protobuf@v1.5.2 && \
	go get -u github.com/golang/protobuf/protoc-gen-go && \
	go install github.com/envoyproxy/protoc-gen-validate@v0.6.1 && \
	go get github.com/grpc-ecosystem/go-grpc-middleware@latest

.PHONY: clean
clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

.PHONY: fmt
fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

.PHONY: proto-without-validate
proto-without-validate: fmt
	for svc in "aws"; do \
		protoc \
			--proto_path=proto \
			--error_format=gcc \
			--go_out=plugins=grpc,paths=source_relative:proto \
			proto/$$svc/*.proto; \
	done

# build with protoc-gen-validate``
.PHONY: proto-validate
proto-validate: fmt
	for svc in "activity"; do \
		protoc \
			--proto_path=proto \
			--error_format=gcc \
			-I $(shell go env GOPATH)/pkg/mod/github.com/envoyproxy/protoc-gen-validate@v0.6.1 \
			--go_out=plugins=grpc,paths=source_relative:proto \
			--validate_out="lang=go,paths=source_relative:proto" \
			proto/$$svc/*.proto; \
	done

.PHONY: proto
proto : proto-without-validate proto-validate

.PHONY: build
build: $(BUILD_TARGETS)
%.build: %.go-test
	. env.sh && TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh

.PHONY: build-ci
build-ci: $(BUILD_CI_TARGETS)
%.build-ci: FAKE
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh
	docker tag $(IMAGE_PREFIX)/$(*):$(IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

.PHONY: push-image
push-image: $(IMAGE_PUSH_TARGETS)
%.push-image: FAKE
	docker push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

.PHONY: create-manifest
create-manifest: $(MANIFEST_CREATE_TARGETS)
%.create-manifest: FAKE
	docker manifest create $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_amd64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_arm64
	docker manifest annotate --arch amd64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_amd64
	docker manifest annotate --arch arm64 $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG_BASE)_linux_arm64

.PHONY: push-manifest
push-manifest: $(MANIFEST_PUSH_TARGETS)
%.push-manifest: FAKE
	docker manifest push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG)
	docker manifest inspect $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(MANIFEST_TAG)

.PHONY: go-test proto-test pkg-test
go-test: $(TEST_TARGETS) proto-test pkg-test
%.go-test: FAKE
	cd src/$(*) && go test ./...
proto-test:
	cd proto/aws           && go test ./...
pkg-test:
	cd pkg/message         && go test ./...
	cd pkg/common          && go test ./...

.PHONY: go-mod-update
go-mod-update:
	cd src/aws \
		&& go get -u \
			github.com/ca-risken/aws/...
	cd src/guard-duty \
		&& go get -u \
			github.com/ca-risken/core/... \
			github.com/ca-risken/aws/...
	cd src/access-analyzer \
		&& go get -u \
			github.com/ca-risken/core/... \
			github.com/ca-risken/aws/...
	cd src/admin-checker \
		&& go get -u \
			github.com/ca-risken/core/... \
			github.com/ca-risken/aws/...
	cd src/cloudsploit \
		&& go get -u \
			github.com/ca-risken/core/... \
			github.com/ca-risken/aws/...
	cd src/portscan \
		&& go get -u \
			github.com/ca-risken/common/... \
			github.com/ca-risken/core/... \
			github.com/ca-risken/aws/...
	cd src/activity \
		&& go get -u \
			github.com/ca-risken/core/... \
			github.com/ca-risken/aws/...

.PHONY: go-mod-tidy
go-mod-tidy:
	cd proto/aws           && go mod tidy
	cd pkg/model           && go mod tidy
	cd pkg/message         && go mod tidy
	cd pkg/common          && go mod tidy
	cd src/aws             && go mod tidy
	cd src/guard-duty      && go mod tidy
	cd src/access-analyzer && go mod tidy
	cd src/admin-checker   && go mod tidy
	cd src/cloudsploit     && go mod tidy
	cd src/portscan        && go mod tidy
	cd src/activity        && go mod tidy

.PHONY: lint proto-lint pkg-lint
lint: $(LINT_TARGETS) proto-lint pkg-lint
%.lint: FAKE
	sh hack/golinter.sh src/$(*)
proto-lint:
	sh hack/golinter.sh proto/activity
	sh hack/golinter.sh proto/aws
pkg-lint:
	sh hack/golinter.sh pkg/common
	sh hack/golinter.sh pkg/message
	sh hack/golinter.sh pkg/model

FAKE: