TARGETS = access-analyzer admin-checker cloudsploit guard-duty portscan
BUILD_TARGETS = $(TARGETS:=.build)
BUILD_CI_TARGETS = $(TARGETS:=.build-ci)
IMAGE_PUSH_TARGETS = $(TARGETS:=.push-image)
IMAGE_PULL_TARGETS = $(TARGETS:=.pull-image)
IMAGE_TAG_TARGETS = $(TARGETS:=.tag-image)
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

.PHONY: build
build: $(BUILD_TARGETS)
%.build: go-test
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh

.PHONY: build-ci
build-ci: $(BUILD_CI_TARGETS)
%.build-ci: FAKE
	TARGET=$(*) IMAGE_TAG=$(IMAGE_TAG) IMAGE_PREFIX=$(IMAGE_PREFIX) BUILD_OPT="$(BUILD_OPT)" . hack/docker-build.sh
	docker tag $(IMAGE_PREFIX)/$(*):$(IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

.PHONY: push-image
push-image: $(IMAGE_PUSH_TARGETS)
%.push-image: FAKE
	docker push $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: pull-image $(IMAGE_PULL_TARGETS)
pull-image: $(IMAGE_PULL_TARGETS)
%.pull-image:
	docker pull $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

PHONY: tag-image $(IMAGE_TAG_TARGETS)
tag-image: $(IMAGE_TAG_TARGETS)
%.tag-image:
	docker tag $(SOURCE_IMAGE_PREFIX)/$(*):$(SOURCE_IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_PREFIX)/$(*):$(IMAGE_TAG)

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

.PHONY: generate
generate:
	go generate ./...

.PHONY: go-test
go-test: generate
	GO111MODULE=on go test ./...

.PHONY: lint
lint:
	GO111MODULE=on GOFLAGS=-buildvcs=false golangci-lint run --timeout 5m

.PHONY: enqueue-accessanalyzer
enqueue-accessanalyzer:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-accessanalyzer \
		--message-body '{"aws_id":1001, "aws_data_source_id":1002, "data_source":"aws:access-analyzer", "project_id":1001, "account_id":"315855282677", "assume_role_arn":"arn:aws:iam::315855282677:role/stg-security-monitor", "external_id":""}'

.PHONY: enqueue-adminchecker
enqueue-adminchecker:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-adminchecker \
		--message-body '{"aws_id":1001, "aws_data_source_id":1003, "data_source":"aws:admin-checker", "project_id":1001, "account_id":"315855282677", "assume_role_arn":"arn:aws:iam::315855282677:role/stg-security-monitor", "external_id":""}'

.PHONY: enqueue-cloudsploit
enqueue-cloudsploit:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-cloudsploit \
		--message-body '{"aws_id":1001, "aws_data_source_id":1001, "data_source":"aws:cloudsploit", "project_id":1001, "account_id":"171706544897", "assume_role_arn":"arn:aws:iam::171706544897:role/cloudsploit-test, "external_id":""}'

.PHONY: enqueue-guardduty
enqueue-guardduty:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-guardduty \
		--message-body '{"aws_id":1001, "aws_data_source_id":1001, "data_source":"aws:guard-duty", "project_id":1001, "account_id":"315855282677", "assume_role_arn":"arn:aws:iam::315855282677:role/stg-security-monitor", "external_id":""}'

.PHONY: enqueue-portscan
enqueue-portscan:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-portscan \
		--message-body '{"aws_id":1001, "aws_data_source_id":1005, "data_source":"aws:portscan", "project_id":1001, "account_id":"315855282677", "assume_role_arn":"arn:aws:iam::315855282677:role/stg-security-monitor", "external_id":""}'

FAKE: