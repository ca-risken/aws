####################################################
## grpcurl example
####################################################
.PHONY: all
all: help

.PHONY: help
help:
	@echo "Usage: make <sub-command>"
	@echo "\n---------------- sub-command list ----------------"
	@cat Makefile | grep -e "^.PHONY:" | grep -v "all" | cut -f2 -d' '

.PHONY: list-service
list-service:
	grpcurl -plaintext localhost:9001 list aws.aws.AWSService

.PHONY: list-aws
list-aws:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "aws_id":1001, "aws_account_id":"123456789012"}' \
		localhost:9001 aws.aws.AWSService.ListAWS
