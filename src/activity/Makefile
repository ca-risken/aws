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
	grpcurl -plaintext localhost:9007 list aws.activity.ActivityService

.PHONY: list-cloudtrail
list-cloudtrail:
	grpcurl \
		-plaintext \
		-d '{"project_id":1001, "aws_id":1002, "region":"ap-northeast-1", "start_time":1614524400, "end_time":1618823464, "attribute_key":3, "attribute_value":"4f26eb67-a8b3-4c55-8955-52d81b65c690"}' \
		localhost:9007 aws.activity.ActivityService.ListCloudTrail

