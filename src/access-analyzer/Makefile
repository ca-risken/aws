.PHONY: all run
all: run

run:
	ls *.go | grep -v '_test.go' | xargs go run

enque:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-accessanalyzer \
		--message-body '{"aws_id":1001, "aws_data_source_id":1002, "data_source":"aws:access-analyzer", "project_id":1001, "account_id":"315855282677", "assume_role_arn":"arn:aws:iam::315855282677:role/stg-security-monitor", "external_id":""}'
