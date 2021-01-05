.PHONY: all run
all: run

run:
	ls *.go | grep -v '_test.go' | xargs go run

enque:
	aws sqs send-message \
		--endpoint-url http://localhost:9324 \
		--queue-url http://localhost:9324/queue/aws-cloudsploit \
		--message-body '{"aws_id":1001, "aws_data_source_id":1001, "data_source":"aws:cloudsploit", "project_id":1001, "account_id":"171706544897", "assume_role_arn":"arn:aws:iam::171706544897:role/cloudsploit-test, "external_id":""}'
