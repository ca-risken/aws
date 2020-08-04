#!/bin/bash -e

# github
export GITHUB_USER="your-name"
export GITHUB_TOKEN="your-token"

# GO
export GOPRIVATE="github.com/CyberAgent/*"

# DB
export DB_MASTER_HOST="db"
export DB_MASTER_USER="hoge"
export DB_MASTER_PASSWORD="moge"
export DB_SLAVE_HOST="db"
export DB_SLAVE_USER="hoge"
export DB_SLAVE_PASSWORD="moge"
export DB_LOG_MODE="false"

# AWS
export AWS_REGION="ap-northeast-1"
export SQS_ENDPOINT="http://sqs:9324"
export GUARD_DUTY_QUEUE_NAME="aws-guardduty"
export GUARD_DUTY_QUEUE_URL="http://sqs:9324/queue/aws-guardduty"

# gRPC server
export FINDING_SVC_ADDR="finding:8001"
