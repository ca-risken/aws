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
export MAX_NUMBER_OF_MESSAGE="5"
export SQS_ENDPOINT="http://sqs:9324"
export GUARD_DUTY_QUEUE_NAME="aws-guardduty"
export GUARD_DUTY_QUEUE_URL="http://sqs:9324/queue/aws-guardduty"
export ACCESS_ANALYZER_QUEUE_NAME="aws-accessanalyzer"
export ACCESS_ANALYZER_QUEUE_URL="http://sqs:9324/queue/aws-accessanalyzer"
export ADMIN_CHECKER_QUEUE_NAME="aws-adminchecker"
export ADMIN_CHECKER_QUEUE_URL="http://sqs:9324/queue/aws-adminchecker"
export CLOUDSPLOIT_QUEUE_NAME="aws-cloudsploit"
export CLOUDSPLOIT_QUEUE_URL="http://sqs:9324/queue/aws-cloudsploit"

# gRPC server
export FINDING_SVC_ADDR="finding:8001"
export ALERT_SVC_ADDR="alert:8004"
export AWS_SVC_ADDR="aws:9001"

# cloudsploit (for local)
export RESULT_DIR="/results"
export CONFIG_DIR="/configs"
export CLOUDSPLOIT_DIR="/opt/cloudsploit/"

# portscan
export SCAN_EXCLUDE_PORT_NUMBER="100"