FROM golang:1.24 AS builder
WORKDIR /go/src/github.com/ca-risken/aws/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/cloudsploit cmd/cloudsploit/main.go

FROM node:lts-alpine3.12 AS cloudsploit
# 2023/03/20時点で最新
ARG CLOUDSPLOIT_COMMIT_HASH=3d5f72d46e495ffcb8d9ebf44e60b6551fddbf4e
RUN apk add --no-cache ca-certificates tzdata git \
  && git clone https://github.com/aquasecurity/cloudsploit.git /opt/cloudsploit \
  && cd /opt/cloudsploit \
  && git checkout ${CLOUDSPLOIT_COMMIT_HASH}
WORKDIR /opt/cloudsploit
# CloudSploitではyarn.lockがないためコピーする（動作確認済みのバージョンを使用）
COPY dockers/cloudsploit/yarn.lock /opt/cloudsploit/
RUN yarn install --frozen-lockfile \
  && chmod +x index.js

FROM public.ecr.aws/risken/base/risken-base:v0.0.1 AS risken-base

FROM node:lts-alpine3.12
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
COPY --from=cloudsploit /opt/cloudsploit /opt/cloudsploit
COPY --from=risken-base /usr/local/bin/env-injector /usr/local/bin/
ENV DEBUG= \
  PROFILE_EXPORTER= \
  PROFILE_TYPES= \
  AWS_REGION= \
  AWS_ACCESS_KEY_ID= \
  AWS_SECRET_ACCESS_KEY= \
  AWS_SESSION_TOKEN= \
  SQS_ENDPOINT= \
  CLOUDSPLOIT_QUEUE_NAME= \
  CLOUDSPLOIT_QUEUE_URL= \
  MAX_NUMBER_OF_MESSAGE= \
  WAIT_TIME_SECOND=20 \
  FINDING_SVC_ADDR= \
  ALERT_SVC_ADDR= \
  AWS_SVC_ADDR= \
  RESULT_DIR=/tmp \
  CONFIG_DIR=/tmp \
  CLOUDSPLOIT_DIR="/opt/cloudsploit" \
  MAX_MEM_SIZE_MB= \
  TZ=Asia/Tokyo
WORKDIR /usr/local/cloudsploit
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/cloudsploit"]

