FROM golang:1.18.2 as builder
WORKDIR /go/src/github.com/ca-risken/aws/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/cloudsploit cmd/cloudsploit/main.go

FROM public.ecr.aws/risken/base/cloudsploit-base:v0.0.1
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
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

