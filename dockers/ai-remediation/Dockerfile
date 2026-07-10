FROM golang:1.24 AS builder
WORKDIR /go/src/github.com/ca-risken/aws/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/ai-remediation cmd/ai-remediation/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/ai-remediation /usr/local/ai-remediation/bin/
ENV DEBUG= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    AI_REMEDIATION_QUEUE_NAME= \
    AI_REMEDIATION_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    TZ=Asia/Tokyo
WORKDIR /usr/local/ai-remediation
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/ai-remediation"]
