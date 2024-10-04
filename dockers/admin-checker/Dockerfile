FROM golang:1.21.3 AS builder
WORKDIR /go/src/github.com/ca-risken/aws/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/admin-checker cmd/admin-checker/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/admin-checker /usr/local/admin-checker/bin/
ENV DEBUG= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    ADMIN_CHECKER_QUEUE_NAME= \
    ADMIN_CHECKER_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    AWS_SVC_ADDR= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/admin-checker
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/admin-checker"]
