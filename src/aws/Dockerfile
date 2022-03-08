FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/aws/src/aws/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/ca-risken/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp aws /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/aws /usr/local/aws/bin/
ENV PORT= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    DB_MASTER_HOST= \
    DB_MASTER_USER= \
    DB_MASTER_PASSWORD= \
    DB_SLAVE_HOST= \
    DB_SLAVE_USER= \
    DB_SLAVE_PASSWORD= \
    DB_SCHEMA=mimosa \
    DB_PORT=3306 \
    DB_LOG_MODE=false \
    IAM_SVC_ADDR= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    AWS_XRAY_SDK_DISABLED=TRUE \
    AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
    SQS_ENDPOINT= \
    GUARD_DUTY_QUEUE_URL= \
    ACCESS_ANALYZER_QUEUE_URL= \
    ADMIN_CHECKER_QUEUE_URL= \
    CLOUDSPLOIT_QUEUE_URL= \
    PORTSCAN_QUEUE_URL= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/aws
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/aws"]
