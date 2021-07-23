FROM golang AS builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-aws/src/aws/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GO111MODULE=on GOPRIVATE="github.com/CyberAgent/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go install -v

FROM alpine
RUN apk add --no-cache ca-certificates tzdata \
  && cd /tmp/ && wget -q https://github.com/gassara-kys/env-injector/releases/download/v0.0.6/env-injector_0.0.6_Linux_x86_64.tar.gz \
  && tar xvfz env-injector_0.0.6_Linux_x86_64.tar.gz && mv env-injector /usr/local/bin/ && rm -rf /tmp/*
COPY --from=builder /go/bin/aws /usr/local/aws/bin/
ENV PORT= \
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
