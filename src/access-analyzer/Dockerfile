FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/aws/src/access-analyzer/
ADD *.go go.* ./
ENV CGO_ENABLED=0
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp access-analyzer /go/bin/

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/access-analyzer /usr/local/access-analyzer/bin/
ENV DEBUG= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    ACCESS_ANALYZER_QUEUE_NAME= \
    ACCESS_ANALYZER_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE= \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    AWS_SVC_ADDR= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/access-analyzer
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/access-analyzer"]
