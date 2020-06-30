FROM golang AS builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-aws/src/guard-duty/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GO111MODULE=on GOPRIVATE="github.com/CyberAgent/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go install -v

FROM alpine
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /go/bin/guard-duty /usr/local/guard-duty/bin/
ENV AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    GUARD_DUTY_QUEUE_NAME= \
    GUARD_DUTY_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE=10 \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/guard-duty
CMD ["bin/guard-duty"]
