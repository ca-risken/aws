FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/aws/src/cloudsploit/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/ca-risken/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp cloudsploit /go/bin/

FROM public.ecr.aws/risken/base/cloudsploit-base:v0.0.1
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
ENV DEBUG= \
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
  AWS_XRAY_SDK_DISABLED=TRUE \
  AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
  RESULT_DIR=/tmp \
  CONFIG_DIR=/tmp \
  CLOUDSPLOIT_DIR="/opt/cloudsploit" \
  TZ=Asia/Tokyo
WORKDIR /usr/local/cloudsploit
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/cloudsploit"]

