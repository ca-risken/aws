FROM golang:1.16 as builder
WORKDIR /go/src/github.com/ca-risken/aws/src/cloudsploit/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/CyberAgent/*,github.com/ca-risken/*"
ARG ENV_INJECTOR_VERSION=v0.0.6
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp cloudsploit /go/bin/

WORKDIR /go/src/github.com/gassara-kys
RUN git clone https://github.com/gassara-kys/env-injector.git -b ${ENV_INJECTOR_VERSION} \
  && cd env-injector \
  && go build \
  && cp env-injector /go/bin/

FROM node:lts-alpine3.12
RUN apk add --no-cache ca-certificates tzdata git \
  && cd /opt && git clone https://github.com/aquasecurity/cloudsploit.git -b v2.0.0 --depth 1  \
  && cd cloudsploit && yarn install
COPY --from=builder /go/bin/env-injector /usr/local/bin/
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
ENV DEBUG= \
  AWS_REGION= \
  AWS_ACCESS_KEY_ID= \
  AWS_SECRET_ACCESS_KEY= \
  AWS_SESSION_TOKEN= \
  SQS_ENDPOINT= \
  CLOUDSPLOIT_QUEUE_NAME= \
  CLOUDSPLOIT_QUEUE_URL= \
  MAX_NUMBER_OF_MESSAGE=5 \
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

