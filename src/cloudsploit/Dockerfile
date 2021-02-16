FROM golang AS builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-aws/src/cloudsploit/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GO111MODULE=on GOPRIVATE="github.com/CyberAgent/*"
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go install -v

FROM node:lts-alpine3.12
RUN apk add --no-cache ca-certificates tzdata git \
  && cd /tmp/ && wget -q https://github.com/gassara-kys/env-injector/releases/download/v0.0.6/env-injector_0.0.6_Linux_x86_64.tar.gz \
  && tar xvfz env-injector_0.0.6_Linux_x86_64.tar.gz && mv env-injector /usr/local/bin/ && rm -rf /tmp/* \
  && cd /opt && git clone https://github.com/aquasecurity/cloudsploit.git -b v2.0.0 --depth 1  \
  && mkdir /results && mkdir /configs \
  && cd cloudsploit && yarn install
COPY --from=builder /go/bin/cloudsploit /usr/local/cloudsploit/bin/
ENV DEBUG= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    SQS_ENDPOINT= \
    CLOUDSPLOIT_QUEUE_NAME= \
    CLOUDSPLOIT_QUEUE_URL= \
    MAX_NUMBER_OF_MESSAGE=10 \
    WAIT_TIME_SECOND=20 \
    FINDING_SVC_ADDR= \
    ALERT_SVC_ADDR= \
    AWS_SVC_ADDR= \
    RESULT_DIR=/results \
    CONFIG_DIR=/configs \
    CLOUDSPLOIT_DIR="/opt/cloudsploit" \
    TZ=Asia/Tokyo
WORKDIR /usr/local/cloudsploit
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/cloudsploit"]

