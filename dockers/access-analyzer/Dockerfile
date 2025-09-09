FROM golang:1.24 AS builder
WORKDIR /go/src/github.com/ca-risken/aws/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/access-analyzer cmd/access-analyzer/main.go

FROM python:3.12-slim
RUN apt-get update && apt-get install -y git ffmpeg libsm6 libxext6 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN git clone --depth 1 --branch v-0.3.37 --single-branch https://github.com/rohitcoder/hawk-eye.git
WORKDIR /app/hawk-eye
RUN pip3 install -r requirements.txt
RUN pip3 install .
COPY --from=public.ecr.aws/risken/base/risken-base:v0.0.1 /usr/local/bin/env-injector /usr/local/bin/env-injector
RUN chmod +x /usr/local/bin/env-injector
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
