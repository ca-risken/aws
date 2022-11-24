FROM golang:1.18.2 as builder
WORKDIR /go/src/github.com/ca-risken/aws/
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /go/bin/activity cmd/activity/main.go

FROM public.ecr.aws/risken/base/risken-base:v0.0.1
COPY --from=builder /go/bin/activity /usr/local/activity/bin/
ENV PORT= \
    PROFILE_EXPORTER= \
    PROFILE_TYPES= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    AWS_SVC_ADDR= \
    TZ=Asia/Tokyo
WORKDIR /usr/local/activity
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/activity"]
