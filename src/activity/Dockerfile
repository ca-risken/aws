FROM golang:1.16 as builder
WORKDIR /go/src/github.com/CyberAgent/mimosa-aws/src/activity/
ADD *.go go.* ./
ENV CGO_ENABLED=0 GOPRIVATE="github.com/CyberAgent/*,github.com/ca-risken/*"
ARG ENV_INJECTOR_VERSION=v0.0.6
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp activity /go/bin/

WORKDIR /go/src/github.com/gassara-kys
RUN git clone https://github.com/gassara-kys/env-injector.git -b ${ENV_INJECTOR_VERSION} \
    && cd env-injector \
    && go build \
    && cp env-injector /go/bin/

FROM alpine
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /go/bin/env-injector /usr/local/bin/
COPY --from=builder /go/bin/activity /usr/local/activity/bin/
ENV PORT= \
    AWS_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    AWS_SESSION_TOKEN= \
    AWS_SVC_ADDR= \
    AWS_XRAY_SDK_DISABLED=TRUE \
    AWS_XRAY_CONTEXT_MISSING=LOG_ERROR \
    TZ=Asia/Tokyo
WORKDIR /usr/local/activity
ENTRYPOINT ["/usr/local/bin/env-injector"]
CMD ["bin/activity"]
