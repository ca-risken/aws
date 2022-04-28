FROM golang:1.17 as builder
WORKDIR /go/src/github.com/ca-risken/aws/src/activity/
ADD *.go go.* ./
ENV CGO_ENABLED=0
ARG GITHUB_USER
ARG GITHUB_TOKEN
RUN echo "machine github.com" > ~/.netrc
RUN echo "login $GITHUB_USER" >> ~/.netrc
RUN echo "password $GITHUB_TOKEN" >> ~/.netrc
RUN go build && cp activity /go/bin/

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
