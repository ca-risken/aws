.PHONY: all install clean network fmt build doc
all: run

install:
	go get \
		google.golang.org/grpc \
		github.com/golang/protobuf/protoc-gen-go \
		github.com/grpc-ecosystem/go-grpc-middleware

clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

# @see https://github.com/CyberAgent/mimosa-common/tree/master/local
network:
	@if [ -z "`docker network ls | grep local-shared`" ]; then docker network create local-shared; fi

fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

doc: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--doc_out=markdown,README.md:doc \
		proto/**/*.proto;

build: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		--go_out=plugins=grpc,paths=source_relative:proto \
		proto/**/*.proto;

go-test: build
	cd proto/aws      && go test ./...
	cd pkg/message    && go test ./...
	cd src/aws        && go test ./...
	cd src/guard-duty && go test ./...

go-mod-update:
	cd src/aws \
		&& go get -u \
			github.com/CyberAgent/mimosa-aws/...
	cd src/guard-duty \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-aws/...

go-mod-tidy: build
	cd proto/aws      && go mod tidy
	cd pkg/model      && go mod tidy
	cd pkg/message    && go mod tidy
	cd src/aws        && go mod tidy
	cd src/guard-duty && go mod tidy

# @see https://github.com/CyberAgent/mimosa-common/tree/master/local
network:
	@if [ -z "`docker network ls | grep local-shared`" ]; then docker network create local-shared; fi

run: go-test network
	. env.sh && docker-compose up -d --build

log:
	. env.sh && docker-compose logs -f

stop:
	. env.sh && docker-compose down
