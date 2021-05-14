.PHONY: all install clean network fmt build doc
all: run

install:
	go get \
		google.golang.org/grpc \
		github.com/golang/protobuf/protoc-gen-go \
		github.com/envoyproxy/protoc-gen-validate \
		github.com/grpc-ecosystem/go-grpc-middleware

clean:
	rm -f proto/**/*.pb.go
	rm -f doc/*.md

fmt: proto/**/*.proto
	clang-format -i proto/**/*.proto

doc: fmt
	protoc \
		--proto_path=proto \
		--error_format=gcc \
		-I $(GOPATH)/src/github.com/envoyproxy/protoc-gen-validate \
		--doc_out=markdown,README.md:doc \
		proto/**/*.proto;

build-without-validate: fmt doc
	for svc in "aws"; do \
		protoc \
			--proto_path=proto \
			--error_format=gcc \
			--go_out=plugins=grpc,paths=source_relative:proto \
			proto/$$svc/*.proto; \
	done

# build with protoc-gen-validate
build-validate: fmt doc
	for svc in "activity"; do \
		protoc \
			--proto_path=proto \
			--error_format=gcc \
			-I $(GOPATH)/src/github.com/envoyproxy/protoc-gen-validate \
			--go_out=plugins=grpc,paths=source_relative:proto \
			--validate_out="lang=go,paths=source_relative:proto" \
			proto/$$svc/*.proto; \
	done

build : build-without-validate build-validate

go-test: build build-validate
	cd proto/aws           && go test ./...
	cd pkg/message         && go test ./...
	cd src/aws             && go test ./...
	cd src/guard-duty      && go test ./...
	cd src/access-analyzer && go test ./...
	cd src/admin-checker   && go test ./...
	cd src/cloudsploit     && go test ./...
	cd src/portscan        && go test ./...
	cd src/activity        && go test ./...

go-mod-update:
	cd src/aws \
		&& go get -u \
			github.com/CyberAgent/mimosa-aws/...
	cd src/guard-duty \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-aws/...
	cd src/access-analyzer \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-aws/...
	cd src/admin-checker \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-aws/...
	cd src/cloudsploit \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-aws/...
	cd src/activity \
		&& go get -u \
			github.com/CyberAgent/mimosa-core/... \
			github.com/CyberAgent/mimosa-aws/...

go-mod-tidy: build build-validate
	cd proto/aws           && go mod tidy
	cd pkg/model           && go mod tidy
	cd pkg/message         && go mod tidy
	cd src/aws             && go mod tidy
	cd src/guard-duty      && go mod tidy
	cd src/access-analyzer && go mod tidy
	cd src/admin-checker   && go mod tidy
	cd src/cloudsploit     && go mod tidy
	cd src/activity        && go mod tidy

# @see https://github.com/CyberAgent/mimosa-common/tree/master/local
network:
	@if [ -z "`docker network ls | grep local-shared`" ]; then docker network create local-shared; fi

run: go-test network
	source env.sh && docker-compose up -d --build --remove-orphans

log:
	source env.sh && docker-compose logs -f

log-activity:
	source env.sh && docker-compose logs -f activity

stop:
	source env.sh && docker-compose down
