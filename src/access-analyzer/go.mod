module github.com/CyberAgent/mimosa-aws/src/access-analyzer

go 1.15

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20210126093719-e0c2d78c64c2
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20210126093719-e0c2d78c64c2
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20210126093719-e0c2d78c64c2
	github.com/CyberAgent/mimosa-core/proto/alert v0.0.0-20210108063741-eceb6a32f58c
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20210108063741-eceb6a32f58c
	github.com/aws/aws-sdk-go v1.36.31
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/h2ik/go-sqs-poller/v3 v3.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210125195502-f46fe6c6624a // indirect
	google.golang.org/grpc v1.35.0
)
