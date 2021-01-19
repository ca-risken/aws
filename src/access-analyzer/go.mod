module github.com/CyberAgent/mimosa-aws/src/access-analyzer

go 1.15

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20210114025109-44874eb514e0
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20210114025109-44874eb514e0
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20210114025109-44874eb514e0
	github.com/CyberAgent/mimosa-core/proto/alert v0.0.0-20210108063741-eceb6a32f58c
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20210108063741-eceb6a32f58c
	github.com/aws/aws-sdk-go v1.36.26
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/h2ik/go-sqs-poller/v3 v3.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210113195801-ae06605f4595 // indirect
	google.golang.org/grpc v1.35.0
)