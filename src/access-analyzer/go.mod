module github.com/CyberAgent/mimosa-aws/src/access-analyzer

go 1.15

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20201023104052-00aa993c37ec
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20201023104052-00aa993c37ec
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20201023104052-00aa993c37ec
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20201023041025-fbc9ccc91389
	github.com/aws/aws-sdk-go v1.35.13
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/h2ik/go-sqs-poller/v3 v3.0.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20201022231255-08b38378de70 // indirect
	golang.org/x/sys v0.0.0-20201022201747-fb209a7c41cd // indirect
	google.golang.org/genproto v0.0.0-20201022181438-0ff5f38871d5 // indirect
	google.golang.org/grpc v1.33.1
	google.golang.org/protobuf v1.25.0 // indirect
)
