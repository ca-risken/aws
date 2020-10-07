module github.com/CyberAgent/mimosa-aws/src/guard-duty

go 1.15

require (
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20201007032440-b9bc0282692b
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20201007032440-b9bc0282692b
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20200623023542-66ab3af089f9
	github.com/aws/aws-sdk-go v1.32.9
	github.com/go-ozzo/ozzo-validation/v4 v4.2.2 // indirect
	github.com/h2ik/go-sqs-poller/v3 v3.0.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.6.0
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20201006153459-a7d1128ccaa0 // indirect
	golang.org/x/sys v0.0.0-20201006155630-ac719f4daadf // indirect
	google.golang.org/genproto v0.0.0-20201006033701-bcad7cf615f2 // indirect
	google.golang.org/grpc v1.32.0
	google.golang.org/protobuf v1.25.0 // indirect
)
