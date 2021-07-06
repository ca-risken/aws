module github.com/CyberAgent/mimosa-aws/src/guard-duty

go 1.16

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20210705090541-72660ab20a71
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20210705090541-72660ab20a71
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20210705090541-72660ab20a71
	github.com/CyberAgent/mimosa-core/proto/alert v0.0.0-20210705055753-70c971de88be
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20210705055753-70c971de88be
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go v1.39.0
	github.com/gassara-kys/go-sqs-poller/worker/v4 v4.0.0-20210215110542-0be358599a2f
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.8.1
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	google.golang.org/genproto v0.0.0-20210701191553-46259e63a0a9 // indirect
	google.golang.org/grpc v1.39.0
)
