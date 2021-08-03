module github.com/CyberAgent/mimosa-aws/src/aws

go 1.16

require (
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20210706052009-c1f53ecf5540
	github.com/CyberAgent/mimosa-aws/pkg/model v0.0.0-20210706052009-c1f53ecf5540
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20210706052009-c1f53ecf5540
	github.com/CyberAgent/mimosa-common/pkg/database v0.0.0-20210721063343-44cefe7f590e
	github.com/CyberAgent/mimosa-common/pkg/xray v0.0.0-20210803120909-2cc57e3c75d2
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go v1.39.3
	github.com/aws/aws-xray-sdk-go v1.6.0
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	google.golang.org/genproto v0.0.0-20210701191553-46259e63a0a9 // indirect
	google.golang.org/grpc v1.39.0
	gorm.io/gorm v1.21.12
)
