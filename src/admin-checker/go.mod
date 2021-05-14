module github.com/CyberAgent/mimosa-aws/src/admin-checker

go 1.16

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20210513125830-6ca7eee6d00d
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20210513125830-6ca7eee6d00d
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20210513125830-6ca7eee6d00d
	github.com/CyberAgent/mimosa-core/proto/alert v0.0.0-20210430051641-778e594322c3
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20210430051641-778e594322c3
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go v1.38.39
	github.com/gassara-kys/go-sqs-poller/worker/v4 v4.0.0-20210215110542-0be358599a2f
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/magefile/mage v1.11.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20210510120150-4163338589ed // indirect
	golang.org/x/sys v0.0.0-20210511113859-b0526f3d8744 // indirect
	google.golang.org/genproto v0.0.0-20210510173355-fb37daa5cd7a // indirect
	google.golang.org/grpc v1.37.1
)
