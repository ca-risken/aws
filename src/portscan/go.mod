module github.com/CyberAgent/mimosa-aws/src/portscan

go 1.15

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20210518111940-64531f94e9b8
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20210518111940-64531f94e9b8
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20210518111940-64531f94e9b8
	github.com/CyberAgent/mimosa-common/pkg/portscan v0.0.0-20210514095718-ed8d6d67c6d5
	github.com/CyberAgent/mimosa-core/proto/alert v0.0.0-20210430051641-778e594322c3
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20210430051641-778e594322c3
	github.com/Ullaakut/nmap/v2 v2.1.1
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go v1.38.41
	github.com/gassara-kys/go-sqs-poller/worker/v4 v4.0.0-20210215110542-0be358599a2f
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/h2ik/go-sqs-poller/v3 v3.1.1
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.8.1
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20210510120150-4163338589ed // indirect
	golang.org/x/sys v0.0.0-20210514084401-e8d321eab015 // indirect
	google.golang.org/genproto v0.0.0-20210517163617-5e0236093d7a // indirect
	google.golang.org/grpc v1.37.1
)
