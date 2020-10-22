module github.com/CyberAgent/mimosa-aws/src/guard-duty

go 1.15

require (
	github.com/CyberAgent/mimosa-aws/pkg/common v0.0.0-20201022012521-19fba454bd59
	github.com/CyberAgent/mimosa-aws/pkg/message v0.0.0-20201022012521-19fba454bd59
	github.com/CyberAgent/mimosa-aws/proto/aws v0.0.0-20201022012521-19fba454bd59
	github.com/CyberAgent/mimosa-core/proto/finding v0.0.0-20201021085603-c08821e12af9
	github.com/aws/aws-sdk-go v1.35.12
	github.com/h2ik/go-sqs-poller/v3 v3.0.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sirupsen/logrus v1.7.0
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	google.golang.org/grpc v1.33.1
)
