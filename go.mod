module github.com/ca-risken/aws

go 1.18

require (
	github.com/aws/aws-sdk-go-v2 v1.19.1
	github.com/aws/aws-sdk-go-v2/config v1.18.21
	github.com/aws/aws-sdk-go-v2/credentials v1.13.20
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.17.2
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.16.15
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.13.16
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.93.2
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.14.22
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.18.25
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.16.2
	github.com/aws/aws-sdk-go-v2/service/iam v1.18.23
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.24.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.30.0
	github.com/aws/aws-sdk-go-v2/service/sqs v1.20.8
	github.com/aws/aws-sdk-go-v2/service/sts v1.18.9
	github.com/ca-risken/common/pkg/logging v0.0.0-20220601065422-5b97bd6efc9b
	github.com/ca-risken/common/pkg/portscan v0.0.0-20230501023912-29382763676f
	github.com/ca-risken/common/pkg/profiler v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/sqs v0.0.0-20221119073224-9db027bda6f8
	github.com/ca-risken/common/pkg/tracer v0.0.0-20230727031236-b35703d5c59d
	github.com/ca-risken/core v0.8.1-0.20230713062340-970d2ea94bf3
	github.com/ca-risken/datasource-api v0.5.1-0.20230317093856-4d9fbbe1735a
	github.com/ca-risken/go-sqs-poller/worker/v5 v5.0.0-20220525093235-9148d33b6aee
	github.com/gassara-kys/envconfig v1.4.4
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/sync v0.1.0
	google.golang.org/grpc v1.54.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.52.0
)

require (
	github.com/DataDog/appsec-internal-go v1.0.0 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.45.0-rc.1 // indirect
	github.com/DataDog/datadog-agent/pkg/remoteconfig/state v0.45.0 // indirect
	github.com/DataDog/datadog-go/v5 v5.1.1 // indirect
	github.com/DataDog/go-libddwaf v1.2.0 // indirect
	github.com/DataDog/go-tuf v0.3.0--fix-localmeta-fork // indirect
	github.com/DataDog/gostackparse v0.5.0 // indirect
	github.com/DataDog/sketches-go v1.2.1 // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/Ullaakut/nmap v2.0.2+incompatible // indirect
	github.com/Ullaakut/nmap/v2 v2.1.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.14.8 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/pprof v0.0.0-20230509042627-b1315fad0c5a // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/outcaste-io/ristretto v0.2.1 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/richardartoul/molecule v1.0.1-0.20221107223329-32cfee06a052 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.6.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spaolacci/murmur3 v0.0.0-20180118202830-f09979ecbc72 // indirect
	github.com/tinylib/msgp v1.1.6 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go4.org/intern v0.0.0-20211027215823-ae77deb06f29 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20220617031537-928513b29760 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	inet.af/netaddr v0.0.0-20220811202034-502d2d690317 // indirect
)
