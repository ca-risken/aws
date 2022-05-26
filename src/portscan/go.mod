module github.com/ca-risken/aws/src/portscan

go 1.17

require (
	github.com/aws/aws-sdk-go-v2 v1.16.4
	github.com/aws/aws-sdk-go-v2/config v1.15.4
	github.com/aws/aws-sdk-go-v2/credentials v1.12.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.36.1
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.14.4
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.18.4
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.20.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.20.1
	github.com/aws/aws-sdk-go-v2/service/sqs v1.18.5
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.4
	github.com/ca-risken/aws/pkg/common v0.0.0-20211004102725-c7fcf33f3fd3
	github.com/ca-risken/aws/pkg/message v0.0.0-20211004102725-c7fcf33f3fd3
	github.com/ca-risken/aws/proto/aws v0.0.0-20211004102725-c7fcf33f3fd3
	github.com/ca-risken/common/pkg/logging v0.0.0-20220524030432-e497432e632b
	github.com/ca-risken/common/pkg/portscan v0.0.0-20211124090848-375c75e97506
	github.com/ca-risken/common/pkg/profiler v0.0.0-20220304031727-c94e2c463b27
	github.com/ca-risken/common/pkg/sqs v0.0.0-20220525094706-413e91572a52
	github.com/ca-risken/common/pkg/tracer v0.0.0-20220426050416-a654045b9fa5
	github.com/ca-risken/core/proto/alert v0.0.0-20211129081226-f2531e88f350
	github.com/ca-risken/core/proto/finding v0.0.0-20220420065103-ec7428a46fe5
	github.com/ca-risken/go-sqs-poller/worker/v5 v5.0.0-20220525093235-9148d33b6aee
	github.com/gassara-kys/envconfig v1.4.4
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	golang.org/x/net v0.0.0-20211020060615-d418f374d309
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/grpc v1.45.0
)

require (
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.0.0-20211129110424-6491aa3bf583 // indirect
	github.com/DataDog/datadog-go v4.8.2+incompatible // indirect
	github.com/DataDog/datadog-go/v5 v5.0.2 // indirect
	github.com/DataDog/gostackparse v0.5.0 // indirect
	github.com/DataDog/sketches-go v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Ullaakut/nmap v2.0.2+incompatible // indirect
	github.com/Ullaakut/nmap/v2 v2.2.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.4 // indirect
	github.com/aws/smithy-go v1.11.2 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/pprof v0.0.0-20210423192551-a2663126120b // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/tinylib/msgp v1.1.2 // indirect
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20211116232009-f0f3c7e86c11 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/genproto v0.0.0-20211129164237-f09f9a12af12 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.38.0 // indirect
)
