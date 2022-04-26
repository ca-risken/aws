module github.com/ca-risken/aws/src/access-analyzer

go 1.17

require (
	github.com/aws/aws-sdk-go v1.42.22
	github.com/aws/aws-sdk-go-v2 v1.16.3
	github.com/aws/aws-sdk-go-v2/config v1.15.4
	github.com/aws/aws-sdk-go-v2/credentials v1.12.0
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.15.4
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.36.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.4
	github.com/aws/aws-xray-sdk-go v1.6.0
	github.com/ca-risken/aws/pkg/common v0.0.0-20210907034232-c56f481434cd
	github.com/ca-risken/aws/pkg/message v0.0.0-20210907034232-c56f481434cd
	github.com/ca-risken/aws/proto/aws v0.0.0-20210907034232-c56f481434cd
	github.com/ca-risken/common/pkg/logging v0.0.0-20220113015330-0e8462d52b5b
	github.com/ca-risken/common/pkg/profiler v0.0.0-20220304031727-c94e2c463b27
	github.com/ca-risken/common/pkg/sqs v0.0.0-20220113015330-0e8462d52b5b
	github.com/ca-risken/common/pkg/xray v0.0.0-20211118071101-9855266b50a1
	github.com/ca-risken/core/proto/alert v0.0.0-20211129081226-f2531e88f350
	github.com/ca-risken/core/proto/finding v0.0.0-20211129081226-f2531e88f350
	github.com/gassara-kys/envconfig v1.4.4
	github.com/gassara-kys/go-sqs-poller/worker/v4 v4.0.0-20210215110542-0be358599a2f
	github.com/vikyd/zero v0.0.0-20190921142904-0f738d0bc858
	google.golang.org/grpc v1.44.0
)

require (
	github.com/DataDog/datadog-go/v5 v5.0.2 // indirect
	github.com/DataDog/gostackparse v0.5.0 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/andybalholm/brotli v1.0.3 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.10 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.4 // indirect
	github.com/aws/smithy-go v1.11.2 // indirect
	github.com/go-ozzo/ozzo-validation v3.6.0+incompatible // indirect
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/pprof v0.0.0-20220218203455-0368bd9e19a7 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.13.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.29.0 // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220218161850-94dd64e39d7c // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.36.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
