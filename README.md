# RISKEN AWS

![Build Status](https://codebuild.ap-northeast-1.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiUmllYmNsYi9CWlJqdDVKdzBTYUllSVF1Z3BmS0p4ZjMyTzVNRHFxYmhLN3cwSVJ2ZjBmb1YyNXFlTUZDZFZiWmdpc3QrdEFTV2U2SXB1bjBFZUJ0SUwwPSIsIml2UGFyYW1ldGVyU3BlYyI6IkQ2cGZubTVCWGZEMVdYUFIiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master)

`RISKEN` is a monitoring tool for your cloud platforms, web-site, source-code... 
`RISKEN AWS` is a security monitoring system for AWS that searches, analyzes, evaluate, and alerts on discovered threat information.

Please check [RISKEN Documentation](https://docs.security-hub.jp/).

## Installation

### Requirements

This module requires the following modules:

- [Go](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/get-docker/)
- [Protocol Buffer](https://grpc.io/docs/protoc-installation/)

### Install packages

This module is developed in the `Go language`, please run the following command after installing the `Go`.

```bash
$ make install
```

### Building

Build the containers on your machine with the following command

```bash
$ make build
```

### Running Apps

Deploy the pre-built containers to the Kubernetes environment on your local machine.

- Follow the [documentation](https://docs.security-hub.jp/admin/infra_local/#risken) to download the Kubernetes manifest sample.
- Fix the Kubernetes object specs of the manifest file as follows and deploy it.

`k8s-sample/overlays/local/aws.yaml`

| service        | spec                                | before (public images)                            | after (pre-build images on your machine) |
| -------------- | ----------------------------------- | ------------------------------------------------- | ---------------------------------------- |
| accessanalyzer | spec.template.spec.containers.image | `public.ecr.aws/risken/aws/accessanalyzer:latest` | `aws/accessanalyzer:latest`              |
| adminchecker   | spec.template.spec.containers.image | `public.ecr.aws/risken/aws/adminchecker:latest`   | `aws/adminchecker:latest`                |
| cloudsploit    | spec.template.spec.containers.image | `public.ecr.aws/risken/aws/cloudsploit:latest`    | `aws/cloudsploit:latest`                 |
| guardduty      | spec.template.spec.containers.image | `public.ecr.aws/risken/aws/guard-duty:latest`     | `aws/guard-duty:latest`                  |
| portscan       | spec.template.spec.containers.image | `public.ecr.aws/risken/aws/portscan:latest`       | `aws/portscan:latest`                    |

## CloudSploit

### Customize CloudSploit

You can customize several settings for CloudSploit by modifying the `cloudsploit.yaml` file.

```yaml
# defaultScore (1-10)
# If a plugin's score is not set, this default score will be applied.
defaultScore: 3

# ignorePlugin
# Specify plugins to be ignored here.
ignorePlugin:
  - EC2/ebsSnapshotPublic
  - Lambda/lambdaPublicAccess
  - SNS/topicPolicies
  - SQS/sqsPublicAccess

# specificPluginSetting
# You can set scores, tags, recommendations, etc. for each plugin.
specificPluginSetting:
  category/pluginName:
    # score (1-10):
    # Set the score for the plugin
    score: 8

    # skipResourceNamePattern:
    # Specify resource name patterns to ignore resources that match these patterns.
    skipResourceNamePattern:
      - "arn:aws:s3:::bucket-name"
      - "ignoreResourceName"

    # tags:
    # You can set tags for resources.
    # Tags can be used for search filters, etc.
    tags:
      - tag1
      - tag2

    # recommend:
    # You can set recommendations.
    recommend:
      risk: "..."
      remediation: "xxxxx"
```

This configuration allows you to customize CloudSploit's behavior, including setting default scores, ignoring specific plugins, and configuring plugin-specific settings such as scores, resource name patterns to skip, tags, and recommendations.

### Generate CloudSploit YAML file

You can generate the latest CloudSploit YAML file using the following command.

```bash
$ make generate-yaml
```


## Community

Info on reporting bugs, getting help, finding roadmaps,
and more can be found in the [RISKEN Community](https://github.com/ca-risken/community).

## License

[MIT](LICENSE).
