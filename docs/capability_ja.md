# Detection Capability

スコア0.8+(デフォルトアラート)のFindingで検出できる項目をリストアップします。

| カテゴリ | サービス | データソース | 検知項目 | ドキュメントリンク |
|---|---|---|---|---|
| Audit | CloudTrail | cloudsploit | CloudTrailが有効化されていない | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Audit | CloudTrail | cloudsploit | CloudTrailログ配信の失敗 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Compute | EC2 | cloudsploit | パブリックAMIの検出 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Database | DynamoDB | access-analyzer | パブリックアクセス可能なDynamoDBテーブル（ストリーム）の検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Database | EBS | access-analyzer | パブリックアクセス可能なEBSスナップショットの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Database | ECR | access-analyzer | パブリックアクセス可能なコンテナリポジトリーの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Database | EFS | access-analyzer | パブリックアクセス可能なElasitic File Systemsの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Database | RDS | access-analyzer | パブリックアクセス可能なRDSやスナップショットの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Database | RDS | cloudsploit | パブリックアクセス可能なRDSスナップショット | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Database | Redshift | cloudsploit | パブリックアクセス可能なRedshiftクラスター | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| DNS | Route53 | cloudsploit | ドメインの有効期限切れ | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Function | Lambda | access-analyzer | パブリックアクセス可能なLambda関数の検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| IAM | IAM | access-analyzer | 任意のAWSアカウントからアクセス可能なIAMロールの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| IAM | IAM | admin-checker | 管理者権限を持つIAMユーザを検知 | [リンク](https://docs.security-hub.jp/aws/adminchecker/) |
| IAM | IAM | cloudsploit | IAM証明書の有効期限切れ | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| IAM | IAM | cloudsploit | ルートアカウントにアクセスキーが存在 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| IAM | IAM | cloudsploit | ルートアカウントのMFA未設定 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| IAM | IAM | cloudsploit | ルートアカウントの署名証明書が存在 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Key Management | KMS | access-analyzer | パブリックアクセス可能なKMSキーの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Messaging | SNS | cloudsploit | 不適切なSNSトピックポリシー | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | API Gateway | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | EC2 | cloudsploit | セキュリティグループでElasticsearch（9200）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | EC2 | cloudsploit | セキュリティグループでMemcached（11211）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | EC2 | cloudsploit | セキュリティグループでMongoDB（27017）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | EC2 | cloudsploit | セキュリティグループでMySQL（3306）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | EC2 | cloudsploit | セキュリティグループでPostgreSQL（5432）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | EC2 | cloudsploit | セキュリティグループでRDP（3389）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Network | EC2 | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | EC2 | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | EC2 | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | EC2 | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | ELB | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | ELB | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | ELB | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | ELB | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | Lightsail | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | Lightsail | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | Lightsail | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | Lightsail | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | RDS | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | RDS | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | RDS | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Network | RDS | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Queue | SNS | access-analyzer | パブリックアクセス可能なSNSの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Queue | SQS | access-analyzer | パブリックアクセス可能なSQSの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Secret Manager | Secrets Manager | access-analyzer | パブリックアクセス可能なSecrets Managerの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Security | GuardDuty | guardduty | Amazon GuardDutyがサポートしている脅威検知のうちServerityが8.0以上の検出 | [リンク](https://docs.security-hub.jp/aws/guardduty/) |
| Storage | EC2 | cloudsploit | パブリックアクセス可能なEBSスナップショット | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Storage | S3 | access-analyzer | パブリック＆書き込み可能なS3バケットの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
