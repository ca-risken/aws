# Detection Capability

スコア0.8+のFindingで検出できる項目をリストアップします。

| サービス | カテゴリ | データソース | 検知項目 | ドキュメントリンク |
|---|---|---|---|---|
| API Gateway | Network | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| CloudTrail | Audit | cloudsploit | CloudTrailが有効化されていない | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| CloudTrail | Audit | cloudsploit | CloudTrailログ配信の失敗 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| DynamoDB | Database | access-analyzer | パブリックアクセス可能なDynamoDBテーブル（ストリーム）の検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| EBS | Database | access-analyzer | パブリックアクセス可能なEBSスナップショットの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| EC2 | Compute | cloudsploit | パブリックAMIの検出 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | cloudsploit | セキュリティグループでRDP（3389）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | cloudsploit | セキュリティグループでMySQL（3306）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | cloudsploit | セキュリティグループでPostgreSQL（5432）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | cloudsploit | セキュリティグループでMongoDB（27017）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | cloudsploit | セキュリティグループでElasticsearch（9200）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | cloudsploit | セキュリティグループでMemcached（11211）が公開 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| EC2 | Network | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| EC2 | Network | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| EC2 | Network | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| EC2 | Network | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| EC2 | Storage | cloudsploit | パブリックアクセス可能なEBSスナップショット | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| ECR | Database | access-analyzer | パブリックアクセス可能なコンテナリポジトリーの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| EFS | Database | access-analyzer | パブリックアクセス可能なElasitic File Systemsの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| ELB | Network | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| ELB | Network | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| ELB | Network | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| ELB | Network | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| GuardDuty | Security | guardduty | Amazon GuardDutyがサポートしている脅威検知のうちServerityが8.0以上の検出 | [リンク](https://docs.security-hub.jp/aws/guardduty/) |
| IAM | IAM | access-analyzer | 任意のAWSアカウントからアクセス可能なIAMロールの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| IAM | IAM | admin-checker | 管理者権限を持つIAMユーザを検知 | [リンク](https://docs.security-hub.jp/aws/adminchecker/) |
| IAM | IAM | cloudsploit | ルートアカウントにアクセスキーが存在 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| IAM | IAM | cloudsploit | ルートアカウントのMFA未設定 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| IAM | IAM | cloudsploit | IAM証明書の有効期限切れ | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| IAM | IAM | cloudsploit | ルートアカウントの署名証明書が存在 | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| KMS | Key Management | access-analyzer | パブリックアクセス可能なKMSキーの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Lambda | Function | access-analyzer | パブリックアクセス可能なLambda関数の検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Lightsail | Network | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Lightsail | Network | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Lightsail | Network | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Lightsail | Network | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| RDS | Database | access-analyzer | パブリックアクセス可能なRDSやスナップショットの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| RDS | Database | cloudsploit | パブリックアクセス可能なRDSスナップショット | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| RDS | Network | portscan | 公開データベースポート（MySQL:3306、PostgreSQL:5432、Redis:6379）の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| RDS | Network | portscan | HTTPオープンプロキシの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| RDS | Network | portscan | SSHパスワード認証有効の検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| RDS | Network | portscan | SMTPオープンリレーの検出 | [リンク](https://docs.security-hub.jp/aws/portscan/) |
| Redshift | Database | cloudsploit | パブリックアクセス可能なRedshiftクラスター | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| Route53 | DNS | cloudsploit | ドメインの有効期限切れ | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| S3 | Storage | access-analyzer | パブリック＆書き込み可能なS3バケットの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| Secrets Manager | Secret Manager | access-analyzer | パブリックアクセス可能なSecrets Managerの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| SNS | Messaging | cloudsploit | 不適切なSNSトピックポリシー | [リンク](https://docs.security-hub.jp/aws/cloudsploit/) |
| SNS | Queue | access-analyzer | パブリックアクセス可能なSNSの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
| SQS | Queue | access-analyzer | パブリックアクセス可能なSQSの検出 | [リンク](https://docs.security-hub.jp/aws/accessanalyzer/) |
