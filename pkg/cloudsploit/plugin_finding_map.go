// TODO: delete
package cloudsploit

const (
	categoryACM                 = "ACM"
	categoryAPIGateway          = "API Gateway"
	categoryAppFlow             = "AppFlow"
	categoryAppMesh             = "App Mesh"
	categoryAppRunner           = "App Runner"
	categoryAthena              = "Athena"
	categoryAuditManager        = "Audit Manager"
	categoryAutoScaling         = "AutoScaling"
	categoryBackup              = "Backup"
	categoryCloudFormation      = "CloudFormation"
	categoryCloudFront          = "CloudFront"
	categoryCloudTrail          = "CloudTrail"
	categoryCloudWatch          = "CloudWatch"
	categoryCloudWatchLogs      = "CloudWatchLogs"
	categoryComprehend          = "Comprehend"
	categoryCodeArtifact        = "CodeArtifact"
	categoryCodeBuild           = "CodeBuild"
	categoryCodePipeline        = "CodePipeline"
	categoryCodeStar            = "CodeStar"
	categoryCognito             = "Cognito"
	categoryComputeOptimizer    = "Compute Optimizer"
	categoryConfigService       = "ConfigService"
	categoryConnect             = "Connect"
	categoryDevOpsGuru          = "DevOpsGuru"
	categoryDMS                 = "DMS"
	categoryDocumentDB          = "DocumentDB"
	categoryDynamoDB            = "DynamoDB"
	categoryEC2                 = "EC2"
	categoryECR                 = "ECR"
	categoryECS                 = "ECS"
	categoryEFS                 = "EFS"
	categoryEKS                 = "EKS"
	categoryElastiCache         = "ElastiCache"
	categoryElasticBeanstalk    = "ElasticBeanstalk"
	categoryElasticTranscoder   = "Elastic Transcoder"
	categoryELB                 = "ELB"
	categoryELBv2               = "ELBv2"
	categoryEMR                 = "EMR"
	categoryES                  = "ES"
	categoryEventBridge         = "EventBridge"
	categoryFinSpace            = "FinSpace"
	categoryFirehose            = "Firehose"
	categoryForecast            = "Forecast"
	categoryFraudDetector       = "Fraud Detector"
	categoryFSx                 = "FSx"
	categoryGlue                = "Glue"
	categoryGlueDataBrew        = "Glue DataBrew"
	categoryGuardDuty           = "GuardDuty"
	categoryHealthLake          = "HealthLake"
	categoryIAM                 = "IAM"
	categoryImageBuilder        = "Image Builder"
	categoryIoTSiteWise         = "IoT SiteWise"
	categoryKendra              = "Kendra"
	categoryKinesis             = "Kinesis"
	categoryKinesisVideoStreams = "Kinesis Video Streams"
	categoryKMS                 = "KMS"
	categoryLambda              = "Lambda"
	categoryLex                 = "Lex"
	categoryLocation            = "Location"
	categoryLookoutMetrics      = "LookoutMetrics"
	categoryLookoutEquipment    = "LookoutEquipment"
	categoryLookout             = "Lookout"
	categoryManagedBlockchain   = "Managed Blockchain"
	categoryMemoryDB            = "MemoryDB"
	categoryMQ                  = "MQ"
	categoryMSK                 = "MSK"
	categoryMWAA                = "MWAA"
	categoryNeptune             = "Neptune"
	categoryOrganizations       = "Organizations"
	categoryProton              = "Proton"
	categoryQLDB                = "QLDB"
	categoryRDS                 = "RDS"
	categoryRedshift            = "Redshift"
	categoryRoute53             = "Route53"
	categoryS3                  = "S3"
	categoryS3Glacier           = "Glacier"
	categorySageMaker           = "SageMaker"
	categorySecretsManager      = "Secrets Manager"
	categorySES                 = "SES"
	categoryShield              = "Shield"
	categorySNS                 = "SNS"
	categorySQS                 = "SQS"
	categorySSM                 = "SSM"
	categoryTimestream          = "Timestream"
	categoryTransfer            = "Transfer"
	categoryTranslate           = "Translate"
	categoryWAF                 = "WAF"
	categoryWorkspaces          = "Workspaces"
	categoryXRay                = "XRay"
)

var CloudSploitFindingMap = map[string]cloudSploitFindingInformation{
	categoryACM + "/acmCertificateExpiry":                 {Score: 6.0, Tags: []string{"pci", "reliability"}},
	categoryACM + "/acmValidation":                        {Score: 6.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/appTierAsgCloudwatchLogs":     {Score: 3.0, Tags: []string{"operation"}},
	categoryAutoScaling + "/asgActiveNotifications":       {Score: 3.0, Tags: []string{"cost"}},
	categoryAutoScaling + "/asgMissingELB":                {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/asgMissingSecurityGroups":     {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/asgMultiAz":                   {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/asgSuspendedProcesses":        {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/elbHealthCheckActive":         {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/emptyASG":                     {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/sameAzElb":                    {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/webTierAsgAssociatedElb":      {Score: 3.0, Tags: []string{"reliability"}},
	categoryAutoScaling + "/webTierAsgCloudwatchLogs":     {Score: 3.0, Tags: []string{"operation"}},
	categoryAutoScaling + "/webTierAsgApprovedAmi":        {Score: 6.0, Tags: []string{}},
	categoryCloudFront + "/cloudfrontHttpsOnly":           {Score: 3.0, Tags: []string{"hipaa"}},
	categoryCloudFront + "/cloudfrontLoggingEnabled":      {Score: 3.0, Tags: []string{"hipaa", "pci", "operation"}},
	categoryCloudFront + "/insecureProtocols":             {Score: 6.0, Tags: []string{"hipaa", "pci"}},
	categoryCloudFront + "/publicS3Origin":                {Score: 3.0, Tags: []string{"hipaa"}},
	categoryCloudFront + "/secureOrigin":                  {Score: 3.0, Tags: []string{"hipaa"}},
	categoryCloudFront + "/compressObjectsAutomatically":  {Score: 3.0, Tags: []string{"cost"}},
	categoryCloudFront + "/enableOriginFailOver":          {Score: 3.0, Tags: []string{"reliability"}},
	categoryCloudTrail + "/cloudtrailBucketAccessLogging": {Score: 3.0, Tags: []string{"hipaa", "pci", "cis1", "cis"}},
	categoryCloudTrail + "/cloudtrailBucketDelete":        {Score: 3.0, Tags: []string{"hipaa"}},
	categoryCloudTrail + "/cloudtrailBucketPrivate":       {Score: 8.0, Tags: []string{"cis1", "cis"}},
	categoryCloudTrail + "/cloudtrailDeliveryFailing":     {Score: 8.0, Tags: []string{}},
	categoryCloudTrail + "/cloudtrailEnabled":             {Score: 8.0, Tags: []string{"hipaa", "pci", "cis1", "cis"}},
	categoryCloudTrail + "/cloudtrailEncryption":          {Score: 3.0, Tags: []string{"cis2", "cis"}},
	categoryCloudTrail + "/cloudtrailFileValidation":      {Score: 3.0, Tags: []string{"hipaa", "cis2", "cis"}},
	categoryCloudTrail + "/cloudtrailToCloudwatch":        {Score: 3.0, Tags: []string{"cis1", "cis"}},
	categoryCloudTrail + "/globalLoggingDuplicated":       {Score: 3.0, Tags: []string{"cost"}},
	categoryCloudWatchLogs + "/monitoringMetrics":         {Score: 3.0, Tags: []string{"cis1", "cis", "operation"}},
	categoryConfigService + "/configServiceEnabled":       {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryDMS + "/dmsEncryptionEnabled":                 {Score: 3.0, Tags: []string{"hipaa"}},
	categoryEC2 + "/classicInstances":                     {Score: 3.0, Tags: []string{"hipaa", "pci", "operation"}},
	categoryEC2 + "/crossVpcPublicPrivate":                {Score: 3.0, Tags: []string{"pci"}},
	categoryEC2 + "/defaultSecurityGroup":                 {Score: 3.0, Tags: []string{"pci", "cis2", "cis"}},
	categoryEC2 + "/ebsEncryptedSnapshots":                {Score: 3.0, Tags: []string{"hipaa"}},
	categoryEC2 + "/ebsEncryptionEnabled":                 {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categoryEC2 + "/ebsOldSnapshots":                      {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/ebsSnapshotLifecycle":                 {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/ebsSnapshotPrivate":                   {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/ebsSnapshotPublic":                    {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/ebsUnusedVolumes":                     {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/elasticIpLimit":                       {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/encryptedAmi":                         {Score: 3.0, Tags: []string{"hipaa"}},
	categoryEC2 + "/excessiveSecurityGroups":              {Score: 3.0, Tags: []string{"pci"}},
	categoryEC2 + "/flowLogsEnabled":                      {Score: 3.0, Tags: []string{"hipaa", "pci", "cis2", "cis"}},
	categoryEC2 + "/instanceLimit":                        {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/instanceMaxCount":                     {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/instanceVcpusLimit":                   {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/managedNatGateway":                    {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/multipleSubnets":                      {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/natMultiAz":                           {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/openAllPortsProtocols":                {Score: 8.0, Tags: []string{"hipaa", "pci"}},
	categoryEC2 + "/openCIFS":                             {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openCustomPorts":                      {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openDNS":                              {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openDocker":                           {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openElasticsearch":                    {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openFTP":                              {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openHadoopNameNode":                   {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openHadoopNameNodeWebUI":              {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openKibana":                           {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openMySQL":                            {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openNetBIOS":                          {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openOracle":                           {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openOracleAutoDataWarehouse":          {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openPostgreSQL":                       {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openRDP":                              {Score: 8.0, Tags: []string{"cis1", "cis"}},
	categoryEC2 + "/openRPC":                              {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openSalt":                             {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openSMBoTCP":                          {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openSMTP":                             {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openSQLServer":                        {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openSSH":                              {Score: 6.0, Tags: []string{}},
	categoryEC2 + "/openTelnet":                           {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openVNCClient":                        {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/openVNCServer":                        {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/overlappingSecurityGroups":            {Score: 3.0, Tags: []string{"operation"}},
	categoryEC2 + "/publicAmi":                            {Score: 8.0, Tags: []string{}},
	categoryEC2 + "/subnetIpAvailability":                 {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/unassociatedElasticIp":                {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/unusedAmi":                            {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/unusedEni":                            {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/unusedVirtualPrivateGateway":          {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/unusedVpcInternetGateways":            {Score: 3.0, Tags: []string{"cost"}},
	categoryEC2 + "/vpcElasticIpLimit":                    {Score: 3.0, Tags: []string{"reliability"}},
	categoryEC2 + "/outdatedAmiInUse":                     {Score: 6.0, Tags: []string{"operation"}},
	categoryEC2 + "/vpcPeeringConnections":                {Score: 3.0, Tags: []string{}},
	categoryEFS + "/efsEncryptionEnabled":                 {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categoryEKS + "/eksKubernetesVersion":                 {Score: 3.0, Tags: []string{"operation"}},
	categoryEKS + "/eksLoggingEnabled":                    {Score: 6.0, Tags: []string{}},
	categoryEKS + "/eksSecurityGroups":                    {Score: 6.0, Tags: []string{}},
	categoryElastiCache + "/elasticacheNodesCount":        {Score: 3.0, Tags: []string{"cost"}},
	categoryElastiCache + "/elasticacheRedisMultiAZ":      {Score: 3.0, Tags: []string{"reliability"}},
	categoryElastiCache + "/elasticaheDesiredNodeType":    {Score: 3.0, Tags: []string{"cost"}},
	categoryElastiCache + "/idleElastiCacheNode":          {Score: 3.0, Tags: []string{"cost"}},
	categoryElasticBeanstalk + "/managedPlatformUpdates":  {Score: 3.0, Tags: []string{"operation"}},
	categoryElasticBeanstalk + "/enviromentAccessLogs":    {Score: 6.0, Tags: []string{}},
	categoryELB + "/elbLoggingEnabled":                    {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categoryELB + "/elbNoInstances":                       {Score: 3.0, Tags: []string{"cost"}},
	categoryELB + "/insecureCiphers":                      {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categoryELBv2 + "/elbv2DeletionProtection":            {Score: 6.0, Tags: []string{"reliability"}},
	categoryELBv2 + "/elbv2LoggingEnabled":                {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categoryELBv2 + "/elbv2MinimumTargetInstances":        {Score: 3.0, Tags: []string{"reliability"}},
	categoryELBv2 + "/elbv2NoInstances":                   {Score: 3.0, Tags: []string{"cost"}},
	categoryELBv2 + "elbv2SslTermination":                 {Score: 6.0, Tags: []string{}},
	categoryES + "/esUpgradeAvailable":                    {Score: 3.0, Tags: []string{"operation"}},
	categoryES + "/esClusterStatus":                       {Score: 6.0, Tags: []string{}},
	categoryES + "/esDesiredInstanceTypes":                {Score: 3.0, Tags: []string{"cost"}},
	categoryFirehose + "/firehoseEncrypted":               {Score: 3.0, Tags: []string{"hipaa"}},
	categoryGuardDuty + "/guardDutyEnabled":               {Score: 6.0, Tags: []string{}},
	categoryIAM + "/accessKeysExtra":                      {Score: 6.0, Tags: []string{}},
	categoryIAM + "/accessKeysLastUsed":                   {Score: 6.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/accessKeysRotated":                    {Score: 3.0, Tags: []string{"hipaa", "pci", "cis1", "cis"}},
	categoryIAM + "/certificateExpiry":                    {Score: 8.0, Tags: []string{"reliability"}},
	categoryIAM + "/iamRoleLastUsed":                      {Score: 6.0, Tags: []string{}},
	categoryIAM + "/iamUserAdmins":                        {Score: 6.0, Tags: []string{"pci"}},
	categoryIAM + "/iamUserUnauthorizedToEdit":            {Score: 3.0, Tags: []string{"pci"}},
	categoryIAM + "/maxPasswordAge":                       {Score: 3.0, Tags: []string{"pci"}},
	categoryIAM + "/minPasswordLength":                    {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/noUserIamPolicies":                    {Score: 3.0, Tags: []string{"cis1", "cis"}},
	categoryIAM + "/passwordExpiration":                   {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/passwordRequiresLowercase":            {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/passwordRequiresNumbers":              {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/passwordRequiresSymbols":              {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/passwordRequiresUppercase":            {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/passwordReusePrevention":              {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/rootAccessKeys":                       {Score: 8.0, Tags: []string{"hipaa", "cis1", "cis"}},
	categoryIAM + "/rootAccountInUse":                     {Score: 6.0, Tags: []string{"hipaa", "pci", "cis1", "cis"}},
	categoryIAM + "/rootMfaEnabled":                       {Score: 8.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryIAM + "/rootSigningCertificate":               {Score: 8.0, Tags: []string{"hipaa"}},
	categoryIAM + "/usersMfaEnabled":                      {Score: 6.0, Tags: []string{"hipaa", "pci", "cis1", "cis"}},
	categoryIAM + "/usersPasswordAndKeys":                 {Score: 6.0, Tags: []string{}},
	categoryIAM + "/usersPasswordLastUsed":                {Score: 3.0, Tags: []string{"pci", "cis1", "cis"}},
	categoryKinesis + "/kinesisEncrypted":                 {Score: 3.0, Tags: []string{"hipaa"}},
	categoryKMS + "/kmsDefaultKeyUsage":                   {Score: 3.0, Tags: []string{"pci"}},
	categoryKMS + "/kmsKeyRotation":                       {Score: 3.0, Tags: []string{"pci", "cis2", "cis"}},
	categoryKMS + "/kmsScheduledDeletion":                 {Score: 6.0, Tags: []string{}},
	categoryLambda + "/lambdaPublicAccess":                {Score: 6.0, Tags: []string{}},
	categoryLambda + "/lambdaAdminPrivileges":             {Score: 6.0, Tags: []string{}},
	categoryMQ + "/mqAutoMinorVersionUpgrade":             {Score: 3.0, Tags: []string{"operation"}},
	categoryMQ + "/mqDesiredInstanceType":                 {Score: 3.0, Tags: []string{"cost"}},
	categoryMSK + "/mskClusterPublicAccess":               {Score: 6.0, Tags: []string{}},
	categoryMWAA + "/environmentAdminPrivileges":          {Score: 6.0, Tags: []string{}},
	categoryMWAA + "/webServerPublicAccess":               {Score: 3.0, Tags: []string{}},
	categoryOrganizations + "/enableAllFeatures":          {Score: 3.0, Tags: []string{"operation"}},
	categoryRDS + "/rdsAutomatedBackups":                  {Score: 3.0, Tags: []string{"reliability"}},
	categoryRDS + "/rdsEncryptionEnabled":                 {Score: 6.0, Tags: []string{"hipaa", "pci"}},
	categoryRDS + "/rdsMinorVersionUpgrade":               {Score: 3.0, Tags: []string{"operation"}},
	categoryRDS + "/rdsMultiAz":                           {Score: 3.0, Tags: []string{"reliability"}},
	categoryRDS + "/rdsPubliclyAccessible":                {Score: 6.0, Tags: []string{"hipaa", "pci"}},
	categoryRDS + "/rdsRestorable":                        {Score: 3.0, Tags: []string{"pci", "reliability"}},
	categoryRDS + "/rdsSnapshotPubliclyAccessible":        {Score: 8.0, Tags: []string{}},
	categoryRedshift + "/redshiftAllowVersionUpgrade":     {Score: 3.0, Tags: []string{"operation"}},
	categoryRedshift + "/redshiftEncryptionEnabled":       {Score: 6.0, Tags: []string{"hipaa"}},
	categoryRedshift + "/redshiftPubliclyAccessible":      {Score: 8.0, Tags: []string{"hipaa", "pci"}},
	categoryRedshift + "/redshiftDesiredNodeType":         {Score: 3.0, Tags: []string{"cost"}},
	categoryRedshift + "/redshiftNodesCount":              {Score: 3.0, Tags: []string{"cost"}},
	categoryRedshift + "/redshiftUnusedReservedNodes":     {Score: 3.0, Tags: []string{"cost"}},
	categoryRoute53 + "/danglingDnsRecords":               {Score: 6.0, Tags: []string{}},
	categoryRoute53 + "/domainAutoRenew":                  {Score: 6.0, Tags: []string{"reliability"}},
	categoryRoute53 + "/domainExpiry":                     {Score: 8.0, Tags: []string{"reliability"}},
	categoryS3 + "/bucketAllUsersAcl":                     {Score: 6.0, Tags: []string{"pci"}},
	categoryS3 + "/bucketAllUsersPolicy":                  {Score: 6.0, Tags: []string{"pci"}},
	categoryS3 + "/bucketLogging":                         {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categoryS3 + "/bucketVersioning":                      {Score: 3.0, Tags: []string{"reliability"}},
	categoryS3 + "/bucketPolicyCloudFrontOac":             {Score: 6.0, Tags: []string{}},
	categoryS3Glacier + "/vaultPublicAccess":              {Score: 6.0, Tags: []string{}},
	categorySageMaker + "/notebookDataEncrypted":          {Score: 3.0, Tags: []string{"hipaa"}},
	categorySageMaker + "/notebookDirectInternetAccess":   {Score: 6.0, Tags: []string{}},
	categorySecretsManager + "/secretsManagerRotation":    {Score: 3.0, Tags: []string{"operation"}},
	categorySES + "/dkimEnabled":                          {Score: 6.0, Tags: []string{"reliability"}},
	categorySNS + "/topicPolicies":                        {Score: 8.0, Tags: []string{}},
	categorySQS + "/sqsCrossAccount":                      {Score: 3.0, Tags: []string{"pci"}},
	categorySQS + "/sqsEncrypted":                         {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categorySQS + "/sqsPublicAccess":                      {Score: 6.0, Tags: []string{}},
	categorySSM + "/ssmActiveOnAllInstances":              {Score: 3.0, Tags: []string{"operation"}},
	categorySSM + "/ssmAgentAutoUpdateEnabled":            {Score: 3.0, Tags: []string{"operation"}},
	categorySSM + "/ssmAgentLatestVersion":                {Score: 3.0, Tags: []string{"operation"}},
	categorySSM + "/ssmEncryptedParameters":               {Score: 3.0, Tags: []string{"hipaa", "pci"}},
	categorySSM + "/ssmDocumentPublicAccess":              {Score: 3.0, Tags: []string{}},
	categoryTransfer + "/transferLoggingEnabled":          {Score: 6.0, Tags: []string{"hipaa", "pci"}},
	categoryWorkspaces + "/unusedWorkspaces":              {Score: 3.0, Tags: []string{"cost"}},
	categoryWorkspaces + "/workspacesDesiredBundleType":   {Score: 3.0, Tags: []string{"cost"}},
	categoryWorkspaces + "/workspacesInstanceCount":       {Score: 3.0, Tags: []string{"cost"}},
}

type cloudSploitFindingInformation struct {
	Score float32
	Tags  []string
}
