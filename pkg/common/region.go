package common

var (
	// AWSRegionList list of AWS Regions, source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html
	AWSRegionList = []string{
		"us-east-1",      // Northern Virginia
		"us-east-2",      // Ohio
		"us-west-1",      // Northern California
		"us-west-2",      // Oregon
		"ca-central-1",   // Canada (Montreal)
		"eu-central-1",   // EU (Frankfurt)
		"eu-west-1",      // EU (Ireland)
		"eu-west-2",      // London
		"eu-west-3",      // Paris
		"eu-north-1",     // Stockholm
		"ap-northeast-1", // Asia Pacific (Tokyo)
		"ap-northeast-2", // Asia Pacific (Seoul)
		"ap-southeast-1", // Asia Pacific (Singapore)
		"ap-southeast-2", // Asia Pacific (Sydney)
		"ap-south-1",     // Asia Pacific (Mumbai)
		"sa-east-1",      // South America (São Paulo)
		"ap-east-1",      // Asia Pacific (Hong Kong)
		"me-south-1",     // Middle East (Bahrain)
	}
)
