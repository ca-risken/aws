package portscan

var LightSailRegions = []string{
	"us-east-2",
	"us-east-1",
	"us-west-2",
	"ap-south-1",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
}

func isAvailableRegionLightSail(region string) bool {
	for _, availableRegion := range LightSailRegions {
		if availableRegion == region {
			return true
		}
	}
	return false
}
