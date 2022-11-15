package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ca-risken/common/pkg/portscan"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/vikyd/zero"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

type portscanAPI interface {
	getTargets(context.Context, *message.AWSQueueMessage) ([]*target, map[string]*relSecurityGroupArn, error)
	listAvailableRegion(ctx context.Context) (*[]ec2types.Region, error)
	listEC2(context.Context, string) error
	listSecurityGroup(context.Context, string) error
	listELB(context.Context, string) error
	listELBv2(context.Context) error
	listRDS(context.Context) error
	listLightsail(context.Context) error
}

type portscanClient struct {
	EC2                  *ec2.Client
	ELB                  *elb.Client
	ELBv2                *elbv2.Client
	RDS                  *rds.Client
	Lightsail            *lightsail.Client
	SecurityGroups       []*targetSG
	relSecurityGroupARNs map[string]*relSecurityGroupArn
	target               []*target
	Region               string
}

func newPortscanClient(ctx context.Context, region, assumeRole, externalID string, scanExcludePortNumber, retry int) (portscanAPI, error) {
	p := portscanClient{}
	if err := p.newAWSSession(ctx, region, assumeRole, externalID, retry); err != nil {
		return nil, err
	}
	p.Region = region
	return &p, nil
}

func (p *portscanClient) newAWSSession(ctx context.Context, region, assumeRole, externalID string, retry int) error {
	if assumeRole == "" {
		return errors.New("Required AWS AssumeRole")
	}
	if externalID == "" {
		return errors.New("Required AWS ExternalID")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return err
	}
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRole,
		func(p *stscreds.AssumeRoleOptions) {
			p.RoleSessionName = "RISKEN"
			p.ExternalID = &externalID
		},
	)
	cfg.Credentials = aws.NewCredentialsCache(provider)
	_, err = cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}
	p.EC2 = ec2.New(ec2.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	p.ELB = elb.New(elb.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	p.ELBv2 = elbv2.New(elbv2.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	p.RDS = rds.New(rds.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	p.Lightsail = lightsail.New(lightsail.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	return nil
}

func (p *portscanClient) listAvailableRegion(ctx context.Context) (*[]ec2types.Region, error) {
	out, err := p.EC2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn(ctx, "Got no regions")
		return nil, nil
	}
	return &out.Regions, nil
}

func (p *portscanClient) getTargets(ctx context.Context, message *message.AWSQueueMessage) ([]*target, map[string]*relSecurityGroupArn, error) {
	err := p.listSecurityGroup(ctx, message.AccountID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describeSecurityGroups: err=%+v", err)
		return []*target{}, map[string]*relSecurityGroupArn{}, err
	}
	err = p.listEC2(ctx, message.AccountID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describeInstances: err=%+v", err)
		return []*target{}, map[string]*relSecurityGroupArn{}, err
	}
	err = p.listELB(ctx, message.AccountID)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describeLoadBalancers: err=%+v", err)
		return []*target{}, map[string]*relSecurityGroupArn{}, err
	}
	err = p.listELBv2(ctx)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describeLoadBalancers(elbv2): err=%+v", err)
		return []*target{}, map[string]*relSecurityGroupArn{}, err
	}
	err = p.listRDS(ctx)
	if err != nil {
		appLogger.Errorf(ctx, "Failed to describeDBInstances(rds): err=%+v", err)
		return []*target{}, map[string]*relSecurityGroupArn{}, err
	}
	err = p.listLightsail(ctx)
	if err != nil {
		if isAvailableRegionLightSail(p.Region) {
			appLogger.Errorf(ctx, "Failed to getInstances(lightsail): err=%+v", err)
			return []*target{}, map[string]*relSecurityGroupArn{}, err
		} else {
			appLogger.Infof(ctx, "Failed to getInstances(lightsail). but region %v is not supported LightSail", p.Region)
		}
	}

	return p.target, p.relSecurityGroupARNs, nil
}

const IP_PROTOCOL_ALL = "-1"

func (p *portscanClient) listSecurityGroup(ctx context.Context, accountID string) error {
	var retSG []*targetSG
	allSecurityGroup := map[string]*relSecurityGroupArn{}
	input := &ec2.DescribeSecurityGroupsInput{}
	result, err := p.EC2.DescribeSecurityGroups(ctx, input)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when DescribeSecurityGroups: %v", err)
		return err
	}
	for _, securityGroup := range result.SecurityGroups {
		fPort := 0
		tPort := 65535
		ipProtocol := "all"
		for _, ipPermission := range securityGroup.IpPermissions {
			// skip scan without tcp,udp and all
			if *ipPermission.IpProtocol != "tcp" && *ipPermission.IpProtocol != "udp" && *ipPermission.IpProtocol != IP_PROTOCOL_ALL {
				continue
			}
			if *ipPermission.IpProtocol == "tcp" || *ipPermission.IpProtocol == "udp" {
				fPort = int(*ipPermission.FromPort)
				tPort = int(*ipPermission.ToPort)
				ipProtocol = *ipPermission.IpProtocol
			}
			isPublic := false
			for _, ipRange := range ipPermission.IpRanges {
				if *ipRange.CidrIp == "0.0.0.0/0" {
					retSG = append(retSG, &targetSG{
						fromPort:  fPort,
						toPort:    tPort,
						protocol:  ipProtocol,
						groupID:   *securityGroup.GroupId,
						groupName: *securityGroup.GroupName,
					})
					isPublic = true
				}
			}
			// for resource
			securityGroupARN := fmt.Sprintf("arn:aws:ec2:%v:%v:security-group/%v", p.Region, accountID, *securityGroup.GroupId)
			allSecurityGroup[securityGroupARN] = &relSecurityGroupArn{
				SecurityGroup: &securityGroup,
				IsPublic:      isPublic,
			}
		}
	}
	p.SecurityGroups = retSG
	p.relSecurityGroupARNs = allSecurityGroup
	return nil
}

func (p *portscanClient) listEC2(ctx context.Context, accountID string) error {
	var listEC2 []*infoEC2
	input := &ec2.DescribeInstancesInput{}
	result, err := p.EC2.DescribeInstances(ctx, input)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when DescribeInstances: %v", err)
		return err
	}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.Association != nil {
					var securityGroups []string
					for _, group := range networkInterface.Groups {
						securityGroups = append(securityGroups, *group.GroupId)
					}
					listEC2 = append(listEC2, &infoEC2{
						InstanceID: *instance.InstanceId,
						PublicIP:   *networkInterface.Association.PublicIp,
						GroupID:    &securityGroups,
					})
				}
			}
		}
	}
	for _, ec2 := range listEC2 {
		// for resource
		p.addRelSecurityGroupARNs(ec2.GroupID, fmt.Sprintf("arn:aws:ec2:%v:%v:instance/%v", p.Region, accountID, ec2.InstanceID))

		securityGroups := p.getMatchSecurityGroup(ec2.GroupID)
		if zero.IsZeroVal(securityGroups) {
			continue
		}
		for _, securityGroup := range securityGroups {
			targetEC2 := &target{
				Arn:           fmt.Sprintf("arn:aws:ec2:%v:%v:instance/%v", p.Region, accountID, ec2.InstanceID),
				Target:        ec2.PublicIP,
				Protocol:      securityGroup.protocol,
				FromPort:      securityGroup.fromPort,
				ToPort:        securityGroup.toPort,
				SecurityGroup: securityGroup.groupID,
				Category:      "ec2",
			}
			p.target = append(p.target, targetEC2)
		}
	}
	return nil
}

func (p *portscanClient) listELB(ctx context.Context, accountID string) error {
	var listELB []*infoELB
	input := &elb.DescribeLoadBalancersInput{}
	result, err := p.ELB.DescribeLoadBalancers(ctx, input)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when DescribeLoadBalancers: %v", err)
		return err
	}
	for _, l := range result.LoadBalancerDescriptions {
		listELB = append(listELB, &infoELB{
			DNSName:          *l.DNSName,
			LoadBalancerName: *l.LoadBalancerName,
			GroupID:          &l.SecurityGroups,
		})
	}
	for _, elb := range listELB {
		// for resource
		p.addRelSecurityGroupARNs(elb.GroupID, fmt.Sprintf("arn:aws:elasticloadbalancing:%v:%v:loadbalancer/%v", p.Region, accountID, elb.LoadBalancerName))

		securityGroups := p.getMatchSecurityGroup(elb.GroupID)
		if zero.IsZeroVal(securityGroups) {
			continue
		}
		for _, securityGroup := range securityGroups {
			targetELB := &target{
				Arn:           fmt.Sprintf("arn:aws:elasticloadbalancing:%v:%v:loadbalancer/%v", p.Region, accountID, elb.LoadBalancerName),
				Target:        elb.DNSName,
				Protocol:      securityGroup.protocol,
				FromPort:      securityGroup.fromPort,
				ToPort:        securityGroup.toPort,
				SecurityGroup: securityGroup.groupID,
				Category:      "elb",
			}
			p.target = append(p.target, targetELB)
		}
	}
	return nil
}

func (p *portscanClient) listELBv2(ctx context.Context) error {
	input := &elbv2.DescribeLoadBalancersInput{}
	result, err := p.ELBv2.DescribeLoadBalancers(ctx, input)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when DescribeLoadBalancers: %v", err)
		return err
	}
	p.setELBv2(result)
	return nil
}

func (p *portscanClient) setELBv2(lbs *elbv2.DescribeLoadBalancersOutput) {
	if lbs == nil {
		return
	}
	var listELBv2 []*infoELBv2
	for _, l := range lbs.LoadBalancers {
		listELBv2 = append(listELBv2, &infoELBv2{
			LoadBalancerArn: convertNilString(l.LoadBalancerArn),
			DNSName:         convertNilString(l.DNSName),
			GroupID:         &l.SecurityGroups,
		})
	}
	for _, elbv2 := range listELBv2 {
		// for resource
		p.addRelSecurityGroupARNs(elbv2.GroupID, elbv2.LoadBalancerArn)

		securityGroups := p.getMatchSecurityGroup(elbv2.GroupID)
		if zero.IsZeroVal(securityGroups) {
			continue
		}
		for _, securityGroup := range securityGroups {
			targetELB := &target{
				Arn:           elbv2.LoadBalancerArn,
				Target:        elbv2.DNSName,
				Protocol:      securityGroup.protocol,
				FromPort:      securityGroup.fromPort,
				ToPort:        securityGroup.toPort,
				SecurityGroup: securityGroup.groupID,
				Category:      "elbv2",
			}
			p.target = append(p.target, targetELB)
		}
	}
}

func (p *portscanClient) listRDS(ctx context.Context) error {
	var listRDS []*infoRDS
	input := &rds.DescribeDBInstancesInput{}
	result, err := p.RDS.DescribeDBInstances(ctx, input)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when DescribeDBInstances: %v", err)
		return err
	}
	for _, i := range result.DBInstances {
		if !i.PubliclyAccessible {
			continue
		}
		var groupIDs []string
		for _, s := range i.VpcSecurityGroups {
			groupIDs = append(groupIDs, *s.VpcSecurityGroupId)
		}
		if !zero.IsZeroVal(groupIDs) {
			listRDS = append(listRDS, &infoRDS{
				DBInstanceArn:      *i.DBInstanceArn,
				PubliclyAccessible: i.PubliclyAccessible,
				Endpoint:           *i.Endpoint.Address,
				GroupID:            &groupIDs,
			})
		}
	}

	for _, rds := range listRDS {
		// for resource
		p.addRelSecurityGroupARNs(rds.GroupID, rds.DBInstanceArn)

		securityGroups := p.getMatchSecurityGroup(rds.GroupID)
		if zero.IsZeroVal(securityGroups) {
			continue
		}
		for _, securityGroup := range securityGroups {
			targetRDS := &target{
				Arn:           rds.DBInstanceArn,
				Target:        rds.Endpoint,
				Protocol:      securityGroup.protocol,
				FromPort:      securityGroup.fromPort,
				ToPort:        securityGroup.toPort,
				SecurityGroup: securityGroup.groupID,
				Category:      "rds",
			}
			p.target = append(p.target, targetRDS)
		}
	}
	return nil
}

func (p *portscanClient) listLightsail(ctx context.Context) error {
	input := &lightsail.GetInstancesInput{}
	result, err := p.Lightsail.GetInstances(ctx, input)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when GetInstances(lightsail) : %v", err)
		return err
	}
	for _, i := range result.Instances {
		if i.PublicIpAddress == nil {
			continue
		}
		for _, n := range (*i.Networking).Ports {
			if *n.AccessFrom == "Custom" {
				continue
			}
			for _, protocal := range getTargetProtocolFromlightsailProtocol(n.Protocol) {
				p.target = append(p.target, &target{
					Arn:      *i.Arn,
					Target:   *i.PublicIpAddress,
					Protocol: protocal,
					FromPort: int(n.FromPort),
					ToPort:   int(n.ToPort),
					Category: "lightsail",
				})
			}
		}
	}
	inputLB := &lightsail.GetLoadBalancersInput{}
	resultLB, err := p.Lightsail.GetLoadBalancers(ctx, inputLB)
	if err != nil {
		appLogger.Errorf(ctx, "error occured when GetLoadBalancers(lightsail): %v", err)
		return err
	}
	for _, l := range resultLB.LoadBalancers {
		p.target = append(p.target, &target{
			Arn:      *l.Arn,
			Target:   *l.DnsName,
			Protocol: "tcp", // lightsailtypes.LoadBalancer(HTTP or HTTPS) is always  need "tcp" scan.
			FromPort: int(*l.InstancePort),
			ToPort:   int(*l.InstancePort),
			Category: "lightsail",
		})
	}
	return nil
}

func getTargetProtocolFromlightsailProtocol(p lightsailtypes.NetworkProtocol) []string {
	protocol := []string{}
	switch p {
	case lightsailtypes.NetworkProtocolTcp:
		protocol = append(protocol, "tcp")
	case lightsailtypes.NetworkProtocolUdp:
		protocol = append(protocol, "udp")
	case lightsailtypes.NetworkProtocolAll:
		protocol = append(protocol, "tcp", "udp")
	default:
		// return empty when others
	}
	return protocol
}

func excludeScan(scanExcludePortNumber int, targets []*target) ([]*target, []*excludeResult) {
	var excludeList []*excludeResult
	var scanTarget []*target
	for _, t := range targets {
		if (t.ToPort - t.FromPort) > scanExcludePortNumber {
			excludeList = append(excludeList, &excludeResult{
				FromPort:      t.FromPort,
				ToPort:        t.ToPort,
				Protocol:      t.Protocol,
				Target:        t.Target,
				Arn:           t.Arn,
				SecurityGroup: t.SecurityGroup,
				Category:      t.Category,
			})
		} else {
			scanTarget = append(scanTarget, t)
		}
	}
	return scanTarget, excludeList
}

func (p *portscanClient) addRelSecurityGroupARNs(targetSecurityGroups *[]string, arn string) {
	for _, sg := range *targetSecurityGroups {
		for groupArn := range p.relSecurityGroupARNs {
			if strings.HasSuffix(groupArn, sg) {
				p.relSecurityGroupARNs[groupArn].ReferenceARNs = append(p.relSecurityGroupARNs[groupArn].ReferenceARNs, arn)
			}
		}
	}
}

func (p *portscanClient) getMatchSecurityGroup(targetSecurityGroups *[]string) []*targetSG {
	var ret []*targetSG
	for _, sg := range *targetSecurityGroups {
		for _, SecurityGroup := range p.SecurityGroups {
			if sg == SecurityGroup.groupID {
				ret = append(ret, SecurityGroup)
			}
		}
	}
	return ret
}

func scan(ctx context.Context, targets []*target, scanConcurrency int64) ([]*portscan.NmapResult, error) {
	eg, errGroupCtx := errgroup.WithContext(ctx)
	var nmapResults []*portscan.NmapResult
	mutex := &sync.Mutex{}
	sem := semaphore.NewWeighted(scanConcurrency)
	for _, t := range targets {
		if err := sem.Acquire(ctx, 1); err != nil {
			appLogger.Errorf(ctx, "failed to acquire semaphore: %v", err)
			return nmapResults, err
		}
		t := t
		eg.Go(func() error {
			defer sem.Release(1)
			select {
			case <-errGroupCtx.Done():
				appLogger.Debugf(ctx, "scan cancel. target: %v", t.Target)
				return nil
			default:
				results, err := portscan.Scan(t.Target, t.Protocol, t.FromPort, t.ToPort)
				if err != nil {
					return err
				}
				for _, result := range results {
					result.ResourceName = t.Arn
				}
				mutex.Lock()
				nmapResults = append(nmapResults, results...)
				mutex.Unlock()
				return nil
			}
		})
	}
	if err := eg.Wait(); err != nil {
		appLogger.Errorf(ctx, "failed to exec portscan: %v", err)
		return nmapResults, err
	}

	return nmapResults, nil
}

type targetSG struct {
	fromPort  int
	toPort    int
	protocol  string
	groupID   string
	groupName string
}

type relSecurityGroupArn struct {
	SecurityGroup *ec2types.SecurityGroup `json:"security_group"`
	ReferenceARNs []string                `json:"reference_arns"`
	IsPublic      bool                    `json:"is_public"`
}

type target struct {
	Arn           string
	Target        string
	FromPort      int
	ToPort        int
	Protocol      string
	Category      string
	SecurityGroup string
}

type infoEC2 struct {
	InstanceID string
	PublicIP   string
	GroupID    *[]string
}

type infoELB struct {
	DNSName          string
	LoadBalancerName string
	GroupID          *[]string
}

type infoELBv2 struct {
	LoadBalancerArn string
	DNSName         string
	GroupID         *[]string
}

type infoRDS struct {
	DBInstanceArn      string
	PubliclyAccessible bool
	Endpoint           string
	GroupID            *[]string
}

type excludeResult struct {
	FromPort      int
	ToPort        int
	Protocol      string
	Target        string
	Arn           string
	SecurityGroup string
	Category      string
}

func convertNilString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
