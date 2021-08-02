package main

import (
	"context"
	"fmt"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-common/pkg/portscan"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/lightsail"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
)

type portscanAPI interface {
	getResult(context.Context, *message.AWSQueueMessage, bool) ([]*finding.FindingForUpsert, error)
	listAvailableRegion(ctx context.Context) ([]*ec2.Region, error)
	listEC2(context.Context, string) error
	listSecurityGroup(context.Context) error
	listELB(context.Context, string) error
	listELBv2(context.Context) error
	listRDS(context.Context) error
	listLightsail(context.Context) error
	excludeScan() []*excludeResult
	scan() ([]*portscan.NmapResult, error)
}

type portscanClient struct {
	Sess                  *session.Session
	EC2                   *ec2.EC2
	ELB                   *elb.ELB
	ELBv2                 *elbv2.ELBV2
	RDS                   *rds.RDS
	Lightsail             *lightsail.Lightsail
	SecurityGroups        []*targetSG
	target                []*target
	Region                string
	ScanExcludePortNumber int
}

type portscanConfig struct {
	AWSRegion             string `envconfig:"aws_region" default:"ap-northeast-1"`
	ScanExcludePortNumber int    `default:"1000" split_words:"true"`
}

func newPortscanClient(region, assumeRole, externalID string) (*portscanClient, error) {
	var conf portscanConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		return nil, err
	}
	if region == "" {
		region = conf.AWSRegion
	}

	p := portscanClient{}
	if err := p.newAWSSession(region, assumeRole, externalID); err != nil {
		return nil, err
	}
	p.Region = region
	p.ScanExcludePortNumber = conf.ScanExcludePortNumber
	return &p, nil
}

func (p *portscanClient) newAWSSession(region, assumeRole, externalID string) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)
	if err != nil {
		return err
	}
	if assumeRole != "" && externalID != "" {
		sess = session.New(&aws.Config{
			Region: sess.Config.Region,
			Credentials: stscreds.NewCredentials(
				sess, assumeRole, func(arp *stscreds.AssumeRoleProvider) {
					arp.ExternalID = aws.String(externalID)
				},
			),
		})
	} else if assumeRole != "" && externalID == "" {
		sess = session.New(&aws.Config{
			Region:      sess.Config.Region,
			Credentials: stscreds.NewCredentials(sess, assumeRole),
		})
	}
	p.Sess = sess
	p.EC2 = ec2.New(p.Sess, aws.NewConfig().WithRegion(region))
	p.ELB = elb.New(p.Sess, aws.NewConfig().WithRegion(region))
	p.ELBv2 = elbv2.New(p.Sess, aws.NewConfig().WithRegion(region))
	p.RDS = rds.New(p.Sess, aws.NewConfig().WithRegion(region))
	p.Lightsail = lightsail.New(p.Sess, aws.NewConfig().WithRegion(region))
	return nil
}

func (p *portscanClient) listAvailableRegion(ctx context.Context) ([]*ec2.Region, error) {
	out, err := p.EC2.DescribeRegionsWithContext(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn("Got no regions")
		return nil, nil
	}
	return out.Regions, nil
}

func (p *portscanClient) getResult(ctx context.Context, message *message.AWSQueueMessage, isFirstRegion bool) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	err := p.listSecurityGroup(ctx)
	if err != nil {
		appLogger.Errorf("Faild to describeSecurityGroups: err=%+v", err)
		return putData, err
	}
	err = p.listEC2(ctx, message.AccountID)
	if err != nil {
		appLogger.Errorf("Faild to describeInstances: err=%+v", err)
		return putData, err
	}
	err = p.listELB(ctx, message.AccountID)
	if err != nil {
		appLogger.Errorf("Faild to describeLoadBalancers: err=%+v", err)
		return putData, err
	}
	err = p.listELBv2(ctx)
	if err != nil {
		appLogger.Errorf("Faild to describeLoadBalancers(elbv2): err=%+v", err)
		return putData, err
	}
	err = p.listRDS(ctx)
	if err != nil {
		appLogger.Errorf("Faild to describeDBInstances(rds): err=%+v", err)
		return putData, err
	}
	err = p.listLightsail(ctx)
	if err != nil {
		appLogger.Errorf("Faild to getInstances(lightsail): err=%+v", err)
		return putData, err
	}
	excludeList := p.excludeScan()
	_, segment := xray.BeginSubsegment(ctx, "scanTargets")
	nmapResults, err := p.scan()
	segment.Close(err)
	if err != nil {
		appLogger.Errorf("Faild to describeSecurityGroups: err=%+v", err)
		return putData, err
	}
	putData, err = makeFindings(nmapResults, message)
	if err != nil {
		appLogger.Errorf("Faild to make findings: err=%+v", err)
		return putData, err
	}
	putDataExclude, err := makeExcludeFindings(excludeList, message)
	if err != nil {
		appLogger.Errorf("Faild to make findings: err=%+v", err)
		return putData, err
	}
	putData = append(putData, putDataExclude...)
	return putData, nil
}

func (p *portscanClient) listSecurityGroup(ctx context.Context) error {
	var retSG []*targetSG
	input := &ec2.DescribeSecurityGroupsInput{}
	result, err := p.EC2.DescribeSecurityGroupsWithContext(ctx, input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeSecurityGroups: %v", err)
		return err
	}
	for _, securityGroup := range result.SecurityGroups {
		fPort := 0
		tPort := 65535
		ipProtocol := "all"
		for _, ipPermission := range securityGroup.IpPermissions {
			if *ipPermission.IpProtocol == "tcp" || *ipPermission.IpProtocol == "udp" {
				fPort = int(*ipPermission.FromPort)
				tPort = int(*ipPermission.ToPort)
				ipProtocol = *ipPermission.IpProtocol
			}
			for _, ipRange := range ipPermission.IpRanges {
				if *ipRange.CidrIp == "0.0.0.0/0" {
					retSG = append(retSG, &targetSG{
						fromPort:  fPort,
						toPort:    tPort,
						protocol:  ipProtocol,
						groupID:   *securityGroup.GroupId,
						groupName: *securityGroup.GroupName,
					})
				}
			}
		}
	}
	p.SecurityGroups = retSG
	return nil
}

func (p *portscanClient) listEC2(ctx context.Context, accountID string) error {
	var listEC2 []*infoEC2
	input := &ec2.DescribeInstancesInput{}
	result, err := p.EC2.DescribeInstancesWithContext(ctx, input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeInstances: %v", err)
		return err
	}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.Association != nil {
					var securityGroups []*string
					for _, group := range networkInterface.Groups {
						securityGroups = append(securityGroups, group.GroupId)
					}
					listEC2 = append(listEC2, &infoEC2{
						InstanceID: *instance.InstanceId,
						PublicIP:   *networkInterface.Association.PublicIp,
						GroupID:    securityGroups,
					})
				}
			}
		}
	}
	for _, ec2 := range listEC2 {
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
	//	for _, aaa := range retEC2 {
	//		fmt.Printf("%v\n", aaa)
	//	}
	return nil
}

func (p *portscanClient) listELB(ctx context.Context, accountID string) error {
	var listELB []*infoELB
	input := &elb.DescribeLoadBalancersInput{}
	result, err := p.ELB.DescribeLoadBalancersWithContext(ctx, input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeLoadBalancers: %v", err)
		return err
	}
	for _, l := range result.LoadBalancerDescriptions {
		listELB = append(listELB, &infoELB{
			DNSName:          *l.DNSName,
			LoadBalancerName: *l.LoadBalancerName,
			GroupID:          l.SecurityGroups,
		})
	}
	for _, elb := range listELB {
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

	//	for _, aaa := range retELB {
	//		fmt.Printf("%v\n", aaa)
	//	}
	return nil
}

func (p *portscanClient) listELBv2(ctx context.Context) error {
	var listELBv2 []*infoELBv2
	input := &elbv2.DescribeLoadBalancersInput{}
	result, err := p.ELBv2.DescribeLoadBalancersWithContext(ctx, input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeLoadBalancers: %v", err)
		return err
	}
	for _, l := range result.LoadBalancers {
		listELBv2 = append(listELBv2, &infoELBv2{
			LoadBalancerArn: *l.LoadBalancerArn,
			DNSName:         *l.DNSName,
			GroupID:         l.SecurityGroups,
		})
	}
	for _, elbv2 := range listELBv2 {
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

	//	for _, aaa := range retELBv2 {
	//		fmt.Printf("%v\n", aaa)
	//	}
	return nil
}

func (p *portscanClient) listRDS(ctx context.Context) error {
	var listRDS []*infoRDS
	input := &rds.DescribeDBInstancesInput{}
	result, err := p.RDS.DescribeDBInstancesWithContext(ctx, input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeDBInstances: %v", err)
		return err
	}
	for _, i := range result.DBInstances {
		if *i.PubliclyAccessible == false {
			continue
		}
		var groupIDs []*string
		for _, s := range i.VpcSecurityGroups {
			groupIDs = append(groupIDs, s.VpcSecurityGroupId)
		}
		if !zero.IsZeroVal(groupIDs) {
			listRDS = append(listRDS, &infoRDS{
				DBInstanceArn:      *i.DBInstanceArn,
				PubliclyAccessible: *i.PubliclyAccessible,
				Endpoint:           *i.Endpoint.Address,
				GroupID:            groupIDs,
			})
		}
	}

	for _, rds := range listRDS {
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

	//	for _, aaa := range retELBv2 {
	//		fmt.Printf("%v\n", aaa)
	//	}
	return nil
}

func (p *portscanClient) listLightsail(ctx context.Context) error {
	input := &lightsail.GetInstancesInput{}
	result, err := p.Lightsail.GetInstancesWithContext(ctx, input)
	if err != nil {
		appLogger.Errorf("error occured when GetInstances(lightsail) : %v", err)
		return err
	}
	for _, i := range result.Instances {
		for _, n := range (*i.Networking).Ports {
			if *n.AccessFrom == "Custom" {
				continue
			}
			p.target = append(p.target, &target{
				Arn:      *i.Arn,
				Target:   *i.PublicIpAddress,
				Protocol: *n.Protocol,
				FromPort: int(*n.FromPort),
				ToPort:   int(*n.ToPort),
				Category: "lightsail",
			})
		}
	}

	inputLB := &lightsail.GetLoadBalancersInput{}
	resultLB, err := p.Lightsail.GetLoadBalancersWithContext(ctx, inputLB)
	if err != nil {
		appLogger.Errorf("error occured when GetLoadBalancers(lightsail): %v", err)
		return err
	}
	for _, l := range resultLB.LoadBalancers {
		p.target = append(p.target, &target{
			Arn:      *l.Arn,
			Target:   *l.DnsName,
			Protocol: *l.Protocol,
			FromPort: int(*l.InstancePort),
			ToPort:   int(*l.InstancePort),
			Category: "lightsail",
		})
	}
	return nil
}

func (p *portscanClient) excludeScan() []*excludeResult {
	var excludeList []*excludeResult
	var excludedTarget []*target
	for _, t := range p.target {
		if (t.ToPort - t.FromPort) > p.ScanExcludePortNumber {
			excludeList = append(excludeList, &excludeResult{
				FromPort:      t.FromPort,
				ToPort:        t.ToPort,
				Protocol:      t.Protocol,
				Target:        t.Target,
				Arn:           t.Arn,
				SecurityGroup: t.SecurityGroup,
			})
		} else {
			excludedTarget = append(excludedTarget, t)
		}
	}
	p.target = excludedTarget
	return excludeList
}

func (p *portscanClient) getMatchSecurityGroup(targetSecurityGroups []*string) []*targetSG {
	var ret []*targetSG
	for _, sg := range targetSecurityGroups {
		for _, SecurityGroup := range p.SecurityGroups {
			if *sg == SecurityGroup.groupID {
				ret = append(ret, SecurityGroup)
			}
		}
	}
	return ret
}

func (p *portscanClient) scan() ([]*portscan.NmapResult, error) {
	var nmapResults []*portscan.NmapResult
	for _, target := range p.target {
		results, err := portscan.Scan(target.Target, target.Protocol, target.FromPort, target.ToPort)
		if err != nil {
			appLogger.Warnf("Error occured when scanning. err: %v", err)
			return nmapResults, nil
		}
		for _, result := range results {
			result.ResourceName = target.Arn
			nmapResults = append(nmapResults, result)
		}
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
	GroupID    []*string
}

type infoELB struct {
	DNSName          string
	LoadBalancerName string
	GroupID          []*string
}

type infoELBv2 struct {
	LoadBalancerArn string
	DNSName         string
	GroupID         []*string
}

type infoRDS struct {
	DBInstanceArn      string
	PubliclyAccessible bool
	Endpoint           string
	GroupID            []*string
}

type excludeResult struct {
	FromPort      int
	ToPort        int
	Protocol      string
	Target        string
	Arn           string
	SecurityGroup string
}
