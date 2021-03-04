package main

import (
	"fmt"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/Ullaakut/nmap/v2"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/aws/aws-sdk-go/service/lightsail"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
)

type portscanAPI interface {
	getResult(*message.AWSQueueMessage, bool) ([]*finding.FindingForUpsert, error)
	listAvailableRegion() ([]*ec2.Region, error)
	listEC2(string) error
	listSecurityGroup() error
	listELB(string) error
	listELBv2() error
	listRDS() error
	listLightsail() error
	excludeScan() []*excludeResult
	scan() ([]*nmapResult, error)
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

func (p *portscanClient) listAvailableRegion() ([]*ec2.Region, error) {
	out, err := p.EC2.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn("Got no regions")
		return nil, nil
	}
	return out.Regions, nil
}

func (p *portscanClient) getResult(message *message.AWSQueueMessage, isFirstRegion bool) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	err := p.listSecurityGroup()
	if err != nil {
		appLogger.Errorf("Faild to describeSecurityGroups: err=%+v", err)
		return putData, err
	}
	err = p.listEC2(message.AccountID)
	if err != nil {
		appLogger.Errorf("Faild to describeInstances: err=%+v", err)
		return putData, err
	}
	err = p.listELB(message.AccountID)
	if err != nil {
		appLogger.Errorf("Faild to describeLoadBalancers: err=%+v", err)
		return putData, err
	}
	err = p.listELBv2()
	if err != nil {
		appLogger.Errorf("Faild to describeLoadBalancers(elbv2): err=%+v", err)
		return putData, err
	}
	err = p.listRDS()
	if err != nil {
		appLogger.Errorf("Faild to describeDBInstances(rds): err=%+v", err)
		return putData, err
	}
	err = p.listLightsail()
	if err != nil {
		appLogger.Errorf("Faild to getInstances(lightsail): err=%+v", err)
		return putData, err
	}
	excludeList := p.excludeScan()
	nmapResults, err := p.scan()
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

func (p *portscanClient) listSecurityGroup() error {
	var retSG []*targetSG
	input := &ec2.DescribeSecurityGroupsInput{}
	result, err := p.EC2.DescribeSecurityGroups(input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeSecurityGroups: %v", err)
		return err
	}
	for _, i := range result.SecurityGroups {
		fPort := 0
		tPort := 65535
		ipProtocol := "all"
		for _, j := range i.IpPermissions {
			if *j.IpProtocol == "tcp" || *j.IpProtocol == "udp" {
				fPort = int(*j.FromPort)
				tPort = int(*j.ToPort)
				ipProtocol = *j.IpProtocol
			}
			for _, k := range j.IpRanges {
				if *k.CidrIp == "0.0.0.0/0" {
					retSG = append(retSG, &targetSG{
						fromPort:  fPort,
						toPort:    tPort,
						protocol:  ipProtocol,
						groupID:   *i.GroupId,
						groupName: *i.GroupName,
					})
				}
			}
		}
	}
	p.SecurityGroups = retSG
	return nil
}

func (p *portscanClient) listEC2(accountID string) error {
	var listEC2 []*infoEC2
	input := &ec2.DescribeInstancesInput{}
	result, err := p.EC2.DescribeInstances(input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeInstances: %v", err)
		return err
	}
	for _, r := range result.Reservations {
		for _, i := range r.Instances {
			for _, j := range i.NetworkInterfaces {
				if j.Association != nil {
					var securityGroups []*string
					for _, k := range j.Groups {
						securityGroups = append(securityGroups, k.GroupId)
					}
					listEC2 = append(listEC2, &infoEC2{
						InstanceID: *i.InstanceId,
						PublicIP:   *j.Association.PublicIp,
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

func (p *portscanClient) listELB(accountID string) error {
	var listELB []*infoELB
	input := &elb.DescribeLoadBalancersInput{}
	result, err := p.ELB.DescribeLoadBalancers(input)
	if err != nil {
		appLogger.Errorf("error occured when DescribeLoadBalancers: %v", err)
		return err
	}
	for _, l := range result.LoadBalancerDescriptions {
		listELB = append(listELB, &infoELB{
			CanonicalHostedZoneName: *l.CanonicalHostedZoneName,
			LoadBalancerName:        *l.LoadBalancerName,
			GroupID:                 l.SecurityGroups,
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
				Target:        elb.CanonicalHostedZoneName,
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

func (p *portscanClient) listELBv2() error {
	var listELBv2 []*infoELBv2
	input := &elbv2.DescribeLoadBalancersInput{}
	result, err := p.ELBv2.DescribeLoadBalancers(input)
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

func (p *portscanClient) listRDS() error {
	var listRDS []*infoRDS
	input := &rds.DescribeDBInstancesInput{}
	result, err := p.RDS.DescribeDBInstances(input)
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

func (p *portscanClient) listLightsail() error {
	input := &lightsail.GetInstancesInput{}
	result, err := p.Lightsail.GetInstances(input)
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
	resultLB, err := p.Lightsail.GetLoadBalancers(inputLB)
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
		appLogger.Infof("SEP: %v", p.ScanExcludePortNumber)
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

func (p *portscanClient) scan() ([]*nmapResult, error) {
	var nmapResults []*nmapResult
	for _, target := range p.target {
		results, err := run(target.Target, target.Protocol, target.FromPort, target.ToPort)
		if err != nil {
			appLogger.Warnf("error occured when scanning. error: %v", err)
			continue
		}
		for _, result := range results {
			result.Arn = target.Arn
			result.SecurityGroup = target.SecurityGroup
			result.ScanDetail = analyzeResult(result.Target, result.Status, result.Service, result.Protocol, result.Port)
			nmapResults = append(nmapResults, result)
		}
	}

	return nmapResults, nil
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

func run(target, protocol string, fPort, tPort int) ([]*nmapResult, error) {
	var nmapResults []*nmapResult
	scanner, err := getScanner(target, protocol, fPort, tPort)
	if err != nil {
		appLogger.Errorf("unable to create nmap scanner %v", err)
		return []*nmapResult{}, err
	}

	result, warn, err := scanner.Run()
	if err != nil {
		appLogger.Errorf("nmap scan failed: %v", err)
		appLogger.Warnf("nmap scan failed error detail: %v", warn)
		return []*nmapResult{}, err
	}
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			nmapResults = append(nmapResults, &nmapResult{
				Port:     int(port.ID),
				Protocol: protocol,
				Target:   target,
				Status:   port.State.State,
				Service:  port.Service.Name,
			})
		}
	}
	return nmapResults, nil
}

func getScanner(host, protocol string, fPort, tPort int) (*nmap.Scanner, error) {
	if protocol == "tcp" {
		scanner, err := nmap.NewScanner(
			nmap.WithTargets(host),
			nmap.WithPorts(fmt.Sprintf("%v", fPort)),
			nmap.WithServiceInfo(),
			nmap.WithSYNScan(),
			nmap.WithTimingTemplate(nmap.TimingAggressive),
		)
		if err != nil {
			appLogger.Errorf("unable to create nmap scanner with TCP: %v", err)
			return nil, err
		}
		return scanner, nil
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(host),
		nmap.WithPorts(fmt.Sprintf("%v-%v", fPort, tPort)),
		nmap.WithServiceInfo(),
		nmap.WithUDPScan(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
	)
	if err != nil {
		appLogger.Errorf("unable to create nmap scanner with UDP: %v", err)

		return nil, err
	}
	return scanner, nil
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
	CanonicalHostedZoneName string
	LoadBalancerName        string
	GroupID                 []*string
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

type nmapResult struct {
	Port          int
	Protocol      string
	Target        string
	Status        string
	Service       string
	Arn           string
	SecurityGroup string
	ScanDetail    map[string]interface{}
}

type excludeResult struct {
	FromPort      int
	ToPort        int
	Protocol      string
	Target        string
	Arn           string
	SecurityGroup string
}
