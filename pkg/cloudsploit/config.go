package cloudsploit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func (c *CloudsploitConfig) generate(ctx context.Context, assumeRole, externalID string, awsID uint32, accountID string) error {
	if assumeRole == "" {
		return errors.New("required AWS AssumeRole")
	}
	c.assumeRole = assumeRole
	if externalID == "" {
		return errors.New("required AWS ExternalID")
	}
	c.externalID = externalID

	creds, err := getCredential(ctx, assumeRole, externalID, time.Duration(3600)*time.Second) // MaxSessionDuration(for API): min=3600, max=3600
	if err != nil {
		return fmt.Errorf("credential error: %w", err)
	}
	c.ConfigPath, err = c.createConfigFile(ctx, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, awsID, accountID)
	return err
}

const awsCredential string = `
module.exports = {
    credentials: {
        aws: {
            access_key: 'ACCESS_KEY',
            secret_access_key: 'SECRET_KEY',
            session_token: 'SESSION_TOKEN',
        },
    },
};
`

func (c *CloudsploitConfig) createConfigFile(ctx context.Context, accessKeyID, secretAccessKey, sessoinToken string, awsID uint32, accountID string) (string, error) {
	now := time.Now().UnixNano()
	file, err := os.Create(fmt.Sprintf("%v/%v_%v_%v_config.js", c.ConfigDir, awsID, accountID, now))
	c.logger.Infof(ctx, "Created config file. filename: %v", file.Name())
	if err != nil {
		return "", err
	}
	defer file.Close()

	config := strings.Replace(awsCredential, "ACCESS_KEY", accessKeyID, 1)
	config = strings.Replace(config, "SECRET_KEY", secretAccessKey, 1)
	config = strings.Replace(config, "SESSION_TOKEN", sessoinToken, 1)
	if _, err := file.Write(([]byte)(config)); err != nil {
		return "", fmt.Errorf("failed to write file, filename: %s, err: %w", file.Name(), err)
	}
	return file.Name(), nil
}

func getCredential(ctx context.Context, assumeRole, externalID string, duration time.Duration) (*aws.Credentials, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRole,
		func(p *stscreds.AssumeRoleOptions) {
			p.RoleSessionName = "RISKEN"
			p.ExternalID = &externalID
			p.Duration = duration
		},
	)
	cfg.Credentials = aws.NewCredentialsCache(provider)
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	return &creds, nil
}

const (
	REGION_US_EAST_1 = "us-east-1"
	API_RETRY_NUM    = 10
)

func newEC2Session(ctx context.Context, assumeRole, externalID, region string) (*ec2.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(REGION_US_EAST_1))
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRole,
		func(p *stscreds.AssumeRoleOptions) {
			p.RoleSessionName = "RISKEN"
			p.ExternalID = &externalID
		},
	)
	cfg.Credentials = aws.NewCredentialsCache(provider)
	if _, err = cfg.Credentials.Retrieve(ctx); err != nil {
		return nil, err
	}
	return ec2.New(ec2.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: API_RETRY_NUM}), nil
}
