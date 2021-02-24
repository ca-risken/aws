package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
)

func (c *cloudsploitConfig) makeConfig(region, assumeRole, externalID string) (string, error) {
	if assumeRole == "" {
		return "", errors.New("Required AWS AssumeRole")
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)
	if err != nil {
		return "", err
	}
	var creds *credentials.Credentials
	if externalID != "" {
		creds = stscreds.NewCredentials(
			sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(externalID)
				p.Duration = time.Duration(60) * time.Minute
			},
		)
	} else {
		creds = stscreds.NewCredentials(
			sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.Duration = time.Duration(60) * time.Minute
			},
		)
	}
	val, err := creds.Get()
	if err != nil {
		return "", err
	}
	configPath, err := c.createConfigFile(val.AccessKeyID, val.SecretAccessKey, val.SessionToken)
	if err != nil {
		return "", err
	}
	return configPath, nil
}

const awsCredential string = `
module.exports = {
    credentials: {
        aws: {
                access_key: 'ACCESS_KEY',
                secret_access_key: 'SECRET_KEY',
                session_token: 'SESSION_TOKEN',
            // plugins_remediate: ['bucketEncryptionInTransit']
        },
    }
};
`

func (c *cloudsploitConfig) createConfigFile(accessKeyID, secretAccessKey, sessoinToken string) (string, error) {
	now := time.Now().UnixNano()
	file, err := os.Create(fmt.Sprintf("%v/%v_%v_config.js", c.ConfigDir, accessKeyID, now))
	if err != nil {
		return "", err
	}
	defer file.Close()

	config := strings.Replace(awsCredential, "ACCESS_KEY", accessKeyID, 1)
	config = strings.Replace(config, "SECRET_KEY", secretAccessKey, 1)
	config = strings.Replace(config, "SESSION_TOKEN", sessoinToken, 1)
	file.Write(([]byte)(config))
	return file.Name(), nil
}
