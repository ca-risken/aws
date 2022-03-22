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

func (c *CloudsploitConfig) generate(assumeRole, externalID string, awsID uint32, accountID string) error {
	if assumeRole == "" {
		return errors.New("Required AWS AssumeRole")
	}
	creds, err := getCredential(assumeRole, externalID, 3600) // MaxSessionDuration(for API): min=3600, max=3600
	if err != nil {
		return err
	}
	val, err := creds.Get()
	if err != nil {
		return err
	}
	c.ConfigPath, err = c.createConfigFile(val.AccessKeyID, val.SecretAccessKey, val.SessionToken, awsID, accountID)
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

func (c *CloudsploitConfig) createConfigFile(accessKeyID, secretAccessKey, sessoinToken string, awsID uint32, accountID string) (string, error) {
	now := time.Now().UnixNano()
	file, err := os.Create(fmt.Sprintf("%v/%v_%v_%v_config.js", c.ConfigDir, awsID, accountID, now))
	appLogger.Infof("Created config file. filename: %v", file.Name())
	if err != nil {
		return "", err
	}
	defer file.Close()

	config := strings.Replace(awsCredential, "ACCESS_KEY", accessKeyID, 1)
	config = strings.Replace(config, "SECRET_KEY", secretAccessKey, 1)
	config = strings.Replace(config, "SESSION_TOKEN", sessoinToken, 1)
	if _, err := file.Write(([]byte)(config)); err != nil {
		appLogger.Errorf("Failed to write file, filename: %s", file.Name())
	}
	return file.Name(), nil
}

func getCredential(assumeRole, externalID string, duration int) (*credentials.Credentials, error) {
	sess, err := session.NewSession()
	if err != nil {
		appLogger.Errorf("Failed to create session, err=%+v", err)
		return nil, err
	}

	var creds *credentials.Credentials
	if externalID != "" {
		creds = stscreds.NewCredentials(
			sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(externalID)
				p.Duration = time.Duration(duration) * time.Second
			},
		)
	} else {
		creds = stscreds.NewCredentials(
			sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.Duration = time.Duration(duration) * time.Second
			},
		)
	}
	return creds, nil
}
