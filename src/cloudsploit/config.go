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
	"github.com/aws/aws-sdk-go/service/iam"
)

func (c *cloudsploitConfig) makeConfig(region, assumeRole, externalID string, awsID uint32, accountID string) (string, error) {
	if assumeRole == "" {
		return "", errors.New("Required AWS AssumeRole")
	}
	creds := getCredential(assumeRole, externalID, 3600)
	roleDuration, err := getRoleMaxSessionDuration(creds, region, assumeRole)
	if err == nil && roleDuration != 3600 {
		creds = getCredential(assumeRole, externalID, roleDuration)
	}
	val, err := creds.Get()
	if err != nil {
		return "", err
	}
	configPath, err := c.createConfigFile(val.AccessKeyID, val.SecretAccessKey, val.SessionToken, awsID, accountID)
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

func (c *cloudsploitConfig) createConfigFile(accessKeyID, secretAccessKey, sessoinToken string, awsID uint32, accountID string) (string, error) {
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
	file.Write(([]byte)(config))
	return file.Name(), nil
}

func getCredential(assumeRole, externalID string, duration int) *credentials.Credentials {
	var creds *credentials.Credentials
	if externalID != "" {
		creds = stscreds.NewCredentials(
			session.New(), assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(externalID)
				p.Duration = time.Duration(duration) * time.Second
			},
		)
	} else {
		creds = stscreds.NewCredentials(
			session.New(), assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.Duration = time.Duration(duration) * time.Second
			},
		)
	}
	return creds
}

func getRoleMaxSessionDuration(cred *credentials.Credentials, region, assumeRole string) (int, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: &region, Credentials: cred},
	})
	if err != nil {
		return 0, err
	}
	svc := iam.New(sess)
	roleName := strings.Split(assumeRole, "/")[len(strings.Split(assumeRole, "/"))-1]
	res, err := svc.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return 0, err
	}
	return int(*res.Role.MaxSessionDuration), nil
}
