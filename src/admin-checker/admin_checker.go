package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/kelseyhightower/envconfig"
)

type adminCheckerAPI interface {
	listUser() (*[]iamUser, error)
}

type adminCheckerClient struct {
	Sess *session.Session
	Svc  *iam.IAM
}

type adminCheckerConfig struct {
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"`
}

func newAdminCheckerClient(assumeRole, externalID string) (*adminCheckerClient, error) {
	var conf adminCheckerConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		return nil, err
	}

	a := adminCheckerClient{}
	if err := a.newAWSSession(conf.AWSRegion, assumeRole, externalID); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *adminCheckerClient) newAWSSession(region, assumeRole, externalID string) error {
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
				sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
					p.ExternalID = aws.String(externalID)
				},
			),
		})
	} else if assumeRole != "" && externalID == "" {
		sess = session.New(&aws.Config{
			Region:      sess.Config.Region,
			Credentials: stscreds.NewCredentials(sess, assumeRole),
		})
	}
	a.Sess = sess
	a.Svc = iam.New(a.Sess)
	return nil
}

type iamUser struct {
	UserArn  string `json:"user_arn"`
	UserName string `json:"user_name"`

	ActiveAccessKeyID []string `json:"active_access_key_id"`

	EnabledPermissionBoundory bool   `json:"enabled_permission_boundory"`
	PermissionBoundoryName    string `json:"permission_boundory_name"`

	IsUserAdmin     bool     `json:"is_user_admin"`
	UserAdminPolicy []string `json:"user_admin_policy"`

	IsGroupAdmin     bool     `json:"is_grorup_admin"`
	GroupAdminPolicy []string `json:"group_admin_policy"`
}

func (a *adminCheckerClient) listUser() (*[]iamUser, error) {
	result, err := a.Svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	var iamUsers []iamUser
	for _, user := range result.Users {
		if user == nil {
			continue
		}
		accessKeys, err := a.listActiveAccessKeyID(user.UserName)
		if err != nil {
			return nil, err
		}
		boundory, err := a.getEnabledPermissionBoundory(user.UserName)
		if err != nil {
			return nil, err
		}
		userAdminPolicy, err := a.getUserAdminPolicy(user.UserName)
		if err != nil {
			return nil, err
		}
		groupAdminPolicy, err := a.getGroupAdminPolicy(user.UserName)
		if err != nil {
			return nil, err
		}
		iamUsers = append(iamUsers, iamUser{
			UserArn:                   *user.Arn,
			UserName:                  *user.UserName,
			ActiveAccessKeyID:         *accessKeys,
			EnabledPermissionBoundory: boundory != "",
			PermissionBoundoryName:    boundory,
			IsUserAdmin:               len(*userAdminPolicy) > 0,
			UserAdminPolicy:           *userAdminPolicy,
			IsGroupAdmin:              len(*groupAdminPolicy) > 0,
			GroupAdminPolicy:          *groupAdminPolicy,
		})
	}
	return &iamUsers, nil
}

func (a *adminCheckerClient) listActiveAccessKeyID(userName *string) (*[]string, error) {
	var accessKeyIDs []string
	result, err := a.Svc.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: userName,
	})
	if err != nil {
		return &accessKeyIDs, err
	}
	for _, key := range result.AccessKeyMetadata {
		if *key.Status == iam.StatusTypeActive {
			accessKeyIDs = append(accessKeyIDs, *key.AccessKeyId)
		}
	}
	return &accessKeyIDs, err
}

// ※ Permission Boundoryが有効かどうかだけ見ます（内容までは見ない）
func (a *adminCheckerClient) getEnabledPermissionBoundory(userName *string) (string, error) {
	result, err := a.Svc.GetUser(&iam.GetUserInput{
		UserName: userName,
	})
	if err != nil {
		return "", err
	}
	boundory := ""
	if result.User != nil && result.User.PermissionsBoundary != nil && result.User.PermissionsBoundary.PermissionsBoundaryArn != nil {
		boundory = *result.User.PermissionsBoundary.PermissionsBoundaryArn
	}
	return boundory, nil
}

func (a *adminCheckerClient) getUserAdminPolicy(userName *string) (*[]string, error) {
	var adminPolicy []string
	// Managed policies
	mngPolicies, err := a.Svc.ListAttachedUserPolicies(
		&iam.ListAttachedUserPoliciesInput{
			UserName: userName,
		})
	if err != nil {
		return nil, err
	}
	for _, p := range mngPolicies.AttachedPolicies {
		if isAdmin, err := a.isAdminManagedPolicy(*p.PolicyArn); err != nil {
			return nil, err
		} else if isAdmin {
			adminPolicy = append(adminPolicy, *p.PolicyArn)
		}
	}

	// Inline policies
	inlinePolicies, err := a.Svc.ListUserPolicies(
		&iam.ListUserPoliciesInput{
			UserName: userName,
		})
	if err != nil {
		return nil, err
	}
	for _, policyNm := range inlinePolicies.PolicyNames {
		if isAdmin, err := a.isAdminUserInlinePolicy(userName, policyNm); err != nil {
			return nil, err

		} else if isAdmin {
			adminPolicy = append(adminPolicy, *policyNm)
		}
	}
	return &adminPolicy, nil
}

func (a *adminCheckerClient) getGroupAdminPolicy(userName *string) (*[]string, error) {
	var adminPolicy []string
	gs, err := a.Svc.ListGroupsForUser(
		&iam.ListGroupsForUserInput{
			UserName: userName,
		})
	if err != nil {
		return nil, err
	}
	for _, g := range gs.Groups {
		// Managed Policy
		mngPolicies, err := a.Svc.ListAttachedGroupPolicies(
			&iam.ListAttachedGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return nil, err
		}
		for _, p := range mngPolicies.AttachedPolicies {
			if isAdmin, err := a.isAdminManagedPolicy(*p.PolicyArn); err != nil {
				return nil, err
			} else if isAdmin {
				adminPolicy = append(adminPolicy, *p.PolicyArn)
			}
		}

		// Inline Policy
		inlinePolicies, err := a.Svc.ListGroupPolicies(
			&iam.ListGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return nil, err
		}
		for _, policyNm := range inlinePolicies.PolicyNames {
			if isAdmin, err := a.isAdminGroupInlinePolicy(g.GroupName, policyNm); err != nil {
				return nil, err

			} else if isAdmin {
				adminPolicy = append(adminPolicy, *policyNm)
			}
		}
	}
	return &adminPolicy, nil
}

const (
	managedAdminArn   = "arn:aws:iam::aws:policy/AdministratorAccess"
	managedIAMFullArn = "arn:aws:iam::aws:policy/IAMFullAccess"
	iamAllAction      = "iam:*"
	allAction1        = "*:*"
	allAction2        = "*"
	allResouce        = "*"
)

// Policy Documentの内容がAdministrator or IAMFullAccess相当かチェックします
// ※Denyルールの有無やConditionsの内容までは見ません
func (a *adminCheckerClient) isAdminPolicyDoc(doc policyDocument) bool {
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			// Denyルールの方が強いが無視
			continue
		}

		dangerAction := false
		for _, a := range stmt.Action {
			if a == allAction1 || a == allAction2 || a == iamAllAction {
				dangerAction = true
				break
			}
		}
		dangerResource := false
		for _, a := range stmt.Resource {
			if a == allResouce {
				dangerResource = true
				break
			}
		}
		if dangerAction && dangerResource {
			return true
		}
	}
	return false
}

// isAdminManagedPolicy AWS Managed Policy / Customer Managed PolicyのAdmin判定
func (a *adminCheckerClient) isAdminManagedPolicy(policyArn string) (bool, error) {
	// Check for AWS Managed policy
	if policyArn == managedAdminArn || policyArn == managedIAMFullArn {
		return true, nil
	}

	// Check for Customer Managed policy
	p, err := a.Svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return false, err
	}
	pv, err := a.Svc.GetPolicyVersion(&iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: p.Policy.DefaultVersionId,
	})
	if err != nil {
		return false, err
	}
	doc, err := convertPolicyDocument(pv.PolicyVersion.Document)
	if err != nil {
		return false, err
	}
	return a.isAdminPolicyDoc(*doc), nil
}

// isAdminUserInlinePolicy Inline PolicyのAdmin判定
func (a *adminCheckerClient) isAdminUserInlinePolicy(userNm, policyNm *string) (bool, error) {
	p, err := a.Svc.GetUserPolicy(&iam.GetUserPolicyInput{
		UserName:   userNm,
		PolicyName: policyNm,
	})
	if err != nil {
		return false, err
	}
	doc, err := convertPolicyDocument(p.PolicyDocument)
	if err != nil {
		return false, err
	}
	return a.isAdminPolicyDoc(*doc), nil
}

// isAdminGroupInlinePolicy Inline PolicyのAdmin判定
func (a *adminCheckerClient) isAdminGroupInlinePolicy(group, policy *string) (bool, error) {
	p, err := a.Svc.GetGroupPolicy(&iam.GetGroupPolicyInput{
		GroupName:  group,
		PolicyName: policy,
	})
	if err != nil {
		return false, err
	}
	doc, err := convertPolicyDocument(p.PolicyDocument)
	if err != nil {
		return false, err
	}
	return a.isAdminPolicyDoc(*doc), nil
}
