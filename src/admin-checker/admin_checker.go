package main

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/kelseyhightower/envconfig"
)

type adminCheckerAPI interface {
	listUserFinding(msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error)
	listRoleFinding(msg *message.AWSQueueMessage) (*[]iamRole, error)
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
	if assumeRole == "" {
		return errors.New("Required AWS AssumeRole")
	}
	var cred *credentials.Credentials
	if externalID != "" {
		cred = stscreds.NewCredentials(
			session.New(), assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(externalID)
			},
		)
	} else {
		cred = stscreds.NewCredentials(session.New(), assumeRole)
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: &region, Credentials: cred},
	})
	if err != nil {
		return err
	}
	a.Sess = sess
	a.Svc = iam.New(a.Sess)
	return nil
}

type iamUser struct {
	UserArn                   string                `json:"user_arn"`
	UserName                  string                `json:"user_name"`
	ActiveAccessKeyID         []string              `json:"active_access_key_id"`
	EnabledPermissionBoundory bool                  `json:"enabled_permission_boundory"`
	PermissionBoundoryName    string                `json:"permission_boundory_name"`
	IsUserAdmin               bool                  `json:"is_user_admin"`
	UserAdminPolicy           []string              `json:"user_admin_policy"`
	IsGroupAdmin              bool                  `json:"is_grorup_admin"`
	GroupAdminPolicy          []string              `json:"group_admin_policy"`
	ServiceAccessedReport     serviceAccessedReport `json:"service_accessed_report"`
}

type serviceAccessedReport struct {
	JobID            string  `json:"job_id"`
	JobStatus        string  `json:"job_status"`
	AllowedServices  int     `json:"allowed_services"`
	AccessedServices int     `json:"accessed_services"`
	AccessRate       float32 `json:"access_rate"`
}

func (a *adminCheckerClient) listUserFinding(msg *message.AWSQueueMessage) (*[]iamUser, error) {
	iamUsers, err := a.listUser()
	if err != nil {
		appLogger.Errorf("IAM.ListUser error: err=%+v", err)
		return nil, err
	}
	return iamUsers, nil
}

func (a *adminCheckerClient) listUser() (*[]iamUser, error) {
	users, err := a.Svc.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	var iamUsers []iamUser
	for _, user := range users.Users {
		if user == nil {
			continue
		}
		jobID, err := a.generateServiceLastAccessedDetails(*user.Arn)
		if err != nil {
			return nil, err
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
			ServiceAccessedReport: serviceAccessedReport{
				JobID: jobID,
			},
		})
	}
	for idx, user := range iamUsers {
		jobID := user.ServiceAccessedReport.JobID
		accessedDetail, err := a.analyzeServiceLastAccessedDetails(jobID)
		if err != nil {
			appLogger.Warnf("Failed to analyzServiceAccessedDetails Job, err=%+v", err.Error())
			continue
		}
		iamUsers[idx].ServiceAccessedReport = *accessedDetail
	}
	return &iamUsers, nil
}

func (a *adminCheckerClient) generateServiceLastAccessedDetails(arn string) (string, error) {
	out, err := a.Svc.GenerateServiceLastAccessedDetails(&iam.GenerateServiceLastAccessedDetailsInput{
		Arn:         &arn,
		Granularity: aws.String("SERVICE_LEVEL"), // or ACTION_LEVEL
	})
	if err != nil {
		return "", err
	}
	return *out.JobId, nil
}

const maxRetry = 3

func (a *adminCheckerClient) analyzeServiceLastAccessedDetails(jobID string) (*serviceAccessedReport, error) {
	resp := serviceAccessedReport{
		JobID: jobID,
	}
	retry := 0
BREAK:
	for {
		out, err := a.Svc.GetServiceLastAccessedDetails(&iam.GetServiceLastAccessedDetailsInput{
			JobId: &jobID,
		})
		if err != nil {
			return nil, err
		}
		switch *out.JobStatus {
		case iam.JobStatusTypeFailed:
			errMsg := fmt.Sprintf("Failed to GetServiceLastAccessedDetails, jobID=%s", jobID)
			if out.Error != nil {
				errMsg += fmt.Sprintf(" error_code=%s, message=%s", *out.Error.Code, *out.Error.Message)
			}
			return nil, errors.New(errMsg)
		case iam.JobStatusTypeInProgress:
			retry++
			if retry > maxRetry {
				resp.JobStatus = "TIMEOUT"
				break BREAK
			}
			time.Sleep(time.Millisecond * 1000)
			continue
		case iam.JobStatusTypeCompleted:
			resp.JobStatus = iam.JobStatusTypeCompleted
			resp.AllowedServices = len(out.ServicesLastAccessed)
			for _, accessed := range out.ServicesLastAccessed {
				//appLogger.Debugf("ServicesLastAccessed: %+v", accessed)
				if accessed.LastAuthenticated != nil {
					resp.AccessedServices++
				}
			}
			rate := float64(resp.AccessedServices) / float64(resp.AllowedServices)
			resp.AccessRate = float32(math.Floor(rate*100) / 100)
			appLogger.Debugf("serviceAccessedReport: %+v", resp)
			break BREAK
		default:
			return nil, fmt.Errorf("Unknown Job Status for GetServiceLastAccessedDetails: jobID=%s, status=%s", jobID, *out.JobStatus)
		}
	}
	return &resp, nil
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

type iamRole struct {
	RoleArn               string                `json:"role_arn"`
	RoleID                string                `json:"role_id"`
	RoleName              string                `json:"role_name"`
	Path                  string                `json:"path"`
	MaxSessionDuration    string                `json:"max_session_duration"`
	CreateDate            time.Time             `json:"create_date"`
	ServiceAccessedReport serviceAccessedReport `json:"service_accessed_report"`
}

func (a *adminCheckerClient) listRoleFinding(msg *message.AWSQueueMessage) (*[]iamRole, error) {
	iamRoles, err := a.listRole()
	if err != nil {
		appLogger.Errorf("IAM.ListRole error: err=%+v", err)
		return nil, err
	}
	return iamRoles, nil
}

func (a *adminCheckerClient) listRole() (*[]iamRole, error) {
	roles, err := a.Svc.ListRoles(&iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}
	var iamRoles []iamRole
	for _, role := range roles.Roles {
		if role == nil || strings.HasPrefix(*role.Path, "/aws-service-role/") {
			continue
		}
		jobID, err := a.generateServiceLastAccessedDetails(*role.Arn)
		if err != nil {
			return nil, err
		}
		iamRoles = append(iamRoles, iamRole{
			RoleArn:    *role.Arn,
			RoleID:     *role.RoleId,
			RoleName:   *role.RoleName,
			Path:       *role.Path,
			CreateDate: *role.CreateDate,
			ServiceAccessedReport: serviceAccessedReport{
				JobID: jobID,
			},
		})
	}
	for idx, role := range iamRoles {
		jobID := role.ServiceAccessedReport.JobID
		accessedDetail, err := a.analyzeServiceLastAccessedDetails(jobID)
		if err != nil {
			appLogger.Warnf("Failed to analyzServiceAccessedDetails Job, err=%+v", err.Error())
			continue
		}
		iamRoles[idx].ServiceAccessedReport = *accessedDetail
	}
	return &iamRoles, nil
}
