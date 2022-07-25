package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ca-risken/datasource-api/pkg/message"
)

type adminCheckerAPI interface {
	listUserFinding(ctx context.Context, msg *message.AWSQueueMessage) (*[]iamUser, error)
	listRoleFinding(ctx context.Context, msg *message.AWSQueueMessage) (*[]iamRole, error)
}

type adminCheckerClient struct {
	Svc *iam.Client
}

func newAdminCheckerClient(ctx context.Context, awsRegion, assumeRole, externalID string, retry int) (adminCheckerAPI, error) {
	a := adminCheckerClient{}
	if err := a.newAWSSession(ctx, awsRegion, assumeRole, externalID, retry); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *adminCheckerClient) newAWSSession(ctx context.Context, region, assumeRole, externalID string, retry int) error {
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
	a.Svc = iam.New(iam.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	return nil
}

type iamUser struct {
	UserArn                   string                `json:"user_arn"`
	UserName                  string                `json:"user_name"`
	ActiveAccessKeyID         []string              `json:"active_access_key_id"`
	EnabledPhysicalMFA        bool                  `json:"enabled_physical_mfa"`
	EnabledVirtualMFA         bool                  `json:"enabled_virtual_mfa"`
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

func (a *adminCheckerClient) listUserFinding(ctx context.Context, msg *message.AWSQueueMessage) (*[]iamUser, error) {
	iamUsers, err := a.listUser(ctx)
	if err != nil {
		appLogger.Errorf(ctx, "IAM.ListUser error: err=%+v", err)
		return nil, err
	}
	return iamUsers, nil
}

func (a *adminCheckerClient) listUser(ctx context.Context) (*[]iamUser, error) {
	users, err := a.Svc.ListUsers(ctx, &iam.ListUsersInput{})
	if err != nil {
		return nil, err
	}
	var iamUsers []iamUser
	for _, user := range users.Users {
		jobID, err := a.generateServiceLastAccessedDetails(ctx, *user.Arn)
		if err != nil {
			return nil, err
		}
		accessKeys, err := a.listActiveAccessKeyID(ctx, user.UserName)
		if err != nil {
			return nil, err
		}
		enabledPhysicalMFA, err := a.enabledPhysicalMFA(ctx, user.UserName)
		if err != nil {
			return nil, err
		}
		enabledVirtualMFA, err := a.enabledVirtualMFA(ctx, *user.Arn)
		if err != nil {
			return nil, err
		}
		boundory, err := a.getEnabledPermissionBoundory(ctx, user.UserName)
		if err != nil {
			return nil, err
		}
		userAdminPolicy, err := a.getUserAdminPolicy(ctx, user.UserName)
		if err != nil {
			return nil, err
		}
		groupAdminPolicy, err := a.getGroupAdminPolicy(ctx, user.UserName)
		if err != nil {
			return nil, err
		}
		iamUsers = append(iamUsers, iamUser{
			UserArn:                   *user.Arn,
			UserName:                  *user.UserName,
			ActiveAccessKeyID:         *accessKeys,
			EnabledPhysicalMFA:        enabledPhysicalMFA,
			EnabledVirtualMFA:         enabledVirtualMFA,
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
		time.Sleep(time.Millisecond * 1000) // For control the API call rating.
	}
	for idx, user := range iamUsers {
		jobID := user.ServiceAccessedReport.JobID
		accessedDetail, err := a.analyzeServiceLastAccessedDetails(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("failed analyzeServiceAccessedDetails Job, err=%w", err)
		}
		iamUsers[idx].ServiceAccessedReport = *accessedDetail
		time.Sleep(time.Millisecond * 1000) // For control the API call rating.
	}
	return &iamUsers, nil
}

func (a *adminCheckerClient) generateServiceLastAccessedDetails(ctx context.Context, arn string) (string, error) {
	out, err := a.Svc.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
		Arn:         &arn,
		Granularity: types.AccessAdvisorUsageGranularityTypeServiceLevel,
	})
	if err != nil {
		return "", err
	}
	return *out.JobId, nil
}

const maxRetry = 3

func (a *adminCheckerClient) analyzeServiceLastAccessedDetails(ctx context.Context, jobID string) (*serviceAccessedReport, error) {
	resp := serviceAccessedReport{
		JobID: jobID,
	}
	retry := 0
BREAK:
	for {
		out, err := a.Svc.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId: &jobID,
		})
		if err != nil {
			return nil, err
		}
		switch out.JobStatus {
		case types.JobStatusTypeFailed:
			errMsg := fmt.Sprintf("failed to GetServiceLastAccessedDetails, jobID=%s", jobID)
			if out.Error != nil {
				errMsg += fmt.Sprintf(" error_code=%s, message=%s", *out.Error.Code, *out.Error.Message)
			}
			return nil, errors.New(errMsg)
		case types.JobStatusTypeInProgress:
			retry++
			if retry > maxRetry {
				resp.JobStatus = "TIMEOUT"
				break BREAK
			}
			time.Sleep(time.Millisecond * 1000)
			continue
		case types.JobStatusTypeCompleted:
			resp.JobStatus = "COMPLETED"
			resp.AllowedServices = len(out.ServicesLastAccessed)
			for _, accessed := range out.ServicesLastAccessed {
				appLogger.Debugf(ctx, "ServicesLastAccessed: %+v", accessed)
				if accessed.LastAuthenticated != nil {
					resp.AccessedServices++
				}
			}
			rate := float64(resp.AccessedServices) / float64(resp.AllowedServices)
			if math.IsNaN(rate) {
				resp.AccessRate = 1.0
			} else {
				resp.AccessRate = float32(math.Floor(rate*100) / 100)
			}
			appLogger.Debugf(ctx, "serviceAccessedReport: %+v", resp)
			break BREAK
		default:
			return nil, fmt.Errorf("unknown Job Status for GetServiceLastAccessedDetails: jobID=%s, status=%s", jobID, out.JobStatus)
		}
	}
	return &resp, nil
}

func (a *adminCheckerClient) listActiveAccessKeyID(ctx context.Context, userName *string) (*[]string, error) {
	var accessKeyIDs []string
	result, err := a.Svc.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: userName,
	})
	if err != nil {
		return &accessKeyIDs, err
	}
	for _, key := range result.AccessKeyMetadata {
		if key.Status == types.StatusTypeActive {
			accessKeyIDs = append(accessKeyIDs, *key.AccessKeyId)
		}
	}
	return &accessKeyIDs, err
}

func (a *adminCheckerClient) enabledPhysicalMFA(ctx context.Context, userName *string) (bool, error) {
	result, err := a.Svc.ListMFADevices(ctx, &iam.ListMFADevicesInput{
		UserName: userName,
	})
	if err != nil {
		return false, err
	}
	return len(result.MFADevices) > 0, err
}

func (a *adminCheckerClient) enabledVirtualMFA(ctx context.Context, userARN string) (bool, error) {
	result, err := a.Svc.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{
		AssignmentStatus: types.AssignmentStatusTypeAssigned,
	})
	if err != nil {
		return false, err
	}
	for _, device := range result.VirtualMFADevices {
		if device.User != nil && *device.User.Arn == userARN {
			return true, nil
		}
	}
	return false, err
}

// ※ Permission Boundoryが有効かどうかだけ見ます（内容までは見ない）
func (a *adminCheckerClient) getEnabledPermissionBoundory(ctx context.Context, userName *string) (string, error) {
	result, err := a.Svc.GetUser(ctx, &iam.GetUserInput{
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

func (a *adminCheckerClient) getUserAdminPolicy(ctx context.Context, userName *string) (*[]string, error) {
	var adminPolicy []string
	// Managed policies
	mngPolicies, err := a.Svc.ListAttachedUserPolicies(
		ctx,
		&iam.ListAttachedUserPoliciesInput{
			UserName: userName,
		})
	if err != nil {
		return nil, err
	}
	for _, p := range mngPolicies.AttachedPolicies {
		if isAdmin, err := a.isAdminManagedPolicy(ctx, *p.PolicyArn); err != nil {
			return nil, err
		} else if isAdmin {
			adminPolicy = append(adminPolicy, *p.PolicyArn)
		}
	}

	// Inline policies
	inlinePolicies, err := a.Svc.ListUserPolicies(
		ctx,
		&iam.ListUserPoliciesInput{
			UserName: userName,
		})
	if err != nil {
		return nil, err
	}
	for _, policyNm := range inlinePolicies.PolicyNames {
		if isAdmin, err := a.isAdminUserInlinePolicy(ctx, userName, &policyNm); err != nil {
			return nil, err

		} else if isAdmin {
			adminPolicy = append(adminPolicy, policyNm)
		}
	}
	return &adminPolicy, nil
}

func (a *adminCheckerClient) getGroupAdminPolicy(ctx context.Context, userName *string) (*[]string, error) {
	var adminPolicy []string
	gs, err := a.Svc.ListGroupsForUser(
		ctx,
		&iam.ListGroupsForUserInput{
			UserName: userName,
		})
	if err != nil {
		return nil, err
	}
	for _, g := range gs.Groups {
		// Managed Policy
		mngPolicies, err := a.Svc.ListAttachedGroupPolicies(
			ctx,
			&iam.ListAttachedGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return nil, err
		}
		for _, p := range mngPolicies.AttachedPolicies {
			if isAdmin, err := a.isAdminManagedPolicy(ctx, *p.PolicyArn); err != nil {
				return nil, err
			} else if isAdmin {
				adminPolicy = append(adminPolicy, *p.PolicyArn)
			}
		}

		// Inline Policy
		inlinePolicies, err := a.Svc.ListGroupPolicies(
			ctx,
			&iam.ListGroupPoliciesInput{
				GroupName: aws.String(*g.GroupName),
			})
		if err != nil {
			return nil, err
		}
		for _, policyNm := range inlinePolicies.PolicyNames {
			if isAdmin, err := a.isAdminGroupInlinePolicy(ctx, g.GroupName, &policyNm); err != nil {
				return nil, err

			} else if isAdmin {
				adminPolicy = append(adminPolicy, policyNm)
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
func (a *adminCheckerClient) isAdminManagedPolicy(ctx context.Context, policyArn string) (bool, error) {
	// Check for AWS Managed policy
	if policyArn == managedAdminArn || policyArn == managedIAMFullArn {
		return true, nil
	}

	// Check for Customer Managed policy
	p, err := a.Svc.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return false, err
	}
	pv, err := a.Svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
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
func (a *adminCheckerClient) isAdminUserInlinePolicy(ctx context.Context, userNm, policyNm *string) (bool, error) {
	p, err := a.Svc.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
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
func (a *adminCheckerClient) isAdminGroupInlinePolicy(ctx context.Context, group, policy *string) (bool, error) {
	p, err := a.Svc.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
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

func (a *adminCheckerClient) listRoleFinding(ctx context.Context, msg *message.AWSQueueMessage) (*[]iamRole, error) {
	iamRoles, err := a.listRole(ctx)
	if err != nil {
		appLogger.Errorf(ctx, "IAM.ListRole error: err=%+v", err)
		return nil, err
	}
	return iamRoles, nil
}

func (a *adminCheckerClient) listRole(ctx context.Context) (*[]iamRole, error) {
	roles, err := a.Svc.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}
	var iamRoles []iamRole
	for _, role := range roles.Roles {
		if role.Path == nil || strings.HasPrefix(*role.Path, "/aws-service-role/") {
			continue
		}
		jobID, err := a.generateServiceLastAccessedDetails(ctx, *role.Arn)
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
		time.Sleep(time.Millisecond * 1000) // For control the API call rating.
	}
	for idx, role := range iamRoles {
		jobID := role.ServiceAccessedReport.JobID
		accessedDetail, err := a.analyzeServiceLastAccessedDetails(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("failed analyzeServiceAccessedDetails Job, err=%w", err)
		}
		iamRoles[idx].ServiceAccessedReport = *accessedDetail
		time.Sleep(time.Millisecond * 1000) // For control the API call rating.
	}
	return &iamRoles, nil
}
