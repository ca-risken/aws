// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: activity/entity.proto

package activity

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// Validate checks the field values on ARN with the rules defined in the proto
// definition for this message. If any rules are violated, an error is returned.
func (m *ARN) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Partition

	// no validation rules for Service

	// no validation rules for Region

	// no validation rules for AccountId

	// no validation rules for Resource

	// no validation rules for ResourceType

	// no validation rules for ResourceId

	return nil
}

// ARNValidationError is the validation error returned by ARN.Validate if the
// designated constraints aren't met.
type ARNValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ARNValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ARNValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ARNValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ARNValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ARNValidationError) ErrorName() string { return "ARNValidationError" }

// Error satisfies the builtin error interface
func (e ARNValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sARN.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ARNValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ARNValidationError{}

// Validate checks the field values on CloudTrail with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *CloudTrail) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for EventId

	// no validation rules for EventName

	// no validation rules for ReadOnly

	// no validation rules for AccessKeyId

	// no validation rules for EventTime

	// no validation rules for EventSource

	// no validation rules for Username

	for idx, item := range m.GetResources() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CloudTrailValidationError{
					field:  fmt.Sprintf("Resources[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for CloudtrailEvent

	return nil
}

// CloudTrailValidationError is the validation error returned by
// CloudTrail.Validate if the designated constraints aren't met.
type CloudTrailValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CloudTrailValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CloudTrailValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CloudTrailValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CloudTrailValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CloudTrailValidationError) ErrorName() string { return "CloudTrailValidationError" }

// Error satisfies the builtin error interface
func (e CloudTrailValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCloudTrail.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CloudTrailValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CloudTrailValidationError{}

// Validate checks the field values on Resource with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Resource) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for ResourceType

	// no validation rules for ResourceName

	// no validation rules for ResourceId

	// no validation rules for RelationshipName

	return nil
}

// ResourceValidationError is the validation error returned by
// Resource.Validate if the designated constraints aren't met.
type ResourceValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ResourceValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ResourceValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ResourceValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ResourceValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ResourceValidationError) ErrorName() string { return "ResourceValidationError" }

// Error satisfies the builtin error interface
func (e ResourceValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sResource.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ResourceValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ResourceValidationError{}

// Validate checks the field values on Configuration with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *Configuration) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Version

	// no validation rules for AccountId

	// no validation rules for ConfigurationItemCaptureTime

	// no validation rules for ConfigurationItemStatus

	// no validation rules for ConfigurationStateId

	// no validation rules for ConfigurationItemMD5Hash

	// no validation rules for Arn

	// no validation rules for ResourceType

	// no validation rules for ResourceId

	// no validation rules for ResourceName

	// no validation rules for AwsRegion

	// no validation rules for AvailabilityZone

	// no validation rules for ResourceCreationTime

	for idx, item := range m.GetTags() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ConfigurationValidationError{
					field:  fmt.Sprintf("Tags[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetRelationships() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ConfigurationValidationError{
					field:  fmt.Sprintf("Relationships[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for Configuration

	if v, ok := interface{}(m.GetSupplementaryConfiguration()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigurationValidationError{
				field:  "SupplementaryConfiguration",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// ConfigurationValidationError is the validation error returned by
// Configuration.Validate if the designated constraints aren't met.
type ConfigurationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ConfigurationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ConfigurationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ConfigurationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ConfigurationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ConfigurationValidationError) ErrorName() string { return "ConfigurationValidationError" }

// Error satisfies the builtin error interface
func (e ConfigurationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sConfiguration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ConfigurationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ConfigurationValidationError{}

// Validate checks the field values on Tag with the rules defined in the proto
// definition for this message. If any rules are violated, an error is returned.
func (m *Tag) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Key

	// no validation rules for Value

	return nil
}

// TagValidationError is the validation error returned by Tag.Validate if the
// designated constraints aren't met.
type TagValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TagValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TagValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TagValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TagValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TagValidationError) ErrorName() string { return "TagValidationError" }

// Error satisfies the builtin error interface
func (e TagValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTag.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TagValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TagValidationError{}

// Validate checks the field values on SupplementaryConfiguration with the
// rules defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *SupplementaryConfiguration) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Key

	// no validation rules for Value

	return nil
}

// SupplementaryConfigurationValidationError is the validation error returned
// by SupplementaryConfiguration.Validate if the designated constraints aren't met.
type SupplementaryConfigurationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e SupplementaryConfigurationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e SupplementaryConfigurationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e SupplementaryConfigurationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e SupplementaryConfigurationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e SupplementaryConfigurationValidationError) ErrorName() string {
	return "SupplementaryConfigurationValidationError"
}

// Error satisfies the builtin error interface
func (e SupplementaryConfigurationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sSupplementaryConfiguration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = SupplementaryConfigurationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = SupplementaryConfigurationValidationError{}
