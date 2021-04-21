# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [activity/entity.proto](#activity/entity.proto)
    - [CloudTrail](#aws.activity.CloudTrail)
    - [Resource](#aws.activity.Resource)
  
- [activity/service.proto](#activity/service.proto)
    - [ListCloudTrailRequest](#aws.activity.ListCloudTrailRequest)
    - [ListCloudTrailResponse](#aws.activity.ListCloudTrailResponse)
  
    - [ActivityService](#aws.activity.ActivityService)
  
- [aws/entity.proto](#aws/entity.proto)
    - [AWS](#aws.aws.AWS)
    - [AWSForUpsert](#aws.aws.AWSForUpsert)
    - [AWSRelDataSource](#aws.aws.AWSRelDataSource)
    - [DataSource](#aws.aws.DataSource)
    - [DataSourceForAttach](#aws.aws.DataSourceForAttach)
  
    - [Status](#aws.aws.Status)
  
- [aws/service.proto](#aws/service.proto)
    - [AttachDataSourceRequest](#aws.aws.AttachDataSourceRequest)
    - [AttachDataSourceResponse](#aws.aws.AttachDataSourceResponse)
    - [DeleteAWSRequest](#aws.aws.DeleteAWSRequest)
    - [DetachDataSourceRequest](#aws.aws.DetachDataSourceRequest)
    - [InvokeScanRequest](#aws.aws.InvokeScanRequest)
    - [ListAWSRequest](#aws.aws.ListAWSRequest)
    - [ListAWSResponse](#aws.aws.ListAWSResponse)
    - [ListDataSourceRequest](#aws.aws.ListDataSourceRequest)
    - [ListDataSourceResponse](#aws.aws.ListDataSourceResponse)
    - [PutAWSRequest](#aws.aws.PutAWSRequest)
    - [PutAWSResponse](#aws.aws.PutAWSResponse)
  
    - [AWSService](#aws.aws.AWSService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="activity/entity.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## activity/entity.proto



<a name="aws.activity.CloudTrail"></a>

### CloudTrail
CloudTrail:
https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html#output


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event_id | [string](#string) |  |  |
| event_name | [string](#string) |  |  |
| read_only | [string](#string) |  |  |
| access_key_id | [string](#string) |  |  |
| event_time | [int64](#int64) |  |  |
| event_source | [string](#string) |  |  |
| username | [string](#string) |  |  |
| resources | [Resource](#aws.activity.Resource) | repeated |  |
| cloudtrail_event | [string](#string) |  | Raw data(JSON) |






<a name="aws.activity.Resource"></a>

### Resource



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| resource_type | [string](#string) |  |  |
| resource_name | [string](#string) |  |  |





 

 

 

 



<a name="activity/service.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## activity/service.proto



<a name="aws.activity.ListCloudTrailRequest"></a>

### ListCloudTrailRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  | CloudTrail lookup-events API parameters: https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html |
| start_time | [int64](#int64) |  |  |
| end_time | [int64](#int64) |  |  |
| event_id | [string](#string) |  |  |
| event_name | [string](#string) |  |  |
| event_source | [string](#string) |  |  |
| read_only | [string](#string) |  |  |
| resource_name | [string](#string) |  |  |
| resource_type | [string](#string) |  |  |
| user_name | [string](#string) |  |  |
| next_token | [string](#string) |  |  |






<a name="aws.activity.ListCloudTrailResponse"></a>

### ListCloudTrailResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cloudtrail | [CloudTrail](#aws.activity.CloudTrail) | repeated |  |
| next_token | [string](#string) |  |  |





 

 

 


<a name="aws.activity.ActivityService"></a>

### ActivityService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ListCloudTrail | [ListCloudTrailRequest](#aws.activity.ListCloudTrailRequest) | [ListCloudTrailResponse](#aws.activity.ListCloudTrailResponse) |  |

 



<a name="aws/entity.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## aws/entity.proto



<a name="aws.aws.AWS"></a>

### AWS
AWS


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| aws_account_id | [string](#string) |  | 12桁のAWSアカウントID |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="aws.aws.AWSForUpsert"></a>

### AWSForUpsert
AWSForUpsert
(Unique keys: aws_account_id)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| aws_account_id | [string](#string) |  | 12桁のAWSアカウントID |






<a name="aws.aws.AWSRelDataSource"></a>

### AWSRelDataSource
AWSRelDataSource


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |
| project_id | [uint32](#uint32) |  |  |
| assume_role_arn | [string](#string) |  |  |
| external_id | [string](#string) |  |  |
| status | [Status](#aws.aws.Status) |  |  |
| status_detail | [string](#string) |  |  |
| scan_at | [int64](#int64) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="aws.aws.DataSource"></a>

### DataSource
DataSource(data_sourceと紐づくaws_rel_data_sourceの状態)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_data_source_id | [uint32](#uint32) |  | aws_data_source.aws_data_source_id |
| data_source | [string](#string) |  | aws_data_source.data_source |
| max_score | [float](#float) |  | aws_data_source.max_score |
| aws_id | [uint32](#uint32) |  | aws_rel_data_source.aws_id |
| project_id | [uint32](#uint32) |  | aws_rel_data_source.project_id |
| assume_role_arn | [string](#string) |  | aws_rel_data_source.assume_role_arn |
| external_id | [string](#string) |  | aws_rel_data_source.external_id |
| status | [Status](#aws.aws.Status) |  | aws_rel_data_source.status |
| status_detail | [string](#string) |  | aws_rel_data_source.status_detail |
| scan_at | [int64](#int64) |  | aws_rel_data_source.scan_at |






<a name="aws.aws.DataSourceForAttach"></a>

### DataSourceForAttach
DataSourceForAttach


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |
| project_id | [uint32](#uint32) |  |  |
| assume_role_arn | [string](#string) |  |  |
| external_id | [string](#string) |  | assume_role時に指定する外部ID |
| status | [Status](#aws.aws.Status) |  |  |
| status_detail | [string](#string) |  |  |
| scan_at | [int64](#int64) |  |  |





 


<a name="aws.aws.Status"></a>

### Status
Status

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| OK | 1 |  |
| CONFIGURED | 2 |  |
| IN_PROGRESS | 3 |  |
| ERROR | 4 |  |


 

 

 



<a name="aws/service.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## aws/service.proto



<a name="aws.aws.AttachDataSourceRequest"></a>

### AttachDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| attach_data_source | [DataSourceForAttach](#aws.aws.DataSourceForAttach) |  |  |






<a name="aws.aws.AttachDataSourceResponse"></a>

### AttachDataSourceResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data_source | [AWSRelDataSource](#aws.aws.AWSRelDataSource) |  |  |






<a name="aws.aws.DeleteAWSRequest"></a>

### DeleteAWSRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |






<a name="aws.aws.DetachDataSourceRequest"></a>

### DetachDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |






<a name="aws.aws.InvokeScanRequest"></a>

### InvokeScanRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |






<a name="aws.aws.ListAWSRequest"></a>

### ListAWSRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| aws_account_id | [string](#string) |  |  |






<a name="aws.aws.ListAWSResponse"></a>

### ListAWSResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws | [AWS](#aws.aws.AWS) | repeated |  |






<a name="aws.aws.ListDataSourceRequest"></a>

### ListDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| data_source | [string](#string) |  |  |






<a name="aws.aws.ListDataSourceResponse"></a>

### ListDataSourceResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data_source | [DataSource](#aws.aws.DataSource) | repeated |  |






<a name="aws.aws.PutAWSRequest"></a>

### PutAWSRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| project_id | [uint32](#uint32) |  |  |
| aws | [AWSForUpsert](#aws.aws.AWSForUpsert) |  |  |






<a name="aws.aws.PutAWSResponse"></a>

### PutAWSResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws | [AWS](#aws.aws.AWS) |  |  |





 

 

 


<a name="aws.aws.AWSService"></a>

### AWSService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ListAWS | [ListAWSRequest](#aws.aws.ListAWSRequest) | [ListAWSResponse](#aws.aws.ListAWSResponse) | AWS |
| PutAWS | [PutAWSRequest](#aws.aws.PutAWSRequest) | [PutAWSResponse](#aws.aws.PutAWSResponse) |  |
| DeleteAWS | [DeleteAWSRequest](#aws.aws.DeleteAWSRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) |  |
| ListDataSource | [ListDataSourceRequest](#aws.aws.ListDataSourceRequest) | [ListDataSourceResponse](#aws.aws.ListDataSourceResponse) | AWS DataSource |
| AttachDataSource | [AttachDataSourceRequest](#aws.aws.AttachDataSourceRequest) | [AttachDataSourceResponse](#aws.aws.AttachDataSourceResponse) |  |
| DetachDataSource | [DetachDataSourceRequest](#aws.aws.DetachDataSourceRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) |  |
| InvokeScan | [InvokeScanRequest](#aws.aws.InvokeScanRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | Scan

For ondeamnd |
| InvokeScanAll | [.google.protobuf.Empty](#google.protobuf.Empty) | [.google.protobuf.Empty](#google.protobuf.Empty) | For scheduled |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

