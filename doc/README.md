# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [controller/entity.proto](#controller/entity.proto)
    - [AWS](#aws.controller.AWS)
    - [AWSForUpsert](#aws.controller.AWSForUpsert)
    - [AWSRole](#aws.controller.AWSRole)
    - [AWSRoleForUpsert](#aws.controller.AWSRoleForUpsert)
    - [DataSource](#aws.controller.DataSource)
    - [DataSourceForAttach](#aws.controller.DataSourceForAttach)
  
- [controller/service.proto](#controller/service.proto)
    - [AttachDataSourceRequest](#aws.controller.AttachDataSourceRequest)
    - [AttachDataSourceResponse](#aws.controller.AttachDataSourceResponse)
    - [DeleteAWSRequest](#aws.controller.DeleteAWSRequest)
    - [DetachDataSourceRequest](#aws.controller.DetachDataSourceRequest)
    - [InvokeScanRequest](#aws.controller.InvokeScanRequest)
    - [ListAWSRequest](#aws.controller.ListAWSRequest)
    - [ListAWSResponse](#aws.controller.ListAWSResponse)
    - [ListAWSRoleRequest](#aws.controller.ListAWSRoleRequest)
    - [ListAWSRoleResponse](#aws.controller.ListAWSRoleResponse)
    - [ListDataSourceRequest](#aws.controller.ListDataSourceRequest)
    - [ListDataSourceResponse](#aws.controller.ListDataSourceResponse)
    - [PutAWSRequest](#aws.controller.PutAWSRequest)
    - [PutAWSResponse](#aws.controller.PutAWSResponse)
    - [PutAWSRoleRequest](#aws.controller.PutAWSRoleRequest)
    - [PutAWSRoleResponse](#aws.controller.PutAWSRoleResponse)
  
    - [AWSService](#aws.controller.AWSService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="controller/entity.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## controller/entity.proto



<a name="aws.controller.AWS"></a>

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






<a name="aws.controller.AWSForUpsert"></a>

### AWSForUpsert
AWSForUpsert
(Unique keys: aws_account_id)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |
| aws_account_id | [string](#string) |  | 12桁のAWSアカウントID |






<a name="aws.controller.AWSRole"></a>

### AWSRole
AWSRole


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_role_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| assume_role_arn | [string](#string) |  |  |
| external_id | [string](#string) |  | AssumeRole時に指定するキー。 |
| activated | [bool](#bool) |  |  |
| created_at | [int64](#int64) |  |  |
| updated_at | [int64](#int64) |  |  |






<a name="aws.controller.AWSRoleForUpsert"></a>

### AWSRoleForUpsert
AWSRoleForUpsert
(Unique keys: assume_role_arn, external_id)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| assume_role_arn | [string](#string) |  |  |
| external_id | [string](#string) |  |  |
| activated | [bool](#bool) |  |  |






<a name="aws.controller.DataSource"></a>

### DataSource
DataSource(data_sourceと紐づくaws_idのリレーション状態)


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_data_source_id | [uint32](#uint32) |  | aws_data_source.aws_data_source_id |
| data_source | [string](#string) |  | aws_data_source.data_source |
| max_score | [float](#float) |  | aws_data_source.max_score |
| aws_id | [uint32](#uint32) |  | aws_rel_data_source.aws_id |
| project_id | [uint32](#uint32) |  | aws_rel_data_source.project_id |
| aws_role_id | [uint32](#uint32) |  | aws_rel_data_source.aws_role_id |
| assume_role_arn | [string](#string) |  | aws_role.assume_role_arn |
| external_id | [string](#string) |  | aws_role.external_id |






<a name="aws.controller.DataSourceForAttach"></a>

### DataSourceForAttach
DataSourceForAttach


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |
| aws_role_id | [uint32](#uint32) |  |  |
| project_id | [uint32](#uint32) |  |  |





 

 

 

 



<a name="controller/service.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## controller/service.proto



<a name="aws.controller.AttachDataSourceRequest"></a>

### AttachDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| attach_data_source | [DataSourceForAttach](#aws.controller.DataSourceForAttach) |  |  |






<a name="aws.controller.AttachDataSourceResponse"></a>

### AttachDataSourceResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data_source | [DataSource](#aws.controller.DataSource) |  |  |






<a name="aws.controller.DeleteAWSRequest"></a>

### DeleteAWSRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |






<a name="aws.controller.DetachDataSourceRequest"></a>

### DetachDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |






<a name="aws.controller.InvokeScanRequest"></a>

### InvokeScanRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| aws_data_source_id | [uint32](#uint32) |  |  |






<a name="aws.controller.ListAWSRequest"></a>

### ListAWSRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| project_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| aws_account_id | [string](#string) |  |  |






<a name="aws.controller.ListAWSResponse"></a>

### ListAWSResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws | [AWS](#aws.controller.AWS) | repeated |  |






<a name="aws.controller.ListAWSRoleRequest"></a>

### ListAWSRoleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws_role_id | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| activated | [bool](#bool) |  |  |






<a name="aws.controller.ListAWSRoleResponse"></a>

### ListAWSRoleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_role | [AWSRole](#aws.controller.AWSRole) | repeated |  |






<a name="aws.controller.ListDataSourceRequest"></a>

### ListDataSourceRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws_id | [uint32](#uint32) |  |  |
| data_source | [string](#string) |  |  |
| project_id | [uint32](#uint32) |  |  |






<a name="aws.controller.ListDataSourceResponse"></a>

### ListDataSourceResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data_source | [DataSource](#aws.controller.DataSource) | repeated |  |






<a name="aws.controller.PutAWSRequest"></a>

### PutAWSRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws | [AWSForUpsert](#aws.controller.AWSForUpsert) |  |  |






<a name="aws.controller.PutAWSResponse"></a>

### PutAWSResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws | [AWS](#aws.controller.AWS) |  |  |






<a name="aws.controller.PutAWSRoleRequest"></a>

### PutAWSRoleRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| user_id | [uint32](#uint32) |  |  |
| aws_role | [AWSRoleForUpsert](#aws.controller.AWSRoleForUpsert) |  |  |






<a name="aws.controller.PutAWSRoleResponse"></a>

### PutAWSRoleResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aws_role | [AWSRole](#aws.controller.AWSRole) |  |  |





 

 

 


<a name="aws.controller.AWSService"></a>

### AWSService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| ListAWS | [ListAWSRequest](#aws.controller.ListAWSRequest) | [ListAWSResponse](#aws.controller.ListAWSResponse) | AWS |
| PutAWS | [PutAWSRequest](#aws.controller.PutAWSRequest) | [PutAWSResponse](#aws.controller.PutAWSResponse) |  |
| DeleteAWS | [DeleteAWSRequest](#aws.controller.DeleteAWSRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) |  |
| ListAWSRole | [ListAWSRoleRequest](#aws.controller.ListAWSRoleRequest) | [ListAWSRoleResponse](#aws.controller.ListAWSRoleResponse) | AWS Role |
| PutAWSRole | [PutAWSRoleRequest](#aws.controller.PutAWSRoleRequest) | [PutAWSRoleResponse](#aws.controller.PutAWSRoleResponse) |  |
| ListDataSource | [ListDataSourceRequest](#aws.controller.ListDataSourceRequest) | [ListDataSourceResponse](#aws.controller.ListDataSourceResponse) | AWS DataSource |
| AttachDataSource | [AttachDataSourceRequest](#aws.controller.AttachDataSourceRequest) | [AttachDataSourceResponse](#aws.controller.AttachDataSourceResponse) |  |
| DetachDataSource | [DetachDataSourceRequest](#aws.controller.DetachDataSourceRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) |  |
| InvokeScan | [InvokeScanRequest](#aws.controller.InvokeScanRequest) | [.google.protobuf.Empty](#google.protobuf.Empty) | Scan |

 



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

