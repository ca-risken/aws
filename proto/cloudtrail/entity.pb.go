// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.15.6
// source: cloudtrail/entity.proto

package cloudtrail

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// CloudTrail:
// https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html#output
type CloudTrail struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventId         string    `protobuf:"bytes,1,opt,name=event_id,json=eventId,proto3" json:"event_id,omitempty"`
	EventName       string    `protobuf:"bytes,2,opt,name=event_name,json=eventName,proto3" json:"event_name,omitempty"`
	ReadOnly        string    `protobuf:"bytes,3,opt,name=read_only,json=readOnly,proto3" json:"read_only,omitempty"`
	AccessKeyId     string    `protobuf:"bytes,4,opt,name=access_key_id,json=accessKeyId,proto3" json:"access_key_id,omitempty"`
	EventTime       int64     `protobuf:"varint,5,opt,name=event_time,json=eventTime,proto3" json:"event_time,omitempty"`
	EventSource     string    `protobuf:"bytes,6,opt,name=event_source,json=eventSource,proto3" json:"event_source,omitempty"`
	Username        string    `protobuf:"bytes,7,opt,name=username,proto3" json:"username,omitempty"`
	Resources       *Resource `protobuf:"bytes,8,opt,name=resources,proto3" json:"resources,omitempty"`
	CloudtrailEvent string    `protobuf:"bytes,9,opt,name=cloudtrail_event,json=cloudtrailEvent,proto3" json:"cloudtrail_event,omitempty"`
}

func (x *CloudTrail) Reset() {
	*x = CloudTrail{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cloudtrail_entity_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CloudTrail) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CloudTrail) ProtoMessage() {}

func (x *CloudTrail) ProtoReflect() protoreflect.Message {
	mi := &file_cloudtrail_entity_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CloudTrail.ProtoReflect.Descriptor instead.
func (*CloudTrail) Descriptor() ([]byte, []int) {
	return file_cloudtrail_entity_proto_rawDescGZIP(), []int{0}
}

func (x *CloudTrail) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *CloudTrail) GetEventName() string {
	if x != nil {
		return x.EventName
	}
	return ""
}

func (x *CloudTrail) GetReadOnly() string {
	if x != nil {
		return x.ReadOnly
	}
	return ""
}

func (x *CloudTrail) GetAccessKeyId() string {
	if x != nil {
		return x.AccessKeyId
	}
	return ""
}

func (x *CloudTrail) GetEventTime() int64 {
	if x != nil {
		return x.EventTime
	}
	return 0
}

func (x *CloudTrail) GetEventSource() string {
	if x != nil {
		return x.EventSource
	}
	return ""
}

func (x *CloudTrail) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *CloudTrail) GetResources() *Resource {
	if x != nil {
		return x.Resources
	}
	return nil
}

func (x *CloudTrail) GetCloudtrailEvent() string {
	if x != nil {
		return x.CloudtrailEvent
	}
	return ""
}

type Resource struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResourceType string `protobuf:"bytes,1,opt,name=resource_type,json=resourceType,proto3" json:"resource_type,omitempty"`
	ResourceName string `protobuf:"bytes,2,opt,name=resource_name,json=resourceName,proto3" json:"resource_name,omitempty"`
}

func (x *Resource) Reset() {
	*x = Resource{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cloudtrail_entity_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Resource) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Resource) ProtoMessage() {}

func (x *Resource) ProtoReflect() protoreflect.Message {
	mi := &file_cloudtrail_entity_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Resource.ProtoReflect.Descriptor instead.
func (*Resource) Descriptor() ([]byte, []int) {
	return file_cloudtrail_entity_proto_rawDescGZIP(), []int{1}
}

func (x *Resource) GetResourceType() string {
	if x != nil {
		return x.ResourceType
	}
	return ""
}

func (x *Resource) GetResourceName() string {
	if x != nil {
		return x.ResourceName
	}
	return ""
}

var File_cloudtrail_entity_proto protoreflect.FileDescriptor

var file_cloudtrail_entity_proto_rawDesc = []byte{
	0x0a, 0x17, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x2f, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x61, 0x77, 0x73, 0x2e, 0x63,
	0x6c, 0x6f, 0x75, 0x64, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x22, 0xc8, 0x02, 0x0a, 0x0a, 0x43, 0x6c,
	0x6f, 0x75, 0x64, 0x54, 0x72, 0x61, 0x69, 0x6c, 0x12, 0x19, 0x0a, 0x08, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x72, 0x65, 0x61, 0x64, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x61, 0x64, 0x4f, 0x6e, 0x6c, 0x79, 0x12,
	0x22, 0x0a, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4b, 0x65,
	0x79, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x53,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x36, 0x0a, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x61, 0x77, 0x73, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x74, 0x72, 0x61, 0x69, 0x6c, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x09,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x29, 0x0a, 0x10, 0x63, 0x6c, 0x6f,
	0x75, 0x64, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x22, 0x54, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x79, 0x62, 0x65, 0x72, 0x41, 0x67,
	0x65, 0x6e, 0x74, 0x2f, 0x6d, 0x69, 0x6d, 0x6f, 0x73, 0x61, 0x2d, 0x61, 0x77, 0x73, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x74, 0x72, 0x61, 0x69, 0x6c, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cloudtrail_entity_proto_rawDescOnce sync.Once
	file_cloudtrail_entity_proto_rawDescData = file_cloudtrail_entity_proto_rawDesc
)

func file_cloudtrail_entity_proto_rawDescGZIP() []byte {
	file_cloudtrail_entity_proto_rawDescOnce.Do(func() {
		file_cloudtrail_entity_proto_rawDescData = protoimpl.X.CompressGZIP(file_cloudtrail_entity_proto_rawDescData)
	})
	return file_cloudtrail_entity_proto_rawDescData
}

var file_cloudtrail_entity_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_cloudtrail_entity_proto_goTypes = []interface{}{
	(*CloudTrail)(nil), // 0: aws.cloudtrail.CloudTrail
	(*Resource)(nil),   // 1: aws.cloudtrail.Resource
}
var file_cloudtrail_entity_proto_depIdxs = []int32{
	1, // 0: aws.cloudtrail.CloudTrail.resources:type_name -> aws.cloudtrail.Resource
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_cloudtrail_entity_proto_init() }
func file_cloudtrail_entity_proto_init() {
	if File_cloudtrail_entity_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cloudtrail_entity_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CloudTrail); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cloudtrail_entity_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Resource); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cloudtrail_entity_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cloudtrail_entity_proto_goTypes,
		DependencyIndexes: file_cloudtrail_entity_proto_depIdxs,
		MessageInfos:      file_cloudtrail_entity_proto_msgTypes,
	}.Build()
	File_cloudtrail_entity_proto = out.File
	file_cloudtrail_entity_proto_rawDesc = nil
	file_cloudtrail_entity_proto_goTypes = nil
	file_cloudtrail_entity_proto_depIdxs = nil
}
