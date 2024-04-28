// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: Message.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_Message_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_Message_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3021000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3021012 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_Message_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_Message_2eproto {
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_Message_2eproto;
class RequestMsg;
struct RequestMsgDefaultTypeInternal;
extern RequestMsgDefaultTypeInternal _RequestMsg_default_instance_;
class RespondMsg;
struct RespondMsgDefaultTypeInternal;
extern RespondMsgDefaultTypeInternal _RespondMsg_default_instance_;
PROTOBUF_NAMESPACE_OPEN
template<> ::RequestMsg* Arena::CreateMaybeMessage<::RequestMsg>(Arena*);
template<> ::RespondMsg* Arena::CreateMaybeMessage<::RespondMsg>(Arena*);
PROTOBUF_NAMESPACE_CLOSE

// ===================================================================

class RequestMsg final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:RequestMsg) */ {
 public:
  inline RequestMsg() : RequestMsg(nullptr) {}
  ~RequestMsg() override;
  explicit PROTOBUF_CONSTEXPR RequestMsg(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  RequestMsg(const RequestMsg& from);
  RequestMsg(RequestMsg&& from) noexcept
    : RequestMsg() {
    *this = ::std::move(from);
  }

  inline RequestMsg& operator=(const RequestMsg& from) {
    CopyFrom(from);
    return *this;
  }
  inline RequestMsg& operator=(RequestMsg&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const RequestMsg& default_instance() {
    return *internal_default_instance();
  }
  static inline const RequestMsg* internal_default_instance() {
    return reinterpret_cast<const RequestMsg*>(
               &_RequestMsg_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(RequestMsg& a, RequestMsg& b) {
    a.Swap(&b);
  }
  inline void Swap(RequestMsg* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(RequestMsg* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  RequestMsg* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<RequestMsg>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const RequestMsg& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const RequestMsg& from) {
    RequestMsg::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(RequestMsg* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "RequestMsg";
  }
  protected:
  explicit RequestMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kClientIDFieldNumber = 2,
    kServerIDFieldNumber = 3,
    kSignFieldNumber = 4,
    kDataFieldNumber = 5,
    kCmdTypeFieldNumber = 1,
  };
  // bytes clientID = 2;
  void clear_clientid();
  const std::string& clientid() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_clientid(ArgT0&& arg0, ArgT... args);
  std::string* mutable_clientid();
  PROTOBUF_NODISCARD std::string* release_clientid();
  void set_allocated_clientid(std::string* clientid);
  private:
  const std::string& _internal_clientid() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_clientid(const std::string& value);
  std::string* _internal_mutable_clientid();
  public:

  // bytes serverID = 3;
  void clear_serverid();
  const std::string& serverid() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_serverid(ArgT0&& arg0, ArgT... args);
  std::string* mutable_serverid();
  PROTOBUF_NODISCARD std::string* release_serverid();
  void set_allocated_serverid(std::string* serverid);
  private:
  const std::string& _internal_serverid() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_serverid(const std::string& value);
  std::string* _internal_mutable_serverid();
  public:

  // bytes sign = 4;
  void clear_sign();
  const std::string& sign() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_sign(ArgT0&& arg0, ArgT... args);
  std::string* mutable_sign();
  PROTOBUF_NODISCARD std::string* release_sign();
  void set_allocated_sign(std::string* sign);
  private:
  const std::string& _internal_sign() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_sign(const std::string& value);
  std::string* _internal_mutable_sign();
  public:

  // bytes data = 5;
  void clear_data();
  const std::string& data() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_data(ArgT0&& arg0, ArgT... args);
  std::string* mutable_data();
  PROTOBUF_NODISCARD std::string* release_data();
  void set_allocated_data(std::string* data);
  private:
  const std::string& _internal_data() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_data(const std::string& value);
  std::string* _internal_mutable_data();
  public:

  // int32 cmdType = 1;
  void clear_cmdtype();
  int32_t cmdtype() const;
  void set_cmdtype(int32_t value);
  private:
  int32_t _internal_cmdtype() const;
  void _internal_set_cmdtype(int32_t value);
  public:

  // @@protoc_insertion_point(class_scope:RequestMsg)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr clientid_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr serverid_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr sign_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr data_;
    int32_t cmdtype_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_Message_2eproto;
};
// -------------------------------------------------------------------

class RespondMsg final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:RespondMsg) */ {
 public:
  inline RespondMsg() : RespondMsg(nullptr) {}
  ~RespondMsg() override;
  explicit PROTOBUF_CONSTEXPR RespondMsg(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  RespondMsg(const RespondMsg& from);
  RespondMsg(RespondMsg&& from) noexcept
    : RespondMsg() {
    *this = ::std::move(from);
  }

  inline RespondMsg& operator=(const RespondMsg& from) {
    CopyFrom(from);
    return *this;
  }
  inline RespondMsg& operator=(RespondMsg&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const RespondMsg& default_instance() {
    return *internal_default_instance();
  }
  static inline const RespondMsg* internal_default_instance() {
    return reinterpret_cast<const RespondMsg*>(
               &_RespondMsg_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(RespondMsg& a, RespondMsg& b) {
    a.Swap(&b);
  }
  inline void Swap(RespondMsg* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(RespondMsg* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  RespondMsg* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<RespondMsg>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const RespondMsg& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const RespondMsg& from) {
    RespondMsg::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(RespondMsg* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "RespondMsg";
  }
  protected:
  explicit RespondMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kClientIDFieldNumber = 3,
    kServerIDFieldNumber = 4,
    kDataFieldNumber = 5,
    kStatusFieldNumber = 1,
    kSeckeyIDFieldNumber = 2,
  };
  // bytes clientID = 3;
  void clear_clientid();
  const std::string& clientid() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_clientid(ArgT0&& arg0, ArgT... args);
  std::string* mutable_clientid();
  PROTOBUF_NODISCARD std::string* release_clientid();
  void set_allocated_clientid(std::string* clientid);
  private:
  const std::string& _internal_clientid() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_clientid(const std::string& value);
  std::string* _internal_mutable_clientid();
  public:

  // bytes serverID = 4;
  void clear_serverid();
  const std::string& serverid() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_serverid(ArgT0&& arg0, ArgT... args);
  std::string* mutable_serverid();
  PROTOBUF_NODISCARD std::string* release_serverid();
  void set_allocated_serverid(std::string* serverid);
  private:
  const std::string& _internal_serverid() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_serverid(const std::string& value);
  std::string* _internal_mutable_serverid();
  public:

  // bytes data = 5;
  void clear_data();
  const std::string& data() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_data(ArgT0&& arg0, ArgT... args);
  std::string* mutable_data();
  PROTOBUF_NODISCARD std::string* release_data();
  void set_allocated_data(std::string* data);
  private:
  const std::string& _internal_data() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_data(const std::string& value);
  std::string* _internal_mutable_data();
  public:

  // bool status = 1;
  void clear_status();
  bool status() const;
  void set_status(bool value);
  private:
  bool _internal_status() const;
  void _internal_set_status(bool value);
  public:

  // int32 seckeyID = 2;
  void clear_seckeyid();
  int32_t seckeyid() const;
  void set_seckeyid(int32_t value);
  private:
  int32_t _internal_seckeyid() const;
  void _internal_set_seckeyid(int32_t value);
  public:

  // @@protoc_insertion_point(class_scope:RespondMsg)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr clientid_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr serverid_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr data_;
    bool status_;
    int32_t seckeyid_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_Message_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// RequestMsg

// int32 cmdType = 1;
inline void RequestMsg::clear_cmdtype() {
  _impl_.cmdtype_ = 0;
}
inline int32_t RequestMsg::_internal_cmdtype() const {
  return _impl_.cmdtype_;
}
inline int32_t RequestMsg::cmdtype() const {
  // @@protoc_insertion_point(field_get:RequestMsg.cmdType)
  return _internal_cmdtype();
}
inline void RequestMsg::_internal_set_cmdtype(int32_t value) {
  
  _impl_.cmdtype_ = value;
}
inline void RequestMsg::set_cmdtype(int32_t value) {
  _internal_set_cmdtype(value);
  // @@protoc_insertion_point(field_set:RequestMsg.cmdType)
}

// bytes clientID = 2;
inline void RequestMsg::clear_clientid() {
  _impl_.clientid_.ClearToEmpty();
}
inline const std::string& RequestMsg::clientid() const {
  // @@protoc_insertion_point(field_get:RequestMsg.clientID)
  return _internal_clientid();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RequestMsg::set_clientid(ArgT0&& arg0, ArgT... args) {
 
 _impl_.clientid_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RequestMsg.clientID)
}
inline std::string* RequestMsg::mutable_clientid() {
  std::string* _s = _internal_mutable_clientid();
  // @@protoc_insertion_point(field_mutable:RequestMsg.clientID)
  return _s;
}
inline const std::string& RequestMsg::_internal_clientid() const {
  return _impl_.clientid_.Get();
}
inline void RequestMsg::_internal_set_clientid(const std::string& value) {
  
  _impl_.clientid_.Set(value, GetArenaForAllocation());
}
inline std::string* RequestMsg::_internal_mutable_clientid() {
  
  return _impl_.clientid_.Mutable(GetArenaForAllocation());
}
inline std::string* RequestMsg::release_clientid() {
  // @@protoc_insertion_point(field_release:RequestMsg.clientID)
  return _impl_.clientid_.Release();
}
inline void RequestMsg::set_allocated_clientid(std::string* clientid) {
  if (clientid != nullptr) {
    
  } else {
    
  }
  _impl_.clientid_.SetAllocated(clientid, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.clientid_.IsDefault()) {
    _impl_.clientid_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RequestMsg.clientID)
}

// bytes serverID = 3;
inline void RequestMsg::clear_serverid() {
  _impl_.serverid_.ClearToEmpty();
}
inline const std::string& RequestMsg::serverid() const {
  // @@protoc_insertion_point(field_get:RequestMsg.serverID)
  return _internal_serverid();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RequestMsg::set_serverid(ArgT0&& arg0, ArgT... args) {
 
 _impl_.serverid_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RequestMsg.serverID)
}
inline std::string* RequestMsg::mutable_serverid() {
  std::string* _s = _internal_mutable_serverid();
  // @@protoc_insertion_point(field_mutable:RequestMsg.serverID)
  return _s;
}
inline const std::string& RequestMsg::_internal_serverid() const {
  return _impl_.serverid_.Get();
}
inline void RequestMsg::_internal_set_serverid(const std::string& value) {
  
  _impl_.serverid_.Set(value, GetArenaForAllocation());
}
inline std::string* RequestMsg::_internal_mutable_serverid() {
  
  return _impl_.serverid_.Mutable(GetArenaForAllocation());
}
inline std::string* RequestMsg::release_serverid() {
  // @@protoc_insertion_point(field_release:RequestMsg.serverID)
  return _impl_.serverid_.Release();
}
inline void RequestMsg::set_allocated_serverid(std::string* serverid) {
  if (serverid != nullptr) {
    
  } else {
    
  }
  _impl_.serverid_.SetAllocated(serverid, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.serverid_.IsDefault()) {
    _impl_.serverid_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RequestMsg.serverID)
}

// bytes sign = 4;
inline void RequestMsg::clear_sign() {
  _impl_.sign_.ClearToEmpty();
}
inline const std::string& RequestMsg::sign() const {
  // @@protoc_insertion_point(field_get:RequestMsg.sign)
  return _internal_sign();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RequestMsg::set_sign(ArgT0&& arg0, ArgT... args) {
 
 _impl_.sign_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RequestMsg.sign)
}
inline std::string* RequestMsg::mutable_sign() {
  std::string* _s = _internal_mutable_sign();
  // @@protoc_insertion_point(field_mutable:RequestMsg.sign)
  return _s;
}
inline const std::string& RequestMsg::_internal_sign() const {
  return _impl_.sign_.Get();
}
inline void RequestMsg::_internal_set_sign(const std::string& value) {
  
  _impl_.sign_.Set(value, GetArenaForAllocation());
}
inline std::string* RequestMsg::_internal_mutable_sign() {
  
  return _impl_.sign_.Mutable(GetArenaForAllocation());
}
inline std::string* RequestMsg::release_sign() {
  // @@protoc_insertion_point(field_release:RequestMsg.sign)
  return _impl_.sign_.Release();
}
inline void RequestMsg::set_allocated_sign(std::string* sign) {
  if (sign != nullptr) {
    
  } else {
    
  }
  _impl_.sign_.SetAllocated(sign, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.sign_.IsDefault()) {
    _impl_.sign_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RequestMsg.sign)
}

// bytes data = 5;
inline void RequestMsg::clear_data() {
  _impl_.data_.ClearToEmpty();
}
inline const std::string& RequestMsg::data() const {
  // @@protoc_insertion_point(field_get:RequestMsg.data)
  return _internal_data();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RequestMsg::set_data(ArgT0&& arg0, ArgT... args) {
 
 _impl_.data_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RequestMsg.data)
}
inline std::string* RequestMsg::mutable_data() {
  std::string* _s = _internal_mutable_data();
  // @@protoc_insertion_point(field_mutable:RequestMsg.data)
  return _s;
}
inline const std::string& RequestMsg::_internal_data() const {
  return _impl_.data_.Get();
}
inline void RequestMsg::_internal_set_data(const std::string& value) {
  
  _impl_.data_.Set(value, GetArenaForAllocation());
}
inline std::string* RequestMsg::_internal_mutable_data() {
  
  return _impl_.data_.Mutable(GetArenaForAllocation());
}
inline std::string* RequestMsg::release_data() {
  // @@protoc_insertion_point(field_release:RequestMsg.data)
  return _impl_.data_.Release();
}
inline void RequestMsg::set_allocated_data(std::string* data) {
  if (data != nullptr) {
    
  } else {
    
  }
  _impl_.data_.SetAllocated(data, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.data_.IsDefault()) {
    _impl_.data_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RequestMsg.data)
}

// -------------------------------------------------------------------

// RespondMsg

// bool status = 1;
inline void RespondMsg::clear_status() {
  _impl_.status_ = false;
}
inline bool RespondMsg::_internal_status() const {
  return _impl_.status_;
}
inline bool RespondMsg::status() const {
  // @@protoc_insertion_point(field_get:RespondMsg.status)
  return _internal_status();
}
inline void RespondMsg::_internal_set_status(bool value) {
  
  _impl_.status_ = value;
}
inline void RespondMsg::set_status(bool value) {
  _internal_set_status(value);
  // @@protoc_insertion_point(field_set:RespondMsg.status)
}

// int32 seckeyID = 2;
inline void RespondMsg::clear_seckeyid() {
  _impl_.seckeyid_ = 0;
}
inline int32_t RespondMsg::_internal_seckeyid() const {
  return _impl_.seckeyid_;
}
inline int32_t RespondMsg::seckeyid() const {
  // @@protoc_insertion_point(field_get:RespondMsg.seckeyID)
  return _internal_seckeyid();
}
inline void RespondMsg::_internal_set_seckeyid(int32_t value) {
  
  _impl_.seckeyid_ = value;
}
inline void RespondMsg::set_seckeyid(int32_t value) {
  _internal_set_seckeyid(value);
  // @@protoc_insertion_point(field_set:RespondMsg.seckeyID)
}

// bytes clientID = 3;
inline void RespondMsg::clear_clientid() {
  _impl_.clientid_.ClearToEmpty();
}
inline const std::string& RespondMsg::clientid() const {
  // @@protoc_insertion_point(field_get:RespondMsg.clientID)
  return _internal_clientid();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RespondMsg::set_clientid(ArgT0&& arg0, ArgT... args) {
 
 _impl_.clientid_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RespondMsg.clientID)
}
inline std::string* RespondMsg::mutable_clientid() {
  std::string* _s = _internal_mutable_clientid();
  // @@protoc_insertion_point(field_mutable:RespondMsg.clientID)
  return _s;
}
inline const std::string& RespondMsg::_internal_clientid() const {
  return _impl_.clientid_.Get();
}
inline void RespondMsg::_internal_set_clientid(const std::string& value) {
  
  _impl_.clientid_.Set(value, GetArenaForAllocation());
}
inline std::string* RespondMsg::_internal_mutable_clientid() {
  
  return _impl_.clientid_.Mutable(GetArenaForAllocation());
}
inline std::string* RespondMsg::release_clientid() {
  // @@protoc_insertion_point(field_release:RespondMsg.clientID)
  return _impl_.clientid_.Release();
}
inline void RespondMsg::set_allocated_clientid(std::string* clientid) {
  if (clientid != nullptr) {
    
  } else {
    
  }
  _impl_.clientid_.SetAllocated(clientid, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.clientid_.IsDefault()) {
    _impl_.clientid_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RespondMsg.clientID)
}

// bytes serverID = 4;
inline void RespondMsg::clear_serverid() {
  _impl_.serverid_.ClearToEmpty();
}
inline const std::string& RespondMsg::serverid() const {
  // @@protoc_insertion_point(field_get:RespondMsg.serverID)
  return _internal_serverid();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RespondMsg::set_serverid(ArgT0&& arg0, ArgT... args) {
 
 _impl_.serverid_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RespondMsg.serverID)
}
inline std::string* RespondMsg::mutable_serverid() {
  std::string* _s = _internal_mutable_serverid();
  // @@protoc_insertion_point(field_mutable:RespondMsg.serverID)
  return _s;
}
inline const std::string& RespondMsg::_internal_serverid() const {
  return _impl_.serverid_.Get();
}
inline void RespondMsg::_internal_set_serverid(const std::string& value) {
  
  _impl_.serverid_.Set(value, GetArenaForAllocation());
}
inline std::string* RespondMsg::_internal_mutable_serverid() {
  
  return _impl_.serverid_.Mutable(GetArenaForAllocation());
}
inline std::string* RespondMsg::release_serverid() {
  // @@protoc_insertion_point(field_release:RespondMsg.serverID)
  return _impl_.serverid_.Release();
}
inline void RespondMsg::set_allocated_serverid(std::string* serverid) {
  if (serverid != nullptr) {
    
  } else {
    
  }
  _impl_.serverid_.SetAllocated(serverid, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.serverid_.IsDefault()) {
    _impl_.serverid_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RespondMsg.serverID)
}

// bytes data = 5;
inline void RespondMsg::clear_data() {
  _impl_.data_.ClearToEmpty();
}
inline const std::string& RespondMsg::data() const {
  // @@protoc_insertion_point(field_get:RespondMsg.data)
  return _internal_data();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void RespondMsg::set_data(ArgT0&& arg0, ArgT... args) {
 
 _impl_.data_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:RespondMsg.data)
}
inline std::string* RespondMsg::mutable_data() {
  std::string* _s = _internal_mutable_data();
  // @@protoc_insertion_point(field_mutable:RespondMsg.data)
  return _s;
}
inline const std::string& RespondMsg::_internal_data() const {
  return _impl_.data_.Get();
}
inline void RespondMsg::_internal_set_data(const std::string& value) {
  
  _impl_.data_.Set(value, GetArenaForAllocation());
}
inline std::string* RespondMsg::_internal_mutable_data() {
  
  return _impl_.data_.Mutable(GetArenaForAllocation());
}
inline std::string* RespondMsg::release_data() {
  // @@protoc_insertion_point(field_release:RespondMsg.data)
  return _impl_.data_.Release();
}
inline void RespondMsg::set_allocated_data(std::string* data) {
  if (data != nullptr) {
    
  } else {
    
  }
  _impl_.data_.SetAllocated(data, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.data_.IsDefault()) {
    _impl_.data_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:RespondMsg.data)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)


// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_Message_2eproto
