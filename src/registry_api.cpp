#include "winclab/registry_api.h"
#include <algorithm>
#include <cstring>
#include <new>

namespace winclab {
std::atomic<RegistryHandle> RegistryApi::next_handle_{0x100000000ULL};

RegistryApi::RegistryApi(RegistryOptions options):options_(options) {
    keys_.emplace(std::make_pair(false,std::u16string{}),Key{false,{}, {}});
    keys_.emplace(std::make_pair(true,std::u16string{}),Key{true,{}, {}});
}
Result<RegistryApi::OpenKey> RegistryApi::resolve(RegistryHandle handle) {
    if(handle==HKEY_CURRENT_USER || handle==HKEY_LOCAL_MACHINE) {
        auto& root=keys_.at({handle==HKEY_LOCAL_MACHINE,{}});
        return {{&root,KEY_ALL_ACCESS},Error::ok};
    }
    auto it=handles_.find(handle);
    return it==handles_.end()?Result<OpenKey>{{},Error::invalid_handle}:Result<OpenKey>{it->second,Error::ok};
}
Result<std::u16string> RegistryApi::normalize(const std::u16string& input,bool path) {
    if(!path && input.size()>16383)return {{},Error::invalid_parameter};
    std::u16string name=input;
    std::size_t segment=0,depth=1;
    for(std::size_t i=0;i<name.size();++i) {
        auto c=name[i];
        if(c==0)return {{},Error::invalid_parameter};
        if(c>=0xd800 && c<=0xdbff) {
            if(i+1==name.size() || name[i+1]<0xdc00 || name[i+1]>0xdfff)return {{},Error::invalid_parameter};
            ++i; segment+=2; continue;
        }
        if(c>=0xdc00 && c<=0xdfff)return {{},Error::invalid_parameter};
        if(path && c==u'\\') {
            if(segment==0 || segment>255)return {{},Error::invalid_parameter};
            segment=0; ++depth;
        } else { ++segment; if(c>=u'A' && c<=u'Z')name[i]=static_cast<char16_t>(c+32); }
    }
    if(path && !name.empty() && (segment==0 || segment>255))return {{},Error::invalid_parameter};
    if(path && depth>32)return {{},Error::not_supported};
    return {std::move(name),Error::ok};
}
Error RegistryApi::validateAccess(const Key& key,std::uint32_t access) const {
    // No WOW64 views, security descriptor APIs or symbolic links in this subset.
    if(access&~KEY_ALL_ACCESS)return Error::not_supported;
    constexpr auto writable=KEY_SET_VALUE|KEY_CREATE_SUB_KEY|0xd0020u; // DELETE, DAC, owner, create-link
    if(key.machine && !options_.machine_writable && (access&writable))return Error::access_denied;
    return Error::ok;
}
Result<RegistryHandle> RegistryApi::allocate(Key& key,std::uint32_t access) {
    auto h=next_handle_.fetch_add(1,std::memory_order_relaxed);
    handles_.emplace(h,OpenKey{&key,access});
    return {h,Error::ok};
}
Result<RegistryHandle> RegistryApi::openKey(RegistryHandle parent,const std::u16string& subkey,
                                          std::uint32_t access,std::uint32_t options) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto p=resolve(parent); if(!p.ok())return {0,p.error};
    if(options!=0)return {0,Error::not_supported};
    auto normalized=normalize(subkey,true); if(!normalized.ok())return {0,normalized.error};
    auto err=validateAccess(*p.value.key,access); if(err!=Error::ok)return {0,err};
    if(normalized.value.empty() && (parent==HKEY_CURRENT_USER || parent==HKEY_LOCAL_MACHINE))return {parent,Error::ok};
    std::u16string path=p.value.key->path;
    if(!normalized.value.empty()) { if(!path.empty())path+=u'\\'; path+=normalized.value; }
    auto it=keys_.find({p.value.key->machine,path});
    if(it==keys_.end())return {0,Error::file_not_found};
    return allocate(it->second,access);
}
Result<RegistryHandle> RegistryApi::createKey(RegistryHandle parent,const std::u16string& subkey,
                                            std::uint32_t access,std::uint32_t* disposition,std::uint32_t options) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto p=resolve(parent); if(!p.ok())return {0,p.error};
    if(options!=REG_OPTION_NON_VOLATILE)return {0,Error::not_supported};
    auto normalized=normalize(subkey,true); if(!normalized.ok())return {0,normalized.error};
    auto err=validateAccess(*p.value.key,access); if(err!=Error::ok)return {0,err};
    const bool machine=p.value.key->machine;
    std::u16string path=p.value.key->path;
    if(!normalized.value.empty()) { if(!path.empty())path+=u'\\'; path+=normalized.value; }
    // Bound total depth even when a caller builds a chain one child at a time.
    if(std::count(path.begin(),path.end(),u'\\')>=512)return {0,Error::not_supported};
    auto it=keys_.find({machine,path}); bool created=it==keys_.end();
    if(created) {
        if(machine && !options_.machine_writable)return {0,Error::access_denied};
        for(std::size_t end=0;;) {
            end=path.find(u'\\',end);
            auto prefix=path.substr(0,end);
            keys_.try_emplace({machine,prefix},Key{machine,prefix,{}});
            if(end==std::u16string::npos)break;
            ++end;
        }
        it=keys_.find({machine,path});
    }
    auto result=allocate(it->second,access);
    if(disposition)*disposition=created?REG_CREATED_NEW_KEY:REG_OPENED_EXISTING_KEY;
    return result;
}
Error RegistryApi::queryValue(RegistryHandle handle,const std::u16string& name,std::uint32_t* type,
                             void* data,std::uint32_t* size) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto h=resolve(handle); if(!h.ok())return h.error;
    if(!(h.value.access&KEY_QUERY_VALUE))return Error::access_denied;
    if(data && !size)return Error::invalid_parameter;
    auto normalized=normalize(name,false); if(!normalized.ok())return normalized.error;
    auto it=h.value.key->values.find(normalized.value);
    if(it==h.value.key->values.end())return Error::file_not_found;
    const auto& value=it->second;
    if(type)*type=value.type;
    // With null data, size is output-only and need not be initialized by caller.
    const auto capacity=data?*size:0;
    if(size)*size=static_cast<std::uint32_t>(value.bytes.size());
    if(data && capacity<value.bytes.size())return Error::more_data;
    if(data && !value.bytes.empty())std::memcpy(data,value.bytes.data(),value.bytes.size());
    return Error::ok;
}
Error RegistryApi::setValue(RegistryHandle handle,const std::u16string& name,std::uint32_t type,
                           const void* data,std::uint32_t size) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto h=resolve(handle); if(!h.ok())return h.error;
    if(!(h.value.access&KEY_SET_VALUE) || (h.value.key->machine && !options_.machine_writable))return Error::access_denied;
    if(size && !data)return Error::invalid_parameter;
    if(type!=REG_SZ && type!=REG_EXPAND_SZ && type!=REG_DWORD && type!=REG_QWORD && type!=REG_BINARY)return Error::not_supported;
    auto normalized=normalize(name,false); if(!normalized.ok())return normalized.error;
    try {
        Value value{type,{}};
        if(size) {
            const auto* first=static_cast<const std::uint8_t*>(data);
            value.bytes.assign(first,first+size);
        }
        h.value.key->values.insert_or_assign(normalized.value,std::move(value));
    } catch(const std::bad_alloc&) { return Error::not_enough_memory; }
    return Error::ok;
}
Error RegistryApi::closeKey(RegistryHandle handle) {
    std::lock_guard<std::mutex> guard(mutex_);
    if(handle==HKEY_CURRENT_USER || handle==HKEY_LOCAL_MACHINE)return Error::ok;
    return handles_.erase(handle)?Error::ok:Error::invalid_handle;
}
std::size_t RegistryApi::liveHandleCount() const {
    std::lock_guard<std::mutex> guard(mutex_); return handles_.size();
}
} // namespace winclab
