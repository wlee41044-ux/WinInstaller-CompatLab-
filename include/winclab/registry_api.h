#pragma once
#include "winclab/file_api.h"
#include <atomic>

namespace winclab {
using RegistryHandle = std::uint64_t;
// Canonical, zero-extended public hive IDs. The ABI adapter normalizes guest HKEYs.
constexpr RegistryHandle HKEY_CURRENT_USER=0x80000001u;
constexpr RegistryHandle HKEY_LOCAL_MACHINE=0x80000002u;
constexpr std::uint32_t KEY_QUERY_VALUE=0x1, KEY_SET_VALUE=0x2, KEY_CREATE_SUB_KEY=0x4;
constexpr std::uint32_t KEY_ENUMERATE_SUB_KEYS=0x8, KEY_NOTIFY=0x10;
constexpr std::uint32_t KEY_READ=0x20019, KEY_WRITE=0x20006, KEY_ALL_ACCESS=0xf003f;
constexpr std::uint32_t KEY_WOW64_64KEY=0x100, KEY_WOW64_32KEY=0x200;
constexpr std::uint32_t REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4;
constexpr std::uint32_t REG_MULTI_SZ=7, REG_QWORD=11;
constexpr std::uint32_t REG_OPTION_NON_VOLATILE=0, REG_OPTION_VOLATILE=1;
constexpr std::uint32_t REG_OPTION_CREATE_LINK=2, REG_OPTION_OPEN_LINK=8;
constexpr std::uint32_t REG_CREATED_NEW_KEY=1, REG_OPENED_EXISTING_KEY=2;

struct RegistryOptions {
    // Only this instance's virtual HKLM. Never grants host OS access.
    bool machine_writable{false};
};

class RegistryApi {
public:
    explicit RegistryApi(RegistryOptions options={});
    RegistryApi(const RegistryApi&)=delete;
    RegistryApi& operator=(const RegistryApi&)=delete;

    Result<RegistryHandle> openKey(RegistryHandle parent,const std::u16string& subkey,
                                  std::uint32_t access,std::uint32_t options=0);
    Result<RegistryHandle> createKey(RegistryHandle parent,const std::u16string& subkey,
                                    std::uint32_t access,std::uint32_t* disposition=nullptr,
                                    std::uint32_t options=REG_OPTION_NON_VOLATILE);
    // Host-owned validated buffers only. Counts are BYTES, not UTF-16 code units.
    // Empty name means the unnamed/default value. No implicit default exists.
    Error queryValue(RegistryHandle handle,const std::u16string& name,std::uint32_t* type,
                     void* data,std::uint32_t* size);
    Error setValue(RegistryHandle handle,const std::u16string& name,std::uint32_t type,
                   const void* data,std::uint32_t size);
    Error closeKey(RegistryHandle handle);
    std::size_t liveHandleCount() const;

private:
    struct Value { std::uint32_t type; std::vector<std::uint8_t> bytes; };
    struct Key { bool machine; std::u16string path; std::map<std::u16string,Value> values; };
    struct OpenKey { Key* key{nullptr}; std::uint32_t access{0}; };
    RegistryOptions options_;
    mutable std::mutex mutex_;
    std::map<std::pair<bool,std::u16string>,Key> keys_;
    std::map<RegistryHandle,OpenKey> handles_;
    static std::atomic<RegistryHandle> next_handle_; // IDs only, no cross-context state
    Result<OpenKey> resolve(RegistryHandle handle);
    static Result<std::u16string> normalize(const std::u16string& name,bool path);
    Error validateAccess(const Key& key,std::uint32_t access) const;
    Result<RegistryHandle> allocate(Key& key,std::uint32_t access);
};
} // namespace winclab
