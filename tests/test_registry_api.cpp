#include "test_support.h"
#include "winclab/registry_api.h"
#include <array>
#include <cstring>
#include <thread>

RegistryHandle makeKey(RegistryApi& r,const std::u16string& path=u"Software\\CompatLab",std::uint32_t access=KEY_ALL_ACCESS) {
    auto h=r.createKey(HKEY_CURRENT_USER,path,access); CHECK(h.ok()); return h.value;
}
void registryLifecycle() {
    RegistryApi r; std::uint32_t disposition=99;
    CHECK(r.openKey(HKEY_CURRENT_USER,u"Software\\Absent",KEY_READ).error==Error::file_not_found);
    auto h=r.createKey(HKEY_CURRENT_USER,u"Software\\CompatLab",KEY_ALL_ACCESS,&disposition);
    CHECK(h.ok() && disposition==REG_CREATED_NEW_KEY);
    auto same=r.createKey(HKEY_CURRENT_USER,u"software\\COMPATLAB",KEY_READ,&disposition);
    CHECK(same.ok() && same.value!=h.value && disposition==REG_OPENED_EXISTING_KEY);
    auto parent=r.openKey(HKEY_CURRENT_USER,u"Software",KEY_READ); CHECK(parent.ok());
    CHECK(r.closeKey(parent.value)==Error::ok); CHECK(r.closeKey(same.value)==Error::ok);
    CHECK(r.closeKey(h.value)==Error::ok); CHECK(r.closeKey(h.value)==Error::invalid_handle);
    CHECK(r.queryValue(h.value,u"x",nullptr,nullptr,nullptr)==Error::invalid_handle);
    CHECK(r.closeKey(HKEY_CURRENT_USER)==Error::ok); // predefined root remains available
    CHECK(r.openKey(HKEY_CURRENT_USER,u"",KEY_READ).value==HKEY_CURRENT_USER);
}
void registryDataTypes() {
    RegistryApi r; auto h=makeKey(r);
    const std::pair<std::uint32_t,std::vector<std::uint8_t>> values[]={
        {REG_SZ,{0x5c,0xd5,0x00,0xae,0,0}}, // 한글, UTF-16LE and terminator
        {REG_EXPAND_SZ,{'%',0,'T',0,'%',0,0,0}},
        {REG_DWORD,{0x78,0x56,0x34,0x12}}, {REG_QWORD,{8,7,6,5,4,3,2,1}},
        {REG_BINARY,{0,0xff,0,3}}};
    for (const auto& v:values) {
        CHECK(r.setValue(h,u"Setting",v.first,v.second.data(),v.second.size())==Error::ok);
        std::array<std::uint8_t,32> output{}; std::uint32_t size=output.size(),type=99;
        CHECK(r.queryValue(h,u"setting",&type,output.data(),&size)==Error::ok);
        CHECK(type==v.first && size==v.second.size()); CHECK(std::memcmp(output.data(),v.second.data(),size)==0);
    }
    CHECK(r.closeKey(h)==Error::ok);
}
void registrySizeNegotiation() {
    RegistryApi r; auto h=makeKey(r); const std::uint8_t bytes[]={1,2,0,4};
    CHECK(r.setValue(h,u"data",REG_BINARY,bytes,4)==Error::ok);
    std::uint32_t size=0,type=0;
    CHECK(r.queryValue(h,u"data",&type,nullptr,&size)==Error::ok && size==4 && type==REG_BINARY);
    std::array<std::uint8_t,6> out; out.fill(0xa5); size=3;
    CHECK(r.queryValue(h,u"data",&type,out.data()+1,&size)==Error::more_data && size==4);
    CHECK((out==std::array<std::uint8_t,6>({0xa5,0xa5,0xa5,0xa5,0xa5,0xa5})));
    size=4; CHECK(r.queryValue(h,u"data",nullptr,out.data()+1,&size)==Error::ok && size==4);
    CHECK(out[0]==0xa5 && out[5]==0xa5 && std::memcmp(out.data()+1,bytes,4)==0);
    CHECK(r.queryValue(h,u"data",&type,nullptr,nullptr)==Error::ok && type==REG_BINARY);
    CHECK(r.queryValue(h,u"data",nullptr,out.data(),nullptr)==Error::invalid_parameter);
}
void registryRawStringsAndDefault() {
    RegistryApi r; auto h=makeKey(r); std::uint32_t size=0;
    CHECK(r.queryValue(h,u"",nullptr,nullptr,&size)==Error::file_not_found);
    const std::uint8_t text[]={'X',0}; // stored WITHOUT null terminator
    CHECK(r.setValue(h,u"",REG_SZ,text,2)==Error::ok);
    std::array<std::uint8_t,4> out{0xa5,0xa5,0xa5,0xa5}; size=4;
    CHECK(r.queryValue(h,u"",nullptr,out.data(),&size)==Error::ok && size==2);
    CHECK(out[0]=='X' && out[1]==0 && out[2]==0xa5 && out[3]==0xa5);
    CHECK(r.setValue(h,u"empty",REG_BINARY,nullptr,0)==Error::ok);
    size=0; CHECK(r.queryValue(h,u"empty",nullptr,nullptr,&size)==Error::ok && size==0);
}
void registryAccessRights() {
    RegistryApi r; auto h=makeKey(r);
    auto read=r.openKey(h,u"",KEY_READ); CHECK(read.ok());
    const std::uint8_t x=7;
    CHECK(r.setValue(read.value,u"x",REG_BINARY,&x,1)==Error::access_denied);
    auto write=r.openKey(h,u"",KEY_WRITE); CHECK(write.ok());
    CHECK(r.setValue(write.value,u"x",REG_BINARY,&x,1)==Error::ok);
    CHECK(r.queryValue(write.value,u"x",nullptr,nullptr,nullptr)==Error::access_denied);
    // Child creation checks the hive policy, not the parent's handle access mask.
    auto child=r.createKey(read.value,u"Child",KEY_READ); CHECK(child.ok());
    CHECK(r.openKey(HKEY_CURRENT_USER,u"Software\\CompatLab\\Child",KEY_READ).ok());
}
void registryHivePolicy() {
    RegistryApi r; std::uint8_t x=1;
    CHECK(r.createKey(HKEY_LOCAL_MACHINE,u"Software\\CompatLab",KEY_WRITE).error==Error::access_denied);
    CHECK(r.setValue(HKEY_LOCAL_MACHINE,u"x",REG_BINARY,&x,1)==Error::access_denied);
    CHECK(r.openKey(HKEY_LOCAL_MACHINE,u"Software",KEY_READ).error==Error::file_not_found);
    RegistryApi installer(RegistryOptions{true});
    auto machine=installer.createKey(HKEY_LOCAL_MACHINE,u"Software\\CompatLab",KEY_ALL_ACCESS); CHECK(machine.ok());
    CHECK(installer.setValue(machine.value,u"x",REG_BINARY,&x,1)==Error::ok);
    CHECK(installer.openKey(HKEY_CURRENT_USER,u"Software\\CompatLab",KEY_READ).error==Error::file_not_found);
}
void registryInvalidArguments() {
    RegistryApi r; auto h=makeKey(r); std::uint8_t x=1;
    CHECK(r.setValue(h,u"x",REG_BINARY,nullptr,1)==Error::invalid_parameter);
    CHECK(r.setValue(h,u"x",REG_MULTI_SZ,&x,1)==Error::not_supported);
    CHECK(r.queryValue(h,u"x",nullptr,nullptr,nullptr)==Error::file_not_found);
    CHECK(r.openKey(42,u"x",KEY_READ).error==Error::invalid_handle);
    CHECK(r.createKey(42,u"x",KEY_READ).error==Error::invalid_handle);
    CHECK(r.setValue(42,u"x",REG_BINARY,&x,1)==Error::invalid_handle);
    CHECK(r.closeKey(42)==Error::invalid_handle);
    CHECK(r.createKey(h,std::u16string(256,u'x'),KEY_READ).error==Error::invalid_parameter);
    CHECK(r.setValue(h,std::u16string(16384,u'x'),REG_BINARY,&x,1)==Error::invalid_parameter);
    CHECK(r.createKey(h,std::u16string(u"bad\0name",8),KEY_READ).error==Error::invalid_parameter);
}
void registryUnsupportedOptions() {
    RegistryApi r; std::uint32_t disposition=123;
    CHECK(r.createKey(HKEY_CURRENT_USER,u"NoSideEffect",KEY_ALL_ACCESS,&disposition,REG_OPTION_CREATE_LINK).error==Error::not_supported);
    CHECK(disposition==123);
    CHECK(r.openKey(HKEY_CURRENT_USER,u"NoSideEffect",KEY_READ).error==Error::file_not_found);
    CHECK(r.openKey(HKEY_CURRENT_USER,u"",KEY_READ,REG_OPTION_OPEN_LINK).error==Error::not_supported);
    CHECK(r.openKey(HKEY_CURRENT_USER,u"",KEY_READ|KEY_WOW64_32KEY).error==Error::not_supported);
    CHECK(r.createKey(HKEY_CURRENT_USER,u"NoView",KEY_READ|KEY_WOW64_64KEY).error==Error::not_supported);
}
void registryUnicodeNames() {
    RegistryApi r; auto h=makeKey(r,u"Software\\한글😀");
    std::uint8_t x=0x42; CHECK(r.setValue(h,u"설정😀",REG_BINARY,&x,1)==Error::ok);
    auto again=r.openKey(HKEY_CURRENT_USER,u"software\\한글😀",KEY_READ); CHECK(again.ok());
    std::uint8_t y=0;std::uint32_t size=1;
    CHECK(r.queryValue(again.value,u"설정😀",nullptr,&y,&size)==Error::ok && y==0x42);
    CHECK(r.createKey(h,std::u16string{0xd800},KEY_READ).error==Error::invalid_parameter);
}
void registryContextIsolation() {
    RegistryApi a,b; auto ah=makeKey(a); auto bh=makeKey(b);
    CHECK(ah!=bh); std::uint8_t x=9;
    CHECK(a.setValue(ah,u"private",REG_BINARY,&x,1)==Error::ok);
    CHECK(b.queryValue(bh,u"private",nullptr,nullptr,nullptr)==Error::file_not_found);
    CHECK(b.queryValue(ah,u"private",nullptr,nullptr,nullptr)==Error::invalid_handle);
    CHECK(b.closeKey(ah)==Error::invalid_handle);
    CHECK(a.queryValue(ah,u"private",nullptr,nullptr,nullptr)==Error::ok);
}
void registryRepeatedHandles() {
    RegistryApi r; auto h=makeKey(r); CHECK(r.closeKey(h)==Error::ok);
    for(int i=0;i<2000;++i) {
        auto n=r.openKey(HKEY_CURRENT_USER,u"Software\\CompatLab",KEY_READ); CHECK(n.ok() && n.value!=h);
        CHECK(r.closeKey(n.value)==Error::ok); CHECK(r.closeKey(n.value)==Error::invalid_handle);
    }
    CHECK(r.liveHandleCount()==0);
    RegistryHandle stale;
    { RegistryApi old; stale=makeKey(old); }
    RegistryApi fresh; auto n=makeKey(fresh); CHECK(n!=stale);
    CHECK(fresh.closeKey(stale)==Error::invalid_handle);
}
void registryCallerBufferOwnership() {
    RegistryApi r; auto h=makeKey(r); std::array<std::uint8_t,4> in{1,2,3,4};
    CHECK(r.setValue(h,u"x",REG_DWORD,in.data(),4)==Error::ok); in.fill(0);
    std::array<std::uint8_t,4> out{};std::uint32_t size=4;
    CHECK(r.queryValue(h,u"x",nullptr,out.data(),&size)==Error::ok && out[0]==1 && out[3]==4);
    CHECK(r.setValue(h,u"x",REG_BINARY,nullptr,10)==Error::invalid_parameter);
    size=4; CHECK(r.queryValue(h,u"x",nullptr,out.data(),&size)==Error::ok && out[3]==4);
}
using Test=void(*)();
int main(int argc,char** argv) {
    const std::pair<const char*,Test> tests[]={
        {"lifecycle",registryLifecycle},{"data_types",registryDataTypes},{"buffer_sizes",registrySizeNegotiation},
        {"raw_strings_default",registryRawStringsAndDefault},{"access",registryAccessRights},{"hive_policy",registryHivePolicy},
        {"invalid_arguments",registryInvalidArguments},{"options",registryUnsupportedOptions},{"unicode",registryUnicodeNames},
        {"isolation",registryContextIsolation},{"handle_lifetime",registryRepeatedHandles},{"buffer_ownership",registryCallerBufferOwnership}};
    bool found=false; int failures=0;
    for(auto t:tests) if(argc==1 || std::string(argv[1])==t.first) {
        found=true; try { t.second();std::cout<<t.first<<" PASS\n"; }
        catch(const std::exception& e) {++failures;std::cerr<<e.what()<<'\n';}
    }
    return !found || failures ? 1:0;
}
