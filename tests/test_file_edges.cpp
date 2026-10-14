#include "test_support.h"
#include <array>
#include <limits>
#include <sys/stat.h>

void openAlwaysReadOnly() {
    Sandbox s; FileApi api(s.root);
    std::ofstream(s.root/"drive_c"/"settings")<<"original";
    auto h=api.createFile(u"C:\\settings",GENERIC_READ,FILE_SHARE_READ,OPEN_ALWAYS);
    CHECK(h.ok()); CHECK(api.getFileSize(h.value).value==8);
    CHECK(api.writeFile(h.value,"x",1).error==Error::access_denied);
    CHECK(api.closeHandle(h.value)==Error::ok);
    auto n=api.createFile(u"C:\\new",GENERIC_READ,FILE_SHARE_READ,OPEN_ALWAYS);
    CHECK(n.ok()); CHECK(api.getFileSize(n.value).value==0);
    CHECK(api.closeHandle(n.value)==Error::ok);
}
void invalidCrtModePreservesOriginal() {
    Sandbox s; FileApi api(s.root);
    std::ofstream(s.root/"drive_c"/"original")<<"original";
    auto d=api.wopen(u"C:\\original",CRT_O_BINARY|CRT_O_WRONLY|CRT_O_RDWR|CRT_O_TRUNC);
    CHECK(d.error==Error::invalid_parameter);
    CHECK(bytesAt(s.root/"drive_c"/"original")=="original");
}
void readOnlyOpenPreservesOriginal() {
    Sandbox s; FileApi api(s.root);
    auto p=s.root/"drive_c"/"locked"; std::ofstream(p)<<"original";
    CHECK(::chmod(p.c_str(),0400)==0);
    for (auto mode:{OPEN_EXISTING,CREATE_ALWAYS,TRUNCATE_EXISTING,OPEN_ALWAYS})
        CHECK(api.createFile(u"C:\\locked",GENERIC_WRITE,FILE_SHARE_READ,mode).error==Error::access_denied);
    CHECK(bytesAt(p)=="original");
    auto read=api.createFile(u"C:\\locked",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING);
    CHECK(read.ok()); CHECK(api.closeHandle(read.value)==Error::ok);
    CHECK(api.deleteFile(u"C:\\locked")==Error::access_denied);
}
void readOnlyReplacePreservesBoth() {
    Sandbox s; FileApi api(s.root);
    std::ofstream(s.root/"drive_c"/"new")<<"new";
    auto p=s.root/"drive_c"/"old"; std::ofstream(p)<<"original";
    CHECK(::chmod(p.c_str(),0400)==0);
    CHECK(api.moveFileEx(u"C:\\new",u"C:\\old",MOVEFILE_REPLACE_EXISTING)==Error::access_denied);
    CHECK(bytesAt(p)=="original"); CHECK(bytesAt(s.root/"drive_c"/"new")=="new");
}
void crossDriveMovePreservesOriginal() {
    Sandbox s; FileApi api(s.root); std::ofstream(s.root/"drive_c"/"source")<<"original";
    CHECK(static_cast<unsigned>(api.moveFileEx(u"C:\\source",u"D:\\target",0))==17);
    CHECK(bytesAt(s.root/"drive_c"/"source")=="original"); CHECK(!fs::exists(s.root/"drive_d"/"target"));
}
void negativeSeekPreservesPointer() {
    Sandbox s; FileApi api(s.root); auto h=api.createFile(u"C:\\seek",GENERIC_READ|GENERIC_WRITE,0,CREATE_NEW);
    CHECK(h.ok()); CHECK(api.writeFile(h.value,"abc",3).value==3);
    CHECK(static_cast<unsigned>(api.setFilePointer(h.value,-4,SEEK_CUR).error)==131);
    CHECK(api.setFilePointer(h.value,0,SEEK_CUR).value==3);
    CHECK(api.setFilePointer(h.value,0,77).error==Error::invalid_parameter);
    CHECK(api.closeHandle(h.value)==Error::ok);
}
void creationDispositions() {
    Sandbox s; FileApi api(s.root);
    CHECK(api.createFile(u"C:\\absent",GENERIC_WRITE,0,TRUNCATE_EXISTING).error==Error::file_not_found);
    auto h=api.createFile(u"C:\\modes",GENERIC_READ|GENERIC_WRITE,0,CREATE_NEW); CHECK(h.ok());
    CHECK(api.writeFile(h.value,"original",8).value==8); CHECK(api.closeHandle(h.value)==Error::ok);
    CHECK(api.createFile(u"C:\\modes",GENERIC_WRITE,0,CREATE_NEW).error==Error::file_exists);
    auto open=api.createFile(u"C:\\modes",GENERIC_READ|GENERIC_WRITE,0,OPEN_ALWAYS); CHECK(open.ok());
    CHECK(api.getFileSize(open.value).value==8); CHECK(api.closeHandle(open.value)==Error::ok);
    for (auto mode:{TRUNCATE_EXISTING,CREATE_ALWAYS}) {
        auto trunc=api.createFile(u"C:\\modes",GENERIC_WRITE,0,mode); CHECK(trunc.ok());
        CHECK(api.getFileSize(trunc.value).value==0); CHECK(api.closeHandle(trunc.value)==Error::ok);
    }
}
void sharingFailurePreservesOriginal() {
    Sandbox s; FileApi api(s.root); std::ofstream(s.root/"drive_c"/"old")<<"original";
    auto h=api.createFile(u"C:\\old",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING); CHECK(h.ok());
    CHECK(api.createFile(u"C:\\old",GENERIC_WRITE,0,CREATE_ALWAYS).error==Error::sharing_violation);
    CHECK(bytesAt(s.root/"drive_c"/"old")=="original"); CHECK(api.closeHandle(h.value)==Error::ok);
}
void repeatedHandlesAndPaths() {
    Sandbox s; const auto before=fdCount();
    {
        FileApi api(s.root);
        CHECK(api.createDirectory(u"C:\\한글")==Error::ok);
        auto h=api.createFile(u"c:/한글/테스트😀.bin",GENERIC_READ|GENERIC_WRITE,0,CREATE_NEW); CHECK(h.ok());
        CHECK(api.writeFile(h.value,"\0\xff",2).value==2); CHECK(api.closeHandle(h.value)==Error::ok);
        for (int i=0;i<250;++i) {
            auto r=api.createFile(u"C:\\한글\\테스트😀.bin",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING); CHECK(r.ok());
            CHECK(api.closeHandle(r.value)==Error::ok); CHECK(api.closeHandle(r.value)==Error::invalid_handle);
            CHECK(api.readFile(r.value,nullptr,0).error==Error::invalid_handle);
            CHECK(api.createFile(u"C:\\missing\\file",GENERIC_READ,0,OPEN_EXISTING).error==Error::path_not_found);
        }
    }
    CHECK(fdCount()==before);
}
void creationSuccessLastError() {
    Sandbox s; FileApi api(s.root);
    auto h=api.createFile(u"C:\\meta",GENERIC_READ,FILE_SHARE_READ,CREATE_NEW); CHECK(h.ok());
    CHECK(h.last_error==Error::ok); CHECK(api.closeHandle(h.value)==Error::ok);
    for (auto mode:{OPEN_ALWAYS,CREATE_ALWAYS}) {
        auto existing=api.createFile(u"C:\\meta",GENERIC_WRITE,FILE_SHARE_READ,mode); CHECK(existing.ok());
        CHECK(existing.last_error==Error::already_exists); CHECK(api.closeHandle(existing.value)==Error::ok);
    }
    auto fresh=api.createFile(u"C:\\fresh",GENERIC_WRITE,0,CREATE_ALWAYS); CHECK(fresh.ok());
    CHECK(fresh.last_error==Error::ok); CHECK(api.closeHandle(fresh.value)==Error::ok);
}
void flushRequiresWriteAccess() {
    Sandbox s; FileApi api(s.root); std::ofstream(s.root/"drive_c"/"flush")<<"original";
    for (auto access:{GENERIC_READ,0u}) {
        auto h=api.createFile(u"C:\\flush",access,FILE_SHARE_READ|FILE_SHARE_WRITE,OPEN_EXISTING); CHECK(h.ok());
        CHECK(api.flushFileBuffers(h.value)==Error::access_denied);
        CHECK(api.closeHandle(h.value)==Error::ok);
        CHECK(api.flushFileBuffers(h.value)==Error::invalid_handle);
    }
    auto writable=api.createFile(u"C:\\flush",GENERIC_WRITE,0,OPEN_EXISTING); CHECK(writable.ok());
    CHECK(api.flushFileBuffers(writable.value)==Error::ok); CHECK(api.closeHandle(writable.value)==Error::ok);
    CHECK(bytesAt(s.root/"drive_c"/"flush")=="original");
}
using Test=void(*)();
int main(int argc,char** argv) {
    const std::pair<const char*,Test> tests[]={
        {"open_always_readonly",openAlwaysReadOnly},{"invalid_crt_mode",invalidCrtModePreservesOriginal},
        {"readonly_open",readOnlyOpenPreservesOriginal},{"readonly_replace",readOnlyReplacePreservesBoth},
        {"cross_drive",crossDriveMovePreservesOriginal},{"negative_seek",negativeSeekPreservesPointer},
        {"dispositions",creationDispositions},{"sharing_preservation",sharingFailurePreservesOriginal},
        {"handle_paths",repeatedHandlesAndPaths},{"creation_last_error",creationSuccessLastError},{"flush_access",flushRequiresWriteAccess}};
    bool found=false; int failures=0;
    for (auto t:tests) if(argc==1 || std::string(argv[1])==t.first) {
        found=true;
        try { t.second(); std::cout<<t.first<<" PASS\n"; }
        catch(const std::exception& e) { ++failures; std::cerr<<e.what()<<'\n'; }
    }
    return !found || failures ? 1:0;
}
