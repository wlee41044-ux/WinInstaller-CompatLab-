#include "test_support.h"
#include "winclab/registry_api.h"
#include <array>
#include <cstring>

void basicUtility() {
    Sandbox s; FileApi f(s.root); std::ofstream(s.root/"drive_c"/"input")<<"old";
    auto read=f.createFile(u"C:\\input",GENERIC_READ|GENERIC_WRITE,0,OPEN_EXISTING); CHECK(read.ok());
    std::array<char,8> b{}; CHECK(f.readFile(read.value,b.data(),b.size()).value==3);
    CHECK(std::string(b.data(),3)=="old"); CHECK(f.setFilePointer(read.value,0,SEEK_SET).ok());
    CHECK(f.writeFile(read.value,"new",3).value==3); CHECK(f.closeHandle(read.value)==Error::ok);
    auto out=f.createFile(u"C:\\copy",GENERIC_WRITE,0,CREATE_NEW); CHECK(out.ok());
    CHECK(f.writeFile(out.value,"result",6).value==6); CHECK(f.closeHandle(out.value)==Error::ok);
    CHECK(f.moveFileEx(u"C:\\copy",u"C:\\done",0)==Error::ok);
    CHECK(bytesAt(s.root/"drive_c"/"done")=="result"); CHECK(f.deleteFile(u"C:\\done")==Error::ok);
    CHECK(f.deleteFile(u"C:\\done")==Error::file_not_found); CHECK(bytesAt(s.root/"drive_c"/"input")=="new");
}
void installerLike() {
    Sandbox s; FileApi f(s.root); RegistryApi r;
    CHECK(f.createDirectory(u"C:\\Product")==Error::ok);
    for(int i=0;i<8;++i) {
        auto path=u"C:\\Product\\part"+std::u16string(1,static_cast<char16_t>(u'0'+i));
        auto h=f.createFile(path,GENERIC_WRITE,0,CREATE_NEW); CHECK(h.ok());
        CHECK(f.writeFile(h.value,"payload",7).value==7); CHECK(f.closeHandle(h.value)==Error::ok);
    }
    std::ofstream(s.root/"drive_c"/"Product"/"config")<<"user settings";
    std::ofstream(s.root/"drive_c"/"Product"/"staged")<<"updated";
    auto lock=f.createFile(u"C:\\Product\\config",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING); CHECK(lock.ok());
    CHECK(f.moveFileEx(u"C:\\Product\\staged",u"C:\\Product\\config",MOVEFILE_REPLACE_EXISTING)==Error::sharing_violation);
    CHECK(bytesAt(s.root/"drive_c"/"Product"/"config")=="user settings");
    CHECK(bytesAt(s.root/"drive_c"/"Product"/"staged")=="updated"); CHECK(f.closeHandle(lock.value)==Error::ok);
    CHECK(f.moveFileEx(u"C:\\Product\\staged",u"C:\\Product\\config",MOVEFILE_REPLACE_EXISTING)==Error::ok);
    auto key=r.createKey(HKEY_CURRENT_USER,u"Software\\Product",KEY_READ|KEY_WRITE); CHECK(key.ok());
    const std::uint8_t version[]={2,0,0,0};
    CHECK(r.setValue(key.value,u"Version",REG_DWORD,version,4)==Error::ok);
    CHECK(r.closeKey(key.value)==Error::ok); auto read=r.openKey(HKEY_CURRENT_USER,u"Software\\Product",KEY_READ); CHECK(read.ok());
    std::uint8_t out[4]{};std::uint32_t size=4;
    CHECK(r.queryValue(read.value,u"Version",nullptr,out,&size)==Error::ok && out[0]==2);
    CHECK(r.closeKey(read.value)==Error::ok && r.liveHandleCount()==0);
    CHECK(bytesAt(s.root/"drive_c"/"Product"/"config")=="updated");
    for(const auto& item:fs::directory_iterator(s.root/"drive_c"/"Product"))
        CHECK(bytesAt(item.path())==(item.path().filename()=="config"?"updated":"payload"));
}
void registryDependent() {
    RegistryApi r; auto h=r.createKey(HKEY_CURRENT_USER,u"Software\\Settings",KEY_READ|KEY_WRITE); CHECK(h.ok());
    const std::uint8_t text[]={'K',0,'O',0,0,0};
    CHECK(r.setValue(h.value,u"Language",REG_SZ,text,6)==Error::ok);
    std::uint32_t size=1;std::array<std::uint8_t,8> out{};out.fill(0xcc);
    CHECK(r.queryValue(h.value,u"language",nullptr,out.data()+1,&size)==Error::more_data && size==6);
    CHECK(out.front()==0xcc && out.back()==0xcc);
    CHECK(r.queryValue(h.value,u"language",nullptr,out.data()+1,&size)==Error::ok && size==6);
    CHECK(out.front()==0xcc && out.back()==0xcc && std::memcmp(out.data()+1,text,6)==0);
    CHECK(r.closeKey(h.value)==Error::ok && r.liveHandleCount()==0);
    RegistryApi other; CHECK(other.openKey(HKEY_CURRENT_USER,u"Software\\Settings",KEY_READ).error==Error::file_not_found);
    CHECK(other.queryValue(h.value,u"Language",nullptr,nullptr,nullptr)==Error::invalid_handle);
}
void crtApplication() {
    Sandbox s; FileApi f(s.root); const std::array<std::uint8_t,6> bytes{0,1,0xff,0x0d,0x0a,0x1a};
    auto d=f.wopen(u"D:\\binary",CRT_O_WRONLY|CRT_O_BINARY|CRT_O_CREAT|CRT_O_EXCL); CHECK(d.ok());
    CHECK(f.writeCrt(d.value,bytes.data(),bytes.size()).value==bytes.size());
    CHECK(f.readCrt(d.value,nullptr,0).error==Error::access_denied);
    auto borrowed=f.getOsfhandle(d.value);CHECK(borrowed.ok());
    CHECK(f.closeHandle(borrowed.value)==Error::invalid_handle); CHECK(f.closeCrt(d.value)==Error::ok);
    CHECK(f.writeFile(borrowed.value,bytes.data(),1).error==Error::invalid_handle);
    auto append=f.wopen(u"D:\\binary",CRT_O_RDWR|CRT_O_BINARY|CRT_O_APPEND);CHECK(append.ok());
    auto ah=f.getOsfhandle(append.value); CHECK(f.setFilePointer(ah.value,0,SEEK_SET).ok());
    CHECK(f.writeCrt(append.value,"Z",1).value==1); CHECK(f.closeCrt(append.value)==Error::ok);
    auto read=f.wopen(u"D:\\binary",CRT_O_BINARY); CHECK(read.ok());
    std::array<std::uint8_t,16> out{}; CHECK(f.readCrt(read.value,out.data(),out.size()).value==7);
    CHECK(std::memcmp(bytes.data(),out.data(),bytes.size())==0 && out[6]=='Z');
    CHECK(f.writeCrt(read.value,"x",1).error==Error::access_denied); CHECK(f.closeCrt(read.value)==Error::ok);
    CHECK(f.closeCrt(read.value)==Error::invalid_handle);
}
int main(int argc,char** argv) {
    if(argc!=2)return 1;
    try {
        std::string name=argv[1];
        if(name=="utility")basicUtility(); else if(name=="installer")installerLike();
        else if(name=="registry")registryDependent(); else if(name=="crt")crtApplication(); else return 1;
        std::cout<<"synthetic host profile "<<name<<" PASS (no EXE executed)\n";return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
