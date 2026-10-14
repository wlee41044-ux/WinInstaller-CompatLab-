#include "winclab/file_api.h"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs=std::filesystem;
using namespace winclab;

#define CHECK(v) do { if(!(v)) throw std::runtime_error(std::string("CHECK failed: ")+ #v+ " line "+std::to_string(__LINE__)); }while(false)

struct Fixture {
    fs::path root;
    Fixture() {
        char buf[]="/tmp/winclab-files-XXXXXX";
        char* name=::mkdtemp(buf);
        if(!name)throw std::runtime_error("mkdtemp failed");
        root=name;
    }
    ~Fixture(){std::error_code ec;fs::remove_all(root,ec);}
};

void testBasicFiles(FileApi& fsapi){
    CHECK(fsapi.getFileAttributes(u"C:\\").value==FILE_ATTRIBUTE_DIRECTORY);
    CHECK(fsapi.createDirectory(u"C:\\")==Error::already_exists);
    CHECK(fsapi.createDirectory(u"C:\\Apps\\")==Error::ok);
    CHECK(fsapi.createDirectory(u"c:\\apps")==Error::already_exists);
    auto missing=fsapi.createFile(u"C:\\Apps\\missing.txt",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING);
    CHECK(missing.error==Error::file_not_found);
    CHECK(fsapi.createFile(u"C:\\not_exist\\file.txt",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING).error==Error::path_not_found);
    auto h=fsapi.createFile(u"c:\\APPS\\Data.bin",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,CREATE_ALWAYS);
    CHECK(h.ok());
    const std::string data("hello\0there",11);
    CHECK(fsapi.writeFile(h.value,data.data(),data.size()).value==data.size());
    CHECK(fsapi.getFileSize(h.value).value==data.size());
    CHECK(fsapi.flushFileBuffers(h.value)==Error::ok);
    CHECK(fsapi.setFilePointer(h.value,0,SEEK_SET).value==0);
    std::array<char,64> buffer{};
    auto n=fsapi.readFile(h.value,buffer.data(),buffer.size());
    CHECK(n.ok() && n.value==data.size() && std::memcmp(buffer.data(),data.data(),data.size())==0);
    CHECK(fsapi.readFile(h.value,nullptr,10).error==Error::invalid_parameter);
    CHECK(fsapi.getFileAttributes(u"C:\\apps\\DATA.BIN").value==FILE_ATTRIBUTE_NORMAL);
    CHECK(fsapi.closeHandle(h.value)==Error::ok);
    CHECK(fsapi.closeHandle(h.value)==Error::invalid_handle);
    CHECK(fsapi.createFile(u"C:\\Apps\\data.bin",GENERIC_WRITE,FILE_SHARE_READ,CREATE_NEW).error==Error::file_exists);
    auto opened=fsapi.createFile(u"C:\\Apps\\DATA.BIN",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING);
    CHECK(opened.ok());
    CHECK(fsapi.writeFile(opened.value,"x",1).error==Error::access_denied);
    CHECK(fsapi.closeHandle(opened.value)==Error::ok);
    CHECK(fsapi.deleteFile(u"C:\\apps\\DATA.bin")==Error::ok);
    CHECK(fsapi.getFileAttributes(u"C:\\Apps\\Data.bin").error==Error::file_not_found);
    CHECK(fsapi.removeDirectory(u"C:\\apps")==Error::ok);
    CHECK(fsapi.removeDirectory(u"C:\\apps")==Error::path_not_found);
}

void testWin32Sharing(FileApi& api){
    auto creator=api.createFile(u"C:\\Share.dat",GENERIC_WRITE,FILE_SHARE_READ,CREATE_NEW);
    CHECK(creator.ok());
    CHECK(api.createFile(u"C:\\SHARE.dat",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,OPEN_EXISTING).error==Error::sharing_violation);
    auto reader=api.createFile(u"C:\\SHARE.dat",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,OPEN_EXISTING);
    CHECK(reader.ok());
    CHECK(api.deleteFile(u"C:\\Share.dat")==Error::sharing_violation);
    CHECK(api.moveFileEx(u"C:\\Share.dat",u"C:\\Moved.dat",0)==Error::sharing_violation);
    CHECK(api.closeHandle(creator.value)==Error::ok);
    CHECK(api.closeHandle(reader.value)==Error::ok);
    // Open handle permitting delete allows unlink while its FD remains usable.
    auto del=api.createFile(u"C:\\Share.dat",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,OPEN_EXISTING);
    CHECK(del.ok());
    CHECK(api.deleteFile(u"C:\\Share.dat")==Error::ok);
    CHECK(api.readFile(del.value,nullptr,0).ok());
    CHECK(api.closeHandle(del.value)==Error::ok);
}

void testCrtFileModes(FileApi& api){
    auto descriptor=api.wopen(u"D:\\created.bin",CRT_O_WRONLY|CRT_O_BINARY|CRT_O_CREAT|CRT_O_EXCL);
    CHECK(descriptor.ok());
    auto osf=api.getOsfhandle(descriptor.value);
    CHECK(osf.ok() && osf.value>=0x10000);
    CHECK(api.writeCrt(descriptor.value,"first",5).value==5);
    CHECK(api.closeHandle(osf.value)==Error::invalid_handle); // CRT owns handle.
    CHECK(api.closeCrt(descriptor.value)==Error::ok);
    CHECK(api.getOsfhandle(descriptor.value).error==Error::invalid_handle);
    auto app=api.wopen(u"d:\\CREATED.bin",CRT_O_WRONLY|CRT_O_BINARY|CRT_O_APPEND);
    CHECK(app.ok());
    CHECK(api.writeCrt(app.value,"!",1).value==1);
    CHECK(api.closeCrt(app.value)==Error::ok);
    auto r=api.wopen(u"D:\\created.bin",CRT_O_RDONLY|CRT_O_BINARY);
    CHECK(r.ok());
    std::array<char,16> buf{};
    auto n=api.readCrt(r.value,buf.data(),buf.size());
    CHECK(n.ok() && n.value==6 && std::string(buf.data(),6)=="first!");
    CHECK(api.writeCrt(r.value,"x",1).error==Error::access_denied);
    CHECK(api.closeCrt(r.value)==Error::ok);
    CHECK(api.wopen(u"D:\\created.bin",0).error==Error::not_supported); // no silent text->binary substitution
    CHECK(api.wopen(u"D:\\created.bin",CRT_O_BINARY|0x4000).error==Error::not_supported);
    CHECK(api.wopen(u"D:\\created.bin",CRT_O_BINARY|CRT_O_EXCL).error==Error::invalid_parameter);
    CHECK(api.wopen(u"D:\\created.bin",CRT_O_BINARY|CRT_O_WRONLY|CRT_O_CREAT|CRT_O_EXCL).error==Error::file_exists);
    CHECK(api.crtErrno(Error::file_not_found)==ENOENT);
    CHECK(api.crtErrno(Error::sharing_violation)==EACCES);
}

void testMoveAndFolders(FileApi& api){
    CHECK(api.createDirectory(u"D:\\Results\\")==Error::ok);
    auto file=api.createFile(u"D:\\file.tmp",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,CREATE_ALWAYS);
    CHECK(file.ok());CHECK(api.closeHandle(file.value)==Error::ok);
    CHECK(api.moveFileEx(u"D:\\file.tmp",u"D:\\Results\\Result.bin",0)==Error::ok);
    CHECK(api.getFileAttributes(u"d:\\results\\RESULT.BIN").ok());
    CHECK(api.createDirectory(u"D:\\Results\\NotEmpty")==Error::ok);
    CHECK(api.removeDirectory(u"D:\\Results")==Error::directory_not_empty);
    CHECK(api.moveFileEx(u"D:\\Results\\Result.bin",u"D:\\Results\\NotEmpty",MOVEFILE_REPLACE_EXISTING)==Error::sharing_violation);
    auto another=api.createFile(u"D:\\Results\\target.bin",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,CREATE_ALWAYS);
    CHECK(another.ok());CHECK(api.closeHandle(another.value)==Error::ok);
    CHECK(api.moveFileEx(u"D:\\Results\\Result.bin",u"D:\\Results\\TARGET.BIN",0)==Error::already_exists);
    CHECK(api.moveFileEx(u"D:\\Results\\Result.bin",u"D:\\Results\\TARGET.BIN",MOVEFILE_REPLACE_EXISTING)==Error::ok);
    CHECK(api.getFileAttributes(u"D:\\Results\\target.bin").ok());
    CHECK(api.moveFileEx(u"D:\\Results\\target.bin",u"D:\\Results\\x.bin",8)==Error::not_supported);
    CHECK(api.deleteFile(u"D:\\Results\\target.bin")==Error::ok);
    CHECK(api.removeDirectory(u"D:\\Results\\NotEmpty")==Error::ok);
    CHECK(api.removeDirectory(u"D:\\Results\\")==Error::ok);
}

void testPathSecurity(FileApi& api,const fs::path& root){
    for(const std::u16string p:{u"C:\\..\\secret",u"C:\\CON.txt",u"C:\\NUL",u"C:\\file:stream",u"C:\\name.",u"E:\\other",u"\\\\server\\share",u"C:\\file\\",u"C:\\app\\..\\x",u"C:\\A?B"}){
        CHECK(api.createFile(p,GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING).error==Error::invalid_name);
    }
    CHECK(api.getFileAttributes(u"C:\\missing\\file").error==Error::path_not_found);
    fs::path outside=root.string()+"-outside.txt";
    std::ofstream(outside)<<"PROTECTED";
    std::error_code ec;
    fs::create_symlink(outside,root/"drive_c"/"escape.txt",ec);
    CHECK(!ec);
    CHECK(api.getFileAttributes(u"C:\\escape.txt").error==Error::access_denied);
    CHECK(api.deleteFile(u"C:\\escape.txt")==Error::access_denied);
    CHECK(api.createFile(u"C:\\escape.txt",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING).error==Error::access_denied);
    fs::create_directory_symlink(root.parent_path(),root/"drive_c"/"symlink_dir",ec);
    CHECK(!ec);
    CHECK(api.createFile(u"C:\\symlink_dir\\unrelated.txt",GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING).error==Error::access_denied);
    CHECK(fs::exists(outside) && fs::file_size(outside)==9);
    fs::remove(outside);
    // Valid exact UTF-16 filenames, including supplementary Unicode surrogate pair.
    auto u=api.createFile(u"C:\\한글😀.txt",GENERIC_WRITE,FILE_SHARE_READ,CREATE_NEW);
    CHECK(u.ok());CHECK(api.closeHandle(u.value)==Error::ok);
    CHECK(api.getFileAttributes(u"C:\\한글😀.txt").ok());
    CHECK(api.createFile(std::u16string{u'C',u':',u'\\',0xD800},GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING).error==Error::invalid_name);
}

int main(){
    try {
        Fixture fx;
        FileApi f(fx.root);
        testBasicFiles(f);
        testWin32Sharing(f);
        testCrtFileModes(f);
        testMoveAndFolders(f);
        testPathSecurity(f,fx.root);
        std::cout<<"WINCLAB_V0_1: file API compatibility tests PASS\n";
        return 0;
    } catch(const std::exception& ex){std::cerr<<ex.what()<<'\n';return 1;}
}
