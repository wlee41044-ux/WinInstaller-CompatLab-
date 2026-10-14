#include "winclab/file_api.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#include <linux/fs.h>
#endif

namespace winclab {
namespace {
constexpr std::uint32_t MASK_ACCESS = GENERIC_READ | GENERIC_WRITE;
constexpr std::uint32_t MASK_SHARE = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

bool asciiEqual(std::string_view a, std::string_view b) {
    if (a.size()!=b.size()) return false;
    for (std::size_t i=0; i<a.size(); ++i) {
        auto lower=[](unsigned char c) -> unsigned char { return (c>='A' && c<='Z') ? static_cast<unsigned char>(c+32) : c; };
        if (lower(static_cast<unsigned char>(a[i]))!=lower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

Result<std::string> findName(int dir, const std::string& wanted) {
    int dupfd=::openat(dir, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (dupfd<0) return {{},Error::access_denied};
    DIR* d=::fdopendir(dupfd);
    if (!d) {::close(dupfd); return {{},Error::access_denied};}
    std::string result;
    bool ambiguous=false;
    errno=0;
    while (const dirent* e=::readdir(d)) {
        if (!asciiEqual(e->d_name, wanted)) continue;
        if (!result.empty()) {ambiguous=true; break;}
        result=e->d_name;
    }
    const int err=errno;
    ::closedir(d);
    if (ambiguous) return {{},Error::invalid_name};
    if (err!=0 && result.empty()) return {{},Error::access_denied};
    return {result,Error::ok};
}

// Reject DOS device names even with an extension, alternate-stream syntax, and trailing . or space.
bool validComponent(const std::string& component) {
    if (component.empty() || component=="." || component==".." ||
        component.back()=='.' || component.back()==' ' || component.find(':')!=std::string::npos) return false;
    for (unsigned char c:component) if(c<32 || c==127 || c=='/' || c=='\\' || c=='?' || c=='*' || c=='"' || c=='<' || c=='>' || c=='|') return false;
    auto dot=component.find('.');
    std::string stem=component.substr(0,dot);
    for(char& c:stem) if(c>='a' && c<='z') c=static_cast<char>(c-32);
    if(stem=="CON" || stem=="PRN" || stem=="AUX" || stem=="NUL") return false;
    if(stem.size()==4 && (stem.substr(0,3)=="COM" || stem.substr(0,3)=="LPT") && stem[3]>='1' && stem[3]<='9') return false;
    return true;
}

bool utf8FromUtf16(const std::u16string& input,std::string& out) {
    out.reserve(input.size());
    for(std::size_t i=0; i<input.size(); ++i) {
        std::uint32_t cp=input[i];
        if(cp>=0xD800 && cp<=0xDBFF) {
            if(i+1>=input.size() || input[i+1]<0xDC00 || input[i+1]>0xDFFF) return false;
            cp=0x10000+((cp-0xD800)<<10)+(input[++i]-0xDC00);
        } else if(cp>=0xDC00 && cp<=0xDFFF) return false;
        if(cp<0x80) out.push_back(static_cast<char>(cp));
        else if(cp<0x800) {out.push_back(static_cast<char>(0xC0|(cp>>6)));out.push_back(static_cast<char>(0x80|(cp&63)));}
        else if(cp<0x10000) {out.push_back(static_cast<char>(0xE0|(cp>>12)));out.push_back(static_cast<char>(0x80|((cp>>6)&63)));out.push_back(static_cast<char>(0x80|(cp&63)));}
        else {out.push_back(static_cast<char>(0xF0|(cp>>18)));out.push_back(static_cast<char>(0x80|((cp>>12)&63)));out.push_back(static_cast<char>(0x80|((cp>>6)&63)));out.push_back(static_cast<char>(0x80|(cp&63)));}
    }
    return true;
}

bool isDriveRoot(const std::u16string& p) {
    return p.size()==3 &&
      (p[0]==u'C'||p[0]==u'c'||p[0]==u'D'||p[0]==u'd') &&
      p[1]==u':' && (p[2]==u'\\'||p[2]==u'/');
}
std::u16string normalizedDirectory(const std::u16string& p) {
    if (isDriveRoot(p)) return p;
    std::u16string result=p;
    while(!result.empty() && (result.back()==u'\\'||result.back()==u'/')) result.pop_back();
    return result;
}

std::uint32_t permissionForAccess(std::uint32_t access) {
    std::uint32_t p=0;
    if(access&GENERIC_READ) p|=FILE_SHARE_READ;
    if(access&GENERIC_WRITE) p|=FILE_SHARE_WRITE;
    return p;
}
}

FileApi::FileApi(const std::filesystem::path& isolated_root) {
    std::error_code ec;
    if(!std::filesystem::exists(isolated_root,ec)) {
        if(!std::filesystem::create_directories(isolated_root,ec) || ec) throw std::runtime_error("sandbox root creation failed");
    }
    root_fd_=::open(isolated_root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(root_fd_<0) throw std::runtime_error("sandbox root must be a real directory, not symlink");
    for (const char* drive:{"drive_c","drive_d"}) {
        if(::mkdirat(root_fd_,drive,0700)<0 && errno!=EEXIST) {::close(root_fd_);throw std::runtime_error("drive directory creation failed");}
        int fd=::openat(root_fd_,drive,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0) {::close(root_fd_);throw std::runtime_error("drive directory must not be symlink");}
        ::close(fd);
    }
}

FileApi::~FileApi() {
    for(auto& e:handles_) ::close(e.second.fd);
    if(root_fd_>=0) ::close(root_fd_);
}

Result<FileApi::Parsed> FileApi::parse(const std::u16string& path) {
    if(path.size()<4 || (path[0]!=u'C' && path[0]!=u'c' && path[0]!=u'D' && path[0]!=u'd') || path[1]!=u':' || (path[2]!=u'\\' && path[2]!=u'/'))
        return {{},Error::invalid_name};
    // Deny UNC, NT device paths, and path portions that are not confined to a drive.
    if(path[3]==u'\\' || path[3]==u'/') return {{},Error::invalid_name};
    Parsed out;
    out.drive=(path[0]==u'C'||path[0]==u'c')?"drive_c":"drive_d";
    std::u16string segment;
    for (std::size_t i=3;i<=path.size();++i) {
        if(i==path.size() || path[i]==u'\\' || path[i]==u'/') {
            if(segment.empty()) return {{},Error::invalid_name};
            std::string encoded;
            if(!utf8FromUtf16(segment,encoded) || !validComponent(encoded)) return {{},Error::invalid_name};
            out.components.push_back(std::move(encoded));segment.clear();
        } else segment.push_back(path[i]);
    }
    return {std::move(out),Error::ok};
}

Error FileApi::osError(int e, bool parent) {
    switch(e) {
        case ENOENT: return parent?Error::path_not_found:Error::file_not_found;
        case ENOTDIR: return Error::path_not_found;
        case EEXIST: return Error::already_exists;
        case EISDIR: case EACCES: case EPERM: case ELOOP: case EROFS: return Error::access_denied;
        case ENOTEMPTY: return Error::directory_not_empty;
        case EMFILE: case ENFILE: return Error::too_many_open_files;
        case ENOSPC: case EDQUOT: return Error::disk_full;
        case EINVAL: return Error::invalid_parameter;
        default: return Error::access_denied;
    }
}
void FileApi::closeParent(Parent& p) {if(p.fd>=0){::close(p.fd);p.fd=-1;}}

Result<FileApi::Parent> FileApi::parentOf(const std::u16string& path) const {
    const auto parsed=parse(path);
    if(!parsed.ok()) return {{},parsed.error};
    int fd=::openat(root_fd_,parsed.value.drive.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return {{},Error::path_not_found};
    Parent result;
    for(std::size_t i=0; i+1<parsed.value.components.size(); ++i) {
        auto match=findName(fd,parsed.value.components[i]);
        if(!match.ok()) {::close(fd);return {{},match.error};}
        if(match.value.empty()) {::close(fd);return {{},Error::path_not_found};}
        struct stat intermediate{};
        if(::fstatat(fd,match.value.c_str(),&intermediate,AT_SYMLINK_NOFOLLOW)<0){auto e=osError(errno,true);::close(fd);return{{},e};}
        if(S_ISLNK(intermediate.st_mode)){::close(fd);return {{},Error::access_denied};}
        int next=::openat(fd,match.value.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if(next<0){::close(fd);return {{},osError(errno,true)};}
        ::close(fd);fd=next;
    }
    result.fd=fd;
    result.leaf=parsed.value.components.back();
    result.key=parsed.value.drive;
    for(const auto& component:parsed.value.components){ result.key+='/'; for(unsigned char c:component)result.key+=static_cast<char>((c>='A'&&c<='Z')?c+32:c);}
    return {std::move(result),Error::ok};
}

bool FileApi::sharingConflict(std::uint64_t dev, std::uint64_t ino,std::uint32_t access,std::uint32_t share) const {
    for(const auto& item:handles_) {
        const File& f=item.second;
        if(f.dev!=dev || f.ino!=ino) continue;
        if((permissionForAccess(access)&~f.share) || (permissionForAccess(f.access)&~share))return true;
    }
    return false;
}
bool FileApi::deleteBlocked(std::uint64_t dev,std::uint64_t ino) const {
    for(const auto& item:handles_) if(item.second.dev==dev && item.second.ino==ino && !(item.second.share&FILE_SHARE_DELETE))return true;
    return false;
}

Result<Handle> FileApi::openLocked(const std::u16string& path,std::uint32_t access,
                                   std::uint32_t share,std::uint32_t disposition,bool append) {
    if((access&~MASK_ACCESS)!=0 || (share&~MASK_SHARE)!=0 ||
       disposition<CREATE_NEW || disposition>TRUNCATE_EXISTING ||
       (append && !(access&GENERIC_WRITE)))return {INVALID_HANDLE,Error::invalid_parameter};
    const bool create=disposition==CREATE_NEW || disposition==CREATE_ALWAYS || disposition==OPEN_ALWAYS;
    const bool truncate=disposition==CREATE_ALWAYS || disposition==TRUNCATE_EXISTING;
    if(truncate && !(access&GENERIC_WRITE))return {INVALID_HANDLE,Error::access_denied};
    if(isDriveRoot(path))return {INVALID_HANDLE,Error::access_denied};
    auto pr=parentOf(path);
    if(!pr.ok()) return {INVALID_HANDLE,pr.error};
    Parent p=std::move(pr.value);
    auto found=findName(p.fd,p.leaf);
    if(!found.ok()){closeParent(p);return {INVALID_HANDLE,found.error};}
    const bool exists=!found.value.empty();
    if((disposition==OPEN_EXISTING || disposition==TRUNCATE_EXISTING) && !exists){closeParent(p);return {INVALID_HANDLE,Error::file_not_found};}
    if(disposition==CREATE_NEW && exists){closeParent(p);return {INVALID_HANDLE,Error::file_exists};}
    struct stat old{};
    if(exists){
        if(::fstatat(p.fd,found.value.c_str(),&old,AT_SYMLINK_NOFOLLOW)<0){auto err=osError(errno);closeParent(p);return{INVALID_HANDLE,err};}
        if(!S_ISREG(old.st_mode)){closeParent(p);return{INVALID_HANDLE,Error::access_denied};}
        if((access&GENERIC_WRITE) && !(old.st_mode&S_IWUSR)){closeParent(p);return{INVALID_HANDLE,Error::access_denied};}
        if(sharingConflict(old.st_dev,old.st_ino,access,share)){closeParent(p);return {INVALID_HANDLE,Error::sharing_violation};}
    }
    int flags=O_CLOEXEC|O_NOFOLLOW;
    if((access&MASK_ACCESS)==MASK_ACCESS) flags|=O_RDWR;
    else if(access&GENERIC_WRITE) flags|=O_WRONLY;
    else flags|=O_RDONLY;
    if(append)flags|=O_APPEND;
    if(create)flags|=O_CREAT;
    if(disposition==CREATE_NEW)flags|=O_EXCL;
    // Defer O_TRUNC until after share checks so a denied open never damages a file.
    if(truncate)flags|=O_TRUNC;
    const auto& leaf=exists?found.value:p.leaf;
    int fd=::openat(p.fd,leaf.c_str(),flags,0600);
    const int e=errno;
    closeParent(p);
    if(fd<0)return {INVALID_HANDLE,osError(e)};
    struct stat st{};
    if(::fstat(fd,&st)!=0 || !S_ISREG(st.st_mode)) {::close(fd);return {INVALID_HANDLE,Error::access_denied};}
    Handle h=next_++;
    handles_.emplace(h,File{fd,access,share,static_cast<std::uint64_t>(st.st_dev),static_cast<std::uint64_t>(st.st_ino),append});
    return {h,Error::ok,exists && (disposition==CREATE_ALWAYS || disposition==OPEN_ALWAYS)
                          ?Error::already_exists:Error::ok};
}

Result<Handle> FileApi::createFile(const std::u16string& path,std::uint32_t access,std::uint32_t share,std::uint32_t disposition) {
    std::lock_guard<std::mutex> g(mutex_);
    return openLocked(path,access,share,disposition,false);
}
Result<std::size_t> FileApi::readFile(Handle handle,void* data,std::size_t length) {
    std::lock_guard<std::mutex> g(mutex_);
    auto i=handles_.find(handle);
    if(i==handles_.end())return {0,Error::invalid_handle};
    if(!(i->second.access&GENERIC_READ))return {0,Error::access_denied};
    if(length && !data)return {0,Error::invalid_parameter};
    auto n=::read(i->second.fd,data,std::min(length,static_cast<std::size_t>(SSIZE_MAX)));
    return n<0?Result<std::size_t>{0,osError(errno)}:Result<std::size_t>{static_cast<std::size_t>(n),Error::ok};
}
Result<std::size_t> FileApi::writeFile(Handle handle,const void* data,std::size_t length) {
    std::lock_guard<std::mutex> g(mutex_);
    auto i=handles_.find(handle);
    if(i==handles_.end())return {0,Error::invalid_handle};
    if(!(i->second.access&GENERIC_WRITE))return {0,Error::access_denied};
    if(length && !data)return {0,Error::invalid_parameter};
    auto n=::write(i->second.fd,data,std::min(length,static_cast<std::size_t>(SSIZE_MAX)));
    return n<0?Result<std::size_t>{0,osError(errno)}:Result<std::size_t>{static_cast<std::size_t>(n),Error::ok};
}
Result<std::uint64_t> FileApi::setFilePointer(Handle handle,std::int64_t distance,int origin){
    std::lock_guard<std::mutex> g(mutex_);
    auto i=handles_.find(handle);
    if(i==handles_.end())return {0,Error::invalid_handle};
    if(origin!=SEEK_SET && origin!=SEEK_CUR && origin!=SEEK_END)return {0,Error::invalid_parameter};
    off_t position=::lseek(i->second.fd,static_cast<off_t>(distance),origin);
    return position<0?Result<std::uint64_t>{0,errno==EINVAL?Error::negative_seek:osError(errno)}:Result<std::uint64_t>{static_cast<std::uint64_t>(position),Error::ok};
}
Result<std::uint64_t> FileApi::getFileSize(Handle handle){
    std::lock_guard<std::mutex> g(mutex_);
    auto i=handles_.find(handle);
    if(i==handles_.end())return {0,Error::invalid_handle};
    struct stat st{};if(::fstat(i->second.fd,&st)!=0)return {0,osError(errno)};
    return {static_cast<std::uint64_t>(st.st_size),Error::ok};
}
Error FileApi::flushFileBuffers(Handle handle){
    std::lock_guard<std::mutex> g(mutex_);
    auto i=handles_.find(handle);
    if(i==handles_.end())return Error::invalid_handle;
    if(!(i->second.access&GENERIC_WRITE))return Error::access_denied;
    return ::fsync(i->second.fd)==0?Error::ok:osError(errno);
}
Error FileApi::closeHandle(Handle handle){
    std::lock_guard<std::mutex> g(mutex_);
    auto i=handles_.find(handle);
    if(i==handles_.end())return Error::invalid_handle;
    // An open CRT descriptor owns this handle; only CRT close may release it.
    for(const auto& crt:crt_)if(crt.second==handle)return Error::invalid_handle;
    ::close(i->second.fd); handles_.erase(i);return Error::ok;
}

Error FileApi::deleteFile(const std::u16string& path){
    if(isDriveRoot(path))return Error::access_denied;
    std::lock_guard<std::mutex> g(mutex_);
    auto pr=parentOf(path);if(!pr.ok())return pr.error;
    Parent p=std::move(pr.value);
    auto name=findName(p.fd,p.leaf);
    if(!name.ok()){closeParent(p);return name.error;}
    if(name.value.empty()){closeParent(p);return Error::file_not_found;}
    struct stat st{};if(::fstatat(p.fd,name.value.c_str(),&st,AT_SYMLINK_NOFOLLOW)<0){auto e=osError(errno);closeParent(p);return e;}
    if(!S_ISREG(st.st_mode) || !(st.st_mode&S_IWUSR)){closeParent(p);return Error::access_denied;}
    if(deleteBlocked(st.st_dev,st.st_ino)){closeParent(p);return Error::sharing_violation;}
    int rc=::unlinkat(p.fd,name.value.c_str(),0);int error=errno;closeParent(p);
    return rc==0?Error::ok:osError(error);
}
Error FileApi::createDirectory(const std::u16string& path){
    if(isDriveRoot(path))return Error::already_exists;
    const auto normalized=normalizedDirectory(path);
    std::lock_guard<std::mutex> g(mutex_);
    auto pr=parentOf(normalized);if(!pr.ok())return pr.error;
    Parent p=std::move(pr.value);
    auto name=findName(p.fd,p.leaf);
    if(!name.ok()){closeParent(p);return name.error;}
    if(!name.value.empty()){closeParent(p);return Error::already_exists;}
    int rc=::mkdirat(p.fd,p.leaf.c_str(),0700);int error=errno;closeParent(p);
    return rc==0?Error::ok:osError(error);
}
Error FileApi::removeDirectory(const std::u16string& path){
    if(isDriveRoot(path))return Error::access_denied;
    const auto normalized=normalizedDirectory(path);
    std::lock_guard<std::mutex> g(mutex_);
    auto pr=parentOf(normalized);if(!pr.ok())return pr.error;
    Parent p=std::move(pr.value);
    auto name=findName(p.fd,p.leaf);
    if(!name.ok()){closeParent(p);return name.error;}
    if(name.value.empty()){closeParent(p);return Error::path_not_found;}
    struct stat st{};if(::fstatat(p.fd,name.value.c_str(),&st,AT_SYMLINK_NOFOLLOW)<0){auto e=osError(errno);closeParent(p);return e;}
    if(!S_ISDIR(st.st_mode)){closeParent(p);return Error::path_not_found;}
    int rc=::unlinkat(p.fd,name.value.c_str(),AT_REMOVEDIR);int error=errno;closeParent(p);
    return rc==0?Error::ok:osError(error);
}
Result<std::uint32_t> FileApi::getFileAttributes(const std::u16string& path){
    if(isDriveRoot(path))return {FILE_ATTRIBUTE_DIRECTORY,Error::ok};
    const auto normalized=normalizedDirectory(path);
    std::lock_guard<std::mutex> g(mutex_);
    auto pr=parentOf(normalized);if(!pr.ok())return {0,pr.error};
    Parent p=std::move(pr.value);
    auto name=findName(p.fd,p.leaf);
    if(!name.ok()){closeParent(p);return {0,name.error};}
    if(name.value.empty()){closeParent(p);return {0,Error::file_not_found};}
    struct stat st{};int rc=::fstatat(p.fd,name.value.c_str(),&st,AT_SYMLINK_NOFOLLOW);int error=errno;closeParent(p);
    if(rc<0)return {0,osError(error)};
    if(!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))return {0,Error::access_denied};
    std::uint32_t attr=S_ISDIR(st.st_mode)?FILE_ATTRIBUTE_DIRECTORY:FILE_ATTRIBUTE_NORMAL;
    if(!(st.st_mode&S_IWUSR))attr|=FILE_ATTRIBUTE_READONLY;
    return {attr,Error::ok};
}
Error FileApi::moveFileEx(const std::u16string& from,const std::u16string& to,std::uint32_t flags){
    if(flags & ~MOVEFILE_REPLACE_EXISTING)return Error::not_supported;
    const auto parsedFrom=parse(from),parsedTo=parse(to);
    if(!parsedFrom.ok() || !parsedTo.ok())return !parsedFrom.ok()?parsedFrom.error:parsedTo.error;
    if(parsedFrom.value.drive!=parsedTo.value.drive)return Error::not_same_device;
    std::lock_guard<std::mutex> g(mutex_);
    auto src=parentOf(from);if(!src.ok())return src.error;
    auto dst=parentOf(to);if(!dst.ok()){closeParent(src.value);return dst.error;}
    Parent a=std::move(src.value),b=std::move(dst.value);
    auto origin=findName(a.fd,a.leaf),dest=findName(b.fd,b.leaf);
    if(!origin.ok() || !dest.ok()){auto e=!origin.ok()?origin.error:dest.error;closeParent(a);closeParent(b);return e;}
    if(origin.value.empty()){closeParent(a);closeParent(b);return Error::file_not_found;}
    struct stat st{};if(::fstatat(a.fd,origin.value.c_str(),&st,AT_SYMLINK_NOFOLLOW)<0){auto e=osError(errno);closeParent(a);closeParent(b);return e;}
    if(!S_ISREG(st.st_mode)){closeParent(a);closeParent(b);return Error::access_denied;}
    if(deleteBlocked(st.st_dev,st.st_ino)){closeParent(a);closeParent(b);return Error::sharing_violation;}
    if(!dest.value.empty()){
        struct stat dstst{};if(::fstatat(b.fd,dest.value.c_str(),&dstst,AT_SYMLINK_NOFOLLOW)<0){auto e=osError(errno);closeParent(a);closeParent(b);return e;}
        if(!S_ISREG(dstst.st_mode) || deleteBlocked(dstst.st_dev,dstst.st_ino)){closeParent(a);closeParent(b);return Error::sharing_violation;}
        if(!(flags&MOVEFILE_REPLACE_EXISTING)){closeParent(a);closeParent(b);return Error::already_exists;}
        if(!(dstst.st_mode&S_IWUSR)){closeParent(a);closeParent(b);return Error::access_denied;}
    }
    // Android targets Linux: no-clobber rename uses renameat2 where available.
    int rc=-1;
    int saved=ENOSYS;
#if defined(__linux__) && defined(SYS_renameat2)
    if(!(flags&MOVEFILE_REPLACE_EXISTING)){
        rc=static_cast<int>(::syscall(SYS_renameat2,a.fd,origin.value.c_str(),b.fd,(dest.value.empty()?b.leaf:dest.value).c_str(),RENAME_NOREPLACE));
        saved=errno;
    } else
#endif
    {rc=::renameat(a.fd,origin.value.c_str(),b.fd,(dest.value.empty()?b.leaf:dest.value).c_str());saved=errno;}
    closeParent(a);closeParent(b);
    return rc==0?Error::ok:(saved==ENOSYS?Error::not_supported:osError(saved));
}

Result<int> FileApi::wopen(const std::u16string& path,std::uint32_t flags){
    constexpr std::uint32_t valid=CRT_O_RDWR|CRT_O_WRONLY|CRT_O_APPEND|CRT_O_NOINHERIT|CRT_O_CREAT|CRT_O_TRUNC|CRT_O_EXCL|CRT_O_BINARY;
    if(flags&~valid)return {-1,Error::not_supported};
    if((flags&(CRT_O_WRONLY|CRT_O_RDWR))==(CRT_O_WRONLY|CRT_O_RDWR) || ((flags&CRT_O_EXCL)&&!(flags&CRT_O_CREAT)) ||
       ((flags&CRT_O_TRUNC) && !(flags&(CRT_O_WRONLY|CRT_O_RDWR))))return {-1,Error::invalid_parameter};
    // Explicit _O_TEXT or no _O_BINARY is NOT assumed to mean binary: the CRT normally performs translation.
    if(!(flags&CRT_O_BINARY))return {-1,Error::not_supported};
    std::uint32_t access=GENERIC_READ;
    if((flags&CRT_O_RDWR)==CRT_O_RDWR)access=GENERIC_READ|GENERIC_WRITE;
    else if(flags&CRT_O_WRONLY)access=GENERIC_WRITE;
    std::uint32_t disposition=OPEN_EXISTING;
    if(flags&CRT_O_CREAT)disposition=(flags&CRT_O_EXCL)?CREATE_NEW:(flags&CRT_O_TRUNC)?CREATE_ALWAYS:OPEN_ALWAYS;
    else if(flags&CRT_O_TRUNC)disposition=TRUNCATE_EXISTING;
    std::lock_guard<std::mutex> g(mutex_);
    auto result=openLocked(path,access,FILE_SHARE_READ|FILE_SHARE_WRITE,disposition,(flags&CRT_O_APPEND)!=0);
    if(!result.ok())return {-1,result.error};
    int d=next_crt_++;
    crt_[d]=result.value;
    return {d,Error::ok};
}
Result<Handle> FileApi::getOsfhandle(int d){
    std::lock_guard<std::mutex> g(mutex_);auto it=crt_.find(d);return it==crt_.end()?Result<Handle>{INVALID_HANDLE,Error::invalid_handle}:Result<Handle>{it->second,Error::ok};
}
Result<std::size_t> FileApi::readCrt(int d,void* buffer,std::size_t count){
    auto h=getOsfhandle(d);return h.ok()?readFile(h.value,buffer,count):Result<std::size_t>{0,h.error};
}
Result<std::size_t> FileApi::writeCrt(int d,const void* buffer,std::size_t count){
    auto h=getOsfhandle(d);return h.ok()?writeFile(h.value,buffer,count):Result<std::size_t>{0,h.error};
}
Error FileApi::closeCrt(int d){
    std::lock_guard<std::mutex> g(mutex_);
    auto it=crt_.find(d);if(it==crt_.end())return Error::invalid_handle;
    auto handle=handles_.find(it->second);if(handle!=handles_.end()){::close(handle->second.fd);handles_.erase(handle);}
    crt_.erase(it);return Error::ok;
}
int FileApi::crtErrno(Error e){
    // POSIX errno values map to CRT errno for common filesystem errors.
    switch(e){
        case Error::ok:return 0;
        case Error::file_not_found:case Error::path_not_found:return ENOENT;
        case Error::access_denied:case Error::sharing_violation:return EACCES;
        case Error::file_exists:case Error::already_exists:return EEXIST;
        case Error::invalid_handle:return EBADF;
        case Error::too_many_open_files:return EMFILE;
        case Error::disk_full:return ENOSPC;
        case Error::directory_not_empty:return ENOTEMPTY;
        case Error::invalid_name:case Error::invalid_parameter:return EINVAL;
        default:return EINVAL;
    }
}
} // namespace winclab
