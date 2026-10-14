#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace winclab {

using Handle = std::uint64_t;
constexpr Handle INVALID_HANDLE = ~Handle{0};

// Windows-compatible numeric values; no Windows SDK dependency.
constexpr std::uint32_t GENERIC_READ = 0x80000000u;
constexpr std::uint32_t GENERIC_WRITE = 0x40000000u;
constexpr std::uint32_t FILE_SHARE_READ = 1;
constexpr std::uint32_t FILE_SHARE_WRITE = 2;
constexpr std::uint32_t FILE_SHARE_DELETE = 4;
constexpr std::uint32_t CREATE_NEW = 1;
constexpr std::uint32_t CREATE_ALWAYS = 2;
constexpr std::uint32_t OPEN_EXISTING = 3;
constexpr std::uint32_t OPEN_ALWAYS = 4;
constexpr std::uint32_t TRUNCATE_EXISTING = 5;
constexpr std::uint32_t MOVEFILE_REPLACE_EXISTING = 1;
constexpr std::uint32_t FILE_ATTRIBUTE_READONLY = 1;
constexpr std::uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x10;
constexpr std::uint32_t FILE_ATTRIBUTE_NORMAL = 0x80;

// Supported MSVC CRT `_O_*` flag values.
constexpr std::uint32_t CRT_O_RDONLY = 0;
constexpr std::uint32_t CRT_O_WRONLY = 1;
constexpr std::uint32_t CRT_O_RDWR = 2;
constexpr std::uint32_t CRT_O_APPEND = 8;
constexpr std::uint32_t CRT_O_NOINHERIT = 0x80;
constexpr std::uint32_t CRT_O_CREAT = 0x100;
constexpr std::uint32_t CRT_O_TRUNC = 0x200;
constexpr std::uint32_t CRT_O_EXCL = 0x400;
constexpr std::uint32_t CRT_O_BINARY = 0x8000;

// Real Win32 error codes, intentionally not host errno.
enum class Error : std::uint32_t {
    ok=0, file_not_found=2, path_not_found=3, too_many_open_files=4,
    access_denied=5, invalid_handle=6, not_enough_memory=8, invalid_data=13,
    write_protect=19, sharing_violation=32, not_supported=50,
    file_exists=80, invalid_parameter=87, disk_full=112, invalid_name=123,
    directory_not_empty=145, already_exists=183,
};

template<class T> struct Result {
    T value{};
    Error error{Error::ok};
    [[nodiscard]] bool ok() const { return error == Error::ok; }
};

// Linux / Android POSIX-backed testable compatibility core. Callers translate guest
// pointers, registers, LastError/errno, and callbacks independently.
class FileApi {
public:
    explicit FileApi(const std::filesystem::path& isolated_root);
    ~FileApi();
    FileApi(const FileApi&) = delete;
    FileApi& operator=(const FileApi&) = delete;

    // Windows paths must be C:\\... or D:\\... . Drive roots live under root/drive_c and root/drive_d.
    Result<Handle> createFile(const std::u16string& path, std::uint32_t access,
                              std::uint32_t share, std::uint32_t disposition);
    Result<std::size_t> readFile(Handle handle, void* buffer, std::size_t count);
    Result<std::size_t> writeFile(Handle handle, const void* buffer, std::size_t count);
    Result<std::uint64_t> setFilePointer(Handle handle, std::int64_t distance, int origin);
    Result<std::uint64_t> getFileSize(Handle handle);
    Error flushFileBuffers(Handle handle);
    Error closeHandle(Handle handle);

    Error deleteFile(const std::u16string& path);
    Error createDirectory(const std::u16string& path);
    Error removeDirectory(const std::u16string& path);
    Result<std::uint32_t> getFileAttributes(const std::u16string& path);
    Error moveFileEx(const std::u16string& from, const std::u16string& to, std::uint32_t flags);

    // CRT descriptors are process-owned and separated from Win32 handles.
    Result<int> wopen(const std::u16string& path, std::uint32_t crt_flags);
    Result<std::size_t> readCrt(int descriptor, void* buffer, std::size_t count);
    Result<std::size_t> writeCrt(int descriptor, const void* buffer, std::size_t count);
    Result<Handle> getOsfhandle(int descriptor);
    Error closeCrt(int descriptor);
    static int crtErrno(Error error);

private:
    struct File {
        int fd{-1};
        std::uint32_t access{0}, share{0};
        std::uint64_t dev{0}, ino{0};
        bool append{false};
    };
    std::mutex mutex_;
    int root_fd_{-1};
    Handle next_{0x10000};
    std::map<Handle, File> handles_;
    int next_crt_{3};
    std::map<int, Handle> crt_;

    struct Parsed { std::string drive; std::vector<std::string> components; };
    struct Parent { int fd{-1}; std::string leaf; std::string key; };
    static Result<Parsed> parse(const std::u16string& path);
    Result<Parent> parentOf(const std::u16string& path) const;
    static Error osError(int value, bool parent=false);
    static void closeParent(Parent& parent);
    Result<Handle> openLocked(const std::u16string& path, std::uint32_t access,
                              std::uint32_t share, std::uint32_t disposition, bool append);
    bool sharingConflict(std::uint64_t dev, std::uint64_t ino, std::uint32_t access,
                         std::uint32_t share) const;
    bool deleteBlocked(std::uint64_t dev, std::uint64_t ino) const;
};

} // namespace winclab
