#pragma once
#include "winclab/file_api.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#define CHECK(v) do { if (!(v)) throw std::runtime_error(std::string(__func__)+": "+#v+" line "+std::to_string(__LINE__)); } while(false)
namespace fs = std::filesystem;
using namespace winclab;
struct Sandbox {
    fs::path root;
    Sandbox() {
        char temp[]="/tmp/winclab-v02-XXXXXX";
        auto p=::mkdtemp(temp);
        if (!p) throw std::runtime_error("mkdtemp");
        root=p;
    }
    ~Sandbox() { std::error_code ec; fs::remove_all(root,ec); }
};
inline std::string bytesAt(const fs::path& p) {
    std::ifstream in(p,std::ios::binary);
    return {std::istreambuf_iterator<char>(in),std::istreambuf_iterator<char>()};
}
inline std::size_t fdCount() {
    return static_cast<std::size_t>(std::distance(fs::directory_iterator("/proc/self/fd"),fs::directory_iterator{}));
}
