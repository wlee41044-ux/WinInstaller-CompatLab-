// Linux x86-64 host probe: distinguish a read from a write to output-only storage.
// The page fault is expected; restore its protection and resume the instruction.
#include "test_support.h"
#include "winclab/registry_api.h"
#include <csignal>
#include <cstdint>
#include <new>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>

namespace {
void* output_page=nullptr;
std::size_t page_size=0;
volatile std::sig_atomic_t read_before_write=0;
void outputFault(int, siginfo_t* info, void* context) {
    if(info->si_addr!=output_page)_exit(100);
    const auto* state=static_cast<ucontext_t*>(context);
    // x86 page-fault error code bit 1: zero = read, one = write.
    read_before_write=(state->uc_mcontext.gregs[REG_ERR]&2)?0:1;
    if(::syscall(SYS_mprotect,output_page,page_size,PROT_READ|PROT_WRITE)!=0)_exit(101);
}
}
int main() {
    try {
        RegistryApi r;auto h=r.createKey(HKEY_CURRENT_USER,u"Probe",KEY_READ|KEY_WRITE);CHECK(h.ok());
        const std::uint8_t bytes[]={1,2,3,4};
        CHECK(r.setValue(h.value,u"x",REG_BINARY,bytes,4)==Error::ok);
        page_size=static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
        output_page=::mmap(nullptr,page_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        CHECK(output_page!=MAP_FAILED);
        auto* required=new(output_page) std::uint32_t; // intentionally output-only
        struct sigaction action{},previous{};
        action.sa_sigaction=outputFault;action.sa_flags=SA_SIGINFO;
        ::sigemptyset(&action.sa_mask);CHECK(::sigaction(SIGSEGV,&action,&previous)==0);
        CHECK(::mprotect(output_page,page_size,PROT_NONE)==0);
        const auto result=r.queryValue(h.value,u"x",nullptr,nullptr,required);
        const auto actual=*required;
        CHECK(::sigaction(SIGSEGV,&previous,nullptr)==0);
        CHECK(::munmap(output_page,page_size)==0);
        CHECK(read_before_write==0); CHECK(result==Error::ok && actual==4);
        CHECK(r.closeKey(h.value)==Error::ok);
        std::cout<<"output-only size is written before any read PASS\n";return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
