#include "test_support.h"
#include "winclab/registry_api.h"
#include <array>
#include <set>
#include <string>

using namespace winclab;
void enumerationAndDeletion() {
    RegistryApi api;
    auto parent=api.createKey(HKEY_CURRENT_USER,u"Software\\Demo",KEY_ALL_ACCESS);
    CHECK(parent.ok());
    CHECK(api.createKey(parent.value,u"ChildA\\Grandchild",KEY_ALL_ACCESS).ok());
    CHECK(api.createKey(parent.value,u"ChildB",KEY_ALL_ACCESS).ok());
    CHECK(api.createKey(parent.value,u"CHILDA",KEY_ALL_ACCESS).ok());
    auto read=api.openKey(parent.value,u"",KEY_READ); CHECK(read.ok());
    CHECK(api.enumerateSubkey(read.value,0).value==u"childa");
    CHECK(api.enumerateSubkey(read.value,1).value==u"childb");
    CHECK(api.enumerateSubkey(read.value,2).error==Error::no_more_items);
    CHECK(api.enumerateSubkey(999,0).error==Error::invalid_handle);
    auto restricted=api.openKey(parent.value,u"",KEY_QUERY_VALUE); CHECK(restricted.ok());
    CHECK(api.enumerateSubkey(restricted.value,0).error==Error::access_denied);
    const std::uint8_t raw[]={0,42,0xff};
    CHECK(api.setValue(parent.value,u"ValueB",REG_BINARY,raw,sizeof(raw))==Error::ok);
    CHECK(api.setValue(parent.value,u"ValueA",REG_BINARY,nullptr,0)==Error::ok);
    CHECK(api.setValue(parent.value,u"",REG_BINARY,raw,1)==Error::ok);
    auto empty=api.enumerateValue(read.value,0); CHECK(empty.ok());
    CHECK(empty.value.name.empty() && empty.value.bytes==std::vector<std::uint8_t>({0}));
    auto a=api.enumerateValue(read.value,1); CHECK(a.ok() && a.value.name==u"valuea" && a.value.bytes.empty());
    auto b=api.enumerateValue(read.value,2); CHECK(b.ok() && b.value.name==u"valueb" && b.value.type==REG_BINARY);
    CHECK(b.value.bytes==std::vector<std::uint8_t>({0,42,0xff}));
    CHECK(api.enumerateValue(read.value,3).error==Error::no_more_items);
    CHECK(api.enumerateValue(999,0).error==Error::invalid_handle);
    auto enumDenied=api.openKey(parent.value,u"",KEY_ENUMERATE_SUB_KEYS); CHECK(enumDenied.ok());
    CHECK(api.enumerateValue(enumDenied.value,0).error==Error::access_denied);
    CHECK(api.deleteValue(read.value,u"valueb")==Error::access_denied);
    CHECK(api.deleteValue(parent.value,u"valueb")==Error::ok);
    CHECK(api.deleteValue(parent.value,u"valueb")==Error::file_not_found);
    CHECK(api.enumerateValue(read.value,2).error==Error::no_more_items);
    CHECK(api.deleteValue(parent.value,std::u16string{0xd800})==Error::invalid_parameter);
    CHECK(api.closeKey(parent.value)==Error::ok);
    CHECK(api.enumerateValue(parent.value,0).error==Error::invalid_handle);
}
void hiveAndIsolation() {
    RegistryApi first,second;
    auto firstRoot=first.createKey(HKEY_CURRENT_USER,u"Demo",KEY_ALL_ACCESS); CHECK(firstRoot.ok());
    CHECK(first.createKey(firstRoot.value,u"A",KEY_READ).ok());
    CHECK(second.enumerateSubkey(HKEY_CURRENT_USER,0).error==Error::no_more_items);
    CHECK(second.deleteValue(firstRoot.value,u"anything")==Error::invalid_handle);
    CHECK(first.deleteValue(HKEY_LOCAL_MACHINE,u"anything")==Error::access_denied);
    CHECK(first.enumerateSubkey(HKEY_LOCAL_MACHINE,0).error==Error::no_more_items);
}
int main() {
    enumerationAndDeletion();
    hiveAndIsolation();
    return 0;
}
