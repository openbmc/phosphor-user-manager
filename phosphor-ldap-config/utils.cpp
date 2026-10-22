#include "utils.hpp"

#include <arpa/inet.h>
#include <ldap.h>
#include <netdb.h>

#include <cstring>
#include <memory>
#include <string>
#include <string_view>

namespace phosphor
{
namespace ldap
{

bool isValidLDAPURI(const std::string& uri, const char* scheme)
{
    // Return false if the user tries to configure port 0
    // This check is not done in line 42, because ldap_url_parse
    // method internally converts port 0 to ldap port 389 and it
    // will always return true (thus allowing the user to
    // configure port 0)

    if (uri.ends_with(":0"))
    {
        return false;
    }

    LDAPURLDesc* ludpp = nullptr;
    int res = LDAP_URL_ERR_BADURL;
    res = ldap_url_parse(uri.c_str(), &ludpp);

    auto ludppCleanupFunc = [](LDAPURLDesc* ludpp) {
        ldap_free_urldesc(ludpp);
    };
    std::unique_ptr<LDAPURLDesc, decltype(ludppCleanupFunc)> ludppPtr(
        ludpp, ludppCleanupFunc);

    if (res != LDAP_URL_SUCCESS)
    {
        return false;
    }
    if (std::strcmp(scheme, ludppPtr->lud_scheme) != 0)
    {
        return false;
    }
    if (ludppPtr->lud_port < 0 || ludppPtr->lud_port > 65536)
    {
        return false;
    }
    addrinfo hints{};
    addrinfo* servinfo = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    auto result = getaddrinfo(ludppPtr->lud_host, nullptr, &hints, &servinfo);
    auto cleanupFunc = [](addrinfo* servinfo) { freeaddrinfo(servinfo); };
    std::unique_ptr<addrinfo, decltype(cleanupFunc)> servinfoPtr(
        servinfo, cleanupFunc);

    if (result)
    {
        return false;
    }
    return true;
}

bool isSafeConfigValue(const std::string& value)
{
    // nslcd reads its configuration line by line: a newline starts a new
    // directive, a carriage return or NUL can truncate or split one.
    constexpr std::string_view invalidChars{"\n\r\0", 3};
    return value.find_first_of(invalidChars) == std::string::npos;
}

} // namespace ldap
} // namespace phosphor
