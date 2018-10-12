#include "utils.hpp"
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <ldap.h>

namespace phosphor
{
namespace ldap
{

bool isValidLDAPURI(const std::string& URI, const char* scheme)
{
    LDAPURLDesc* ludpp = nullptr;
    int res = LDAP_URL_ERR_BADURL;

    res = ldap_url_parse(URI.c_str(), &ludpp);
    if (res != LDAP_URL_SUCCESS)
    {
        ldap_free_urldesc(ludpp);
        return false;
    }
    if (std::strcmp(scheme, ludpp->lud_scheme) != 0)
    {
        ldap_free_urldesc(ludpp);
        return false;
    }
    addrinfo hints{};
    addrinfo* servinfo = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    auto result = getaddrinfo(ludpp->lud_host, nullptr, &hints, &servinfo);
    freeaddrinfo(servinfo);
    ldap_free_urldesc(ludpp);
    if (result)
    {
        return false;
    }
    return true;
}

} // namespace ldap
} // namespace phosphor
