#include "utils.hpp"
#include <phosphor-logging/log.hpp>
#include <netdb.h>
#include <arpa/inet.h>
#include <ldap.h>

namespace phosphor
{
namespace ldap
{
using namespace phosphor::logging;

bool isValidIP(const char* address)
{
    addrinfo hints{};
    addrinfo* res1 = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    auto result = getaddrinfo(address, nullptr, &hints, &res1);
    if (result)
    {
        log<level::ERR>("bad LDAP's host address", entry("ADDRESS=%s", address),
                        entry("ERRNO=%d", result));
        return false;
    }
    return true;
}

bool isValidLDAPURI(const std::string& URI)
{
    LDAPURLDesc* ludpp = nullptr;
    int res = LDAP_URL_ERR_BADURL;

    if (URI.find(LDAP_PREFIX) == 0)
    {
        res = ldap_url_parse(URI.c_str(), &ludpp);
    }

    if (res != LDAP_URL_SUCCESS)
    {
        log<level::ERR>("bad LDAPURI", entry("URI=%s", URI.c_str()),
                        entry("ERRNO=%d", res));
        return false;
    }
    return isValidIP(ludpp->lud_host);
}

bool isValidLDAPSURI(const std::string& URI)
{
    LDAPURLDesc* ludpp = nullptr;
    int res = LDAP_URL_ERR_BADURL;

    if (URI.find(LDAPS_PREFIX) == 0)
    {
        res = ldap_url_parse(URI.c_str(), &ludpp);
    }

    if (res != LDAP_URL_SUCCESS)
    {
        log<level::ERR>("bad LDAPSURI", entry("URI=%s", URI.c_str()),
                        entry("ERRNO=%d", res));
        return false;
    }
    return isValidIP(ludpp->lud_host);
}
} // namespace ldap
} // namespace phosphor
