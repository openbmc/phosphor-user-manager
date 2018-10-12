#include "utils.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <netdb.h>
#include <arpa/inet.h>
#include <ldap.h>
#include <iostream>

namespace phosphor
{
namespace ldap
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

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

bool isValidLDAPURI(const char* URI)
{
    LDAPURLDesc* ludpp;
    int res;

    if (ldap_is_ldap_url(URI))
    {
        if ((res = ldap_url_parse(URI, &ludpp)) != 0)
        {
            log<level::ERR>("bad LDAPURI", entry("URI=%s", URI),
                            entry("ERRNO=%d", res));
            return false;
        }
    }
    else
    {
        log<level::ERR>("bad LDAPSURI", entry("URI=%s", URI),
                        entry("ERRNO=%d", res));
        return false;
    }
    return isValidIP(ludpp->lud_host);
}

bool isValidLDAPSURI(const char* URI)
{
    LDAPURLDesc* ludpp;
    int res;

    if (ldap_is_ldaps_url(URI))
    {
        if ((res = ldap_url_parse(URI, &ludpp)) != 0)
        {
            log<level::ERR>("bad LDAPSURI", entry("URI=%s", URI),
                            entry("ERRNO=%d", res));
            return false;
        }
    }
    else
    {
        log<level::ERR>("bad LDAPSURI", entry("URI=%s", URI),
                        entry("ERRNO=%d", res));
        return false;
    }
    return isValidIP(ludpp->lud_host);
}
} // namespace ldap
} // namespace phosphor
