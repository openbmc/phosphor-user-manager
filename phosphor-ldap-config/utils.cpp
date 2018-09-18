#include "utils.hpp"

namespace phosphor
{
namespace ldap
{

bool isValidLDAPURI(std::string url)
{
    // TODO use the API ldap_is_ldap_url from Openldap library
    return url.find(LDAP_URL_PREFIX) == 0 || url.find(LDAPS_URL_PREFIX) == 0;
}
} // namespace ldap
} // namespace phosphor
