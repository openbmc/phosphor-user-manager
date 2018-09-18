#pragma once

#include <string>
#include <sdbusplus/bus.hpp>

namespace phosphor
{
namespace ldap
{
constexpr auto LDAP_URL_PREFIX = "ldap://";
constexpr auto LDAPS_URL_PREFIX = "ldaps://";

/* @brief checks that the given URL is LDAP URL or not.
 * @param[in] url - url.
 * @returns true if it is LDAP URL otherwise false.
 */
bool isValidLDAPURI(std::string url);
} // namespace ldap
} // namespace phosphor
