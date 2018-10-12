#pragma once

#include <string>
namespace phosphor
{
namespace ldap
{
constexpr auto LDAP_PREFIX = "ldap://";
constexpr auto LDAPS_PREFIX = "ldaps://";

/** @brief checks that the given URI is valid LDAP's URI.
 *      LDAP's URL begins with "ldap://".
 *  @param[in] URI - URI which needs to be validated.
 *  @returns true if it is valid otherwise false.
 */
bool isValidLDAPURI(const std::string& URI);

/** @brief checks that the given URI is valid LDAPS's URI.
 *      LDAPS's URL begins with "ldaps://".
 *  @param[in] URI - URI which needs to be validated.
 *  @returns true if it is valid otherwise false.
 */
bool isValidLDAPSURI(const std::string& URI);

/* @brief checks that the given ip address valid or not.
 * @param[in] address - IP address.
 * @returns true if it is valid otherwise false.
 */
bool isValidIP(const char* address);

} // namespace ldap
} // namespace phosphor
