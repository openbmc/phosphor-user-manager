#pragma once

#include <string>

namespace phosphor
{
namespace ldap
{

/** @brief checks that the given URI is valid LDAP's URI.
 *      LDAP's URL begins with "ldap://" and LDAPS's URL begins with "ldaps://"
 *  @param[in] URI - URI which needs to be validated.
 *  @param[in] scheme - LDAP's scheme, scheme equals to "ldaps" to validate
 *       against LDAPS type URI, for LDAP type URI it is equals to "ldap".
 *  @returns true if it is valid otherwise false.
 */
bool isValidLDAPURI(const std::string& uri, const char* scheme);

/** @brief checks that the given value can be written into a single nslcd.conf
 *      directive line.
 *  @param[in] value - The value to be checked.
 *  @returns false if the value contains a line break or an embedded NUL,
 *       otherwise true.
 */
bool isSafeConfigValue(const std::string& value);

} // namespace ldap
} // namespace phosphor
