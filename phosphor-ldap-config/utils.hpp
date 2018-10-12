#pragma once

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <map>
#include <string>

#include <sdbusplus/server.hpp>

namespace phosphor
{
namespace ldap
{
/** @brief checks that the given URI is vlaid LDAP's URI.
 *  @param[in] URI - URI which is needs to be validated.
 *  @returns true if it is valid otherwise false.
 */
bool isValidLDAPURI(const char* URI);

/** @brief checks that the given URI is vlaid LDAPS's URI.
 *  @param[in] URI - URI which is needs to be validated.
 *  @returns true if it is valid otherwise false.
 */
bool isValidLDAPSURI(const char* URI);

/* @brief checks that the given ip address valid or not.
 * @param[in] address - IP address.
 * @returns true if it is valid otherwise false.
 */
bool isValidIP(const char* address);

} // namespace ldap
} // namespace phosphor
