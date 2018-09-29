#pragma once

#include <experimental/filesystem>
#include "ldap_mapper_entry.hpp"

namespace phosphor
{
namespace user
{

namespace fs = std::experimental::filesystem;

/** @brief Serialize and persist LDAP privilege mapper D-bus object
 *
 *  @param[in] entry - LDAP privilege mapper entry
 *  @param[in] groupName - name of the LDAP group
 *
 *  @return fs::path - pathname of persisted error file
 */
fs::path serialize(const LDAPMapperEntry& entry, Id id);

/** @brief Deserialize a persisted LDAP privilege mapper into a D-bus object
 *
 *  @param[in] path - pathname of persisted file
 *  @param[in/out] entry - reference to  LDAP privilege mapper entry object
 *                         which is the target of deserialization.
 *
 *  @return bool - true if the deserialization was successful, false otherwise.
 */
bool deserialize(const fs::path& path, LDAPMapperEntry& entry);

} // namespace user
} // namespace phosphor
