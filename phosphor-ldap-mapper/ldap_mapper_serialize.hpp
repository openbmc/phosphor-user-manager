#pragma once

#include "config.h"

#include "ldap_mapper_entry.hpp"

#include <filesystem>

namespace phosphor
{
namespace user
{

/** @brief Serialize and persist LDAP privilege mapper D-Bus object
 *
 *  @param[in] entry - LDAP privilege mapper entry
 *  @param[in] id - filename of the persisted LDAP mapper entry
 *  @param[in] dir - pathname of directory where the serialized privilege
 *                   mappings are stored.
 *
 *  @return std::filesystem::path - pathname of persisted error file
 */
std::filesystem::path serialize(const LDAPMapperEntry& entry, Id id,
                                const std::filesystem::path& dir);

/** @brief Deserialize a persisted LDAP privilege mapper into a D-Bus object
 *
 *  @param[in] path - pathname of persisted file
 *  @param[in/out] entry - reference to  LDAP privilege mapper entry object
 *                         which is the target of deserialization.
 *
 *  @return bool - true if the deserialization was successful, false otherwise.
 */
bool deserialize(const std::filesystem::path& path, LDAPMapperEntry& entry);

} // namespace user
} // namespace phosphor
