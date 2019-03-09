#pragma once

#include <filesystem>
#include "ldap_configuration.hpp"

namespace phosphor
{
namespace ldap
{

namespace fs = std::filesystem;

/** @brief Serialize and persist LDAP service status property.
 *  @param[in] config - const reference to LDAP config object.
 *  @param[in] path -  path of persistent location where D-Bus property would be
 *                     saved.
 *  @return fs::path - pathname of persisted LDAP Config file.
 */
fs::path serialize(const Config& config, const fs::path& path);

/** @brief Deserialize LDAP service status into a D-Bus object
 *  @param[in] path - pathname of persisted LDAP Config file.
 *  @param[in] config - reference of the object which needs to be deserialized.
 *  @return bool - true if the deserialization was successful, false otherwise.
 */
bool deserialize(const fs::path& path, Config& config);

} // namespace ldap
} // namespace phosphor
