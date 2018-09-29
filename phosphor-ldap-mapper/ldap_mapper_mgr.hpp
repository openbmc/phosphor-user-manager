#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include "ldap_mapper_entry.hpp"
#include <xyz/openbmc_project/User/PrivilegeMapper/server.hpp>
#include <unordered_map>

namespace phosphor
{

namespace user
{

using MapperMgrIface =
    sdbusplus::xyz::openbmc_project::User::server::PrivilegeMapper;

// D-Bus root for LDAP privilege mapper
constexpr auto mapperMgrRoot = "/xyz/openbmc_project/user/ldap";

/** @class LDAPMapperMgr
 *
 *  @brief Responsible for managing LDAP groups to privilege mapping.
 */
class LDAPMapperMgr : public MapperMgrIface
{
  public:
    LDAPMapperMgr() = delete;
    ~LDAPMapperMgr() = default;
    LDAPMapperMgr(const LDAPMapperMgr &) = delete;
    LDAPMapperMgr &operator=(const LDAPMapperMgr &) = delete;
    LDAPMapperMgr(LDAPMapperMgr &&) = delete;
    LDAPMapperMgr &operator=(LDAPMapperMgr &&) = delete;

    /** @brief Constructs LDAPMapperMgr object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     */
    LDAPMapperMgr(sdbusplus::bus::bus &bus, const char *path);

    /** @brief Creates a mapping for the group to the privilege
     *
     *  @param[in] groupName - Group Name to which the privilege needs to be
     *                         assigned.
     *  @param[in] privilege - The privilege role associated with the group.
     */
    std::string create(std::string groupName, std::string privilege) override;

    /** @brief Delete privilege mapping for LDAP group
     *
     *  This method deletes the privilege mapping
     *
     *  @param[in] groupName - name of the LDAP group for which privilege
     *                         mapping is to be deleted.
     */
    void deletePrivilegeMapper(std::string groupName);

    /** @brief Check if LDAP group privilege mapping requested is valid
     *
     *  Check if the privilege mapping already exists for the LDAP group name
     *  / group name is empty/ group name contains only the ASCII characters
     *  "[A-Z][a-z][0-9]_".
     *
     *  @param[in] groupName - LDAP group name
     *
     *  @return throw exception if the conditions are not met.
     */
    void checkPrivilegeMapper(const std::string &groupName);

    /** @brief Check if the privilege level is a valid one
     *
     *  @param[in] privilege - Privilege level
     *
     *  @return -true if privilege level is valid and false if not.
     */
    void checkPrivilegeLevel(const std::string &privilege);

    /** @brief Construct LDAP mapper entry D-Bus objects from their persisted
     *         representations.
     */
    void restore();

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus &bus;

    /** @brief object path for the manager object*/
    const std::string path;

    /** @brief available privileges container */
    std::vector<std::string> privMgr = {"priv-admin", "priv-operator",
                                        "priv-user", "priv-callback"};

    /** @brief container to hold privilege mapper objects */
    using GroupName = std::string;
    std::unordered_map<GroupName,
                       std::unique_ptr<phosphor::user::LDAPMapperEntry>>
        PrivilegeMapperList;
};

} // namespace user
} // namespace phosphor
