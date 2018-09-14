#pragma once

#include "ldap_mapper_entry.hpp"
#include <xyz/openbmc_project/User/PrivilegeMapper/server.hpp>
#include <unordered_map>

namespace phosphor
{

namespace user
{

using MapperMgrIface =
        sdbusplus::xyz::openbmc_project::User::server::PrivilegeMapper;

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
    void createPrivilegeMapper(std::string groupName,
                               std::string privilege) override;

    /** @brief Delete privilege mapping for LDAP group
     *
     *  This method deletes the privilege mapping
     *
     *  @param[in] groupName - name of the LDAP group for which privilege
     *                         mapping is to be deleted.
     */
    void deletePrivilegeMapper(std::string groupName);

  private:

    /** @brief Check privilege mapping exists for the group name
     *
     *  @param[in] groupName - LDAP group name
     *
     *  @return -true if mapping exists and false if not.
     */
    bool checkPrivilegeMapping(const std::string &groupName);

    /** @brief Check if the privilege level is a valid one
     *
     *  @param[in] privilege - Privilege level
     *
     *  @return -true if privilege level is valid and false if not.
     */
    bool checkPrivilegeLevel(const std::string &privilege);

    /** @brief sdbusplus handler */
    sdbusplus::bus::bus &bus;

    /** @brief object path */
    const std::string path;

    /** @brief available privileges container */
    std::vector<std::string> privMgr = {"priv-admin", "priv-operator",
                                        "priv-user", "priv-callback"};

    /** @brief map container to hold privilege mapper objects */
    using GroupName = std::string;
    std::unordered_map<GroupName,
        std::unique_ptr<phosphor::user::LDAPMapperEntry>> PrivilegeMapperList;
};

} // namespace user
} // namespace phosphor
