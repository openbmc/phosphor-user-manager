#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/PrivilegeMapperEntry/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace user
{

namespace Base = sdbusplus::xyz::openbmc_project;
using EntryIface =
    sdbusplus::server::object::object<Base::User::server::PrivilegeMapperEntry>;
using DeleteIface =
    sdbusplus::server::object::object<Base::Object::server::Delete>;

class LDAPMapperMgr; // Forward declaration for UserMgr.

/** @class LDAPMapperEntry
 *
 *  @brief This D-Bus object represents the privilege level for the LDAP group.
 */
class LDAPMapperEntry : public EntryIface, DeleteIface
{
  public:
    LDAPMapperEntry() = delete;
    ~LDAPMapperEntry() = default;
    LDAPMapperEntry(const LDAPMapperEntry &) = delete;
    LDAPMapperEntry &operator=(const LDAPMapperEntry &) = delete;
    LDAPMapperEntry(LDAPMapperEntry &&) = default;
    LDAPMapperEntry &operator=(LDAPMapperEntry &&) = default;

    /** @brief Constructs LDAP privilege mapper entry object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     *  @param[in] privilege - the privilege for the group
     *  @param[in] parent - LDAP privilege mapper manager
     */
    LDAPMapperEntry(sdbusplus::bus::bus &bus, const char *path,
                    std::string privilege, LDAPMapperMgr &parent);

    /** @brief Constructs LDAP privilege mapper entry object
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     *  @param[in] parent - LDAP privilege mapper manager
     */
    LDAPMapperEntry(sdbusplus::bus::bus &bus, const char *path,
                    LDAPMapperMgr &parent);

    /** @brief Delete privilege mapper entry object
     *
     *  This method deletes the privilege mapper entry.
     */
    void delete_(void) override;

    /** @brief Update privilege associated with LDAP group
     *
     *  @param[in] value - privilege level
     *
     *  @return On success the updated privilege level
     */
    std::string privilege(std::string value) override;

    /** @brief Read privilege for the LDAP group
     *
     *  @return current privilege level
     */
    std::string privilege(void) const override;

  private:
    std::string groupName;
    LDAPMapperMgr &manager;
};

} // namespace user
} // namespace phosphor
