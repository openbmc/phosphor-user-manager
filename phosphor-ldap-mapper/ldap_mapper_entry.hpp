#pragma once

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

// Path where all privilege mapper objects is created.
constexpr auto mapperObjPath = "/xyz/openbmc_project/user/ldap";

class LDAPMapperMgr; // Forward declaration for UserMgr.

/** @class LDAPMapperEntry
 *
 *  @brief List
 */
class LDAPMapperEntry : public EntryIface, DeleteIface
{
  public:
    LDAPMapperEntry() = delete;
    ~LDAPMapperEntry() = default;
    LDAPMapperEntry(const LDAPMapperEntry &) = delete;
    LDAPMapperEntry &operator=(const LDAPMapperEntry &) = delete;
    LDAPMapperEntry(LDAPMapperEntry &&) = delete;
    LDAPMapperEntry &operator=(LDAPMapperEntry &&) = delete;

    /** @brief Constructs UserMgr object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     *  @param[in] privilege - the privilege for the group
     *  @param[in] parent - LDAP privilege mapper manager
     */
    LDAPMapperEntry(sdbusplus::bus::bus &bus,
                    const char *path,
                    std::string privilege,
                    LDAPMapperMgr &parent);

    /** @brief delete user method.
     *
     *  This method deletes the privilege mapper entry
     */
    void delete_(void) override;

  private:
    std::string groupName;
    LDAPMapperMgr &manager;
};

} // namespace user
} // namespace phosphor
