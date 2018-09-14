#include <experimental/filesystem>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "config.h"
#include "ldap_mapper_entry.hpp"
#include "ldap_mapper_mgr.hpp"

namespace phosphor
{
namespace user
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;

using Argument = xyz::openbmc_project::Common::InvalidArgument;

/** @brief Constructs UserMgr object.
 *
 *  @param[in] bus  - sdbusplus handler
 *  @param[in] path - D-Bus path
 *  @param[in] groups - users group list
 *  @param[in] priv - user privilege
 *  @param[in] enabled - user enabled state
 *  @param[in] parent - user manager - parent object
 */
LDAPMapperEntry::LDAPMapperEntry(sdbusplus::bus::bus &bus,
                                 const char *path,
                                 std::string privilege,
                                 LDAPMapperMgr &parent) :
                    EntryIface(bus, path),
                    DeleteIface(bus, path),
                    groupName(std::experimental::filesystem::path(path).filename()),
                    manager(parent)
{
    EntryIface::privilege(privilege);
    EntryIface::emit_object_added();
}

/** @brief delete user method.
 *  This method deletes the user as requested
 *
 */
void LDAPMapperEntry::delete_(void)
{
    manager.deletePrivilegeMapper(groupName);
}

} // namespace user
} // namespace phosphor
