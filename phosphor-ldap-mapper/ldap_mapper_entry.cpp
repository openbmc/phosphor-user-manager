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
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

LDAPMapperEntry::LDAPMapperEntry(sdbusplus::bus::bus &bus, const char *path,
                                 std::string privilege, LDAPMapperMgr &parent) :
    EntryIface(bus, path),
    DeleteIface(bus, path),
    groupName(std::experimental::filesystem::path(path).filename()),
    manager(parent)
{
    EntryIface::privilege(privilege);
    EntryIface::emit_object_added();
}

void LDAPMapperEntry::delete_(void)
{
    manager.deletePrivilegeMapper(groupName);
}

std::string LDAPMapperEntry::privilege(std::string value)
{
    if (value == EntryIface::privilege())
    {
        return value;
    }

    manager.checkPrivilegeLevel(value);
    return EntryIface::privilege(value);
}

std::string LDAPMapperEntry::privilege(void) const
{
    return EntryIface::privilege();
}

} // namespace user
} // namespace phosphor
