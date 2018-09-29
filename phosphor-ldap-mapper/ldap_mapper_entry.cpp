#include <experimental/filesystem>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "config.h"
#include "ldap_mapper_entry.hpp"
#include "ldap_mapper_mgr.hpp"
#include "ldap_mapper_serialize.hpp"

namespace phosphor
{
namespace user
{

using namespace phosphor::logging;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

LDAPMapperEntry::LDAPMapperEntry(sdbusplus::bus::bus &bus, const char *path,
                                 const std::string &groupName,
                                 const std::string &privilege,
                                 LDAPMapperMgr &parent) :
    Ifaces(bus, path),
    id(std::stol(std::experimental::filesystem::path(path).filename())),
    manager(parent)
{
    Ifaces::privilege(privilege);
    Ifaces::groupName(groupName);
    Ifaces::emit_object_added();
}

LDAPMapperEntry::LDAPMapperEntry(sdbusplus::bus::bus &bus, const char *path,
                                 LDAPMapperMgr &parent) :
    Ifaces(bus, path),
    id(std::stol(std::experimental::filesystem::path(path).filename())),
    manager(parent)
{
}

void LDAPMapperEntry::delete_(void)
{
    manager.deletePrivilegeMapper(id);
}

std::string LDAPMapperEntry::privilege(std::string value)
{
    if (value == Ifaces::privilege())
    {
        return value;
    }

    manager.checkPrivilegeLevel(value);
    auto val = Ifaces::privilege(value);
    serialize(*this, id);
    return val;
}

std::string LDAPMapperEntry::groupName(std::string value)
{
    if (value == Ifaces::groupName())
    {
        return value;
    }

    manager.checkPrivilegeMapper(value);
    return Ifaces::groupName(value);
}

} // namespace user
} // namespace phosphor
