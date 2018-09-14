#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "config.h"
#include "ldap_mapper_mgr.hpp"

namespace phosphor
{
namespace user
{

using namespace phosphor::logging;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using PrivilegeMappingExists = sdbusplus::xyz::openbmc_project::User::Common::
    Error::PrivilegeMappingExists;

LDAPMapperMgr::LDAPMapperMgr(sdbusplus::bus::bus &bus, const char *path) :
    MapperMgrIface(bus, path), bus(bus), path(path)
{
}

ObjectPath LDAPMapperMgr::create(std::string groupName, std::string privilege)
{
    checkPrivilegeMapper(groupName);
    checkPrivilegeLevel(privilege);

    entryId++;

    // Object path for the LDAP group privilege mapper entry
    auto mapperObject =
        std::string(mapperMgrRoot) + "/" + std::to_string(entryId);

    // Create mapping for LDAP privilege mapper entry
    auto entry = std::make_unique<phosphor::user::LDAPMapperEntry>(
        bus, mapperObject.c_str(), groupName, privilege, *this);

    PrivilegeMapperList.emplace(entryId, std::move(entry));

    return mapperObject;
}

void LDAPMapperMgr::deletePrivilegeMapper(Id id)
{
    PrivilegeMapperList.erase(id);
}

void LDAPMapperMgr::checkPrivilegeMapper(const std::string &groupName)
{
    if (groupName.empty())
    {
        log<level::ERR>("Group name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    for (const auto &val : PrivilegeMapperList)
    {
        if (val.second.get()->groupName() == groupName)
        {
            log<level::ERR>("Group name already exists");
            elog<PrivilegeMappingExists>();
        }
    }
}

void LDAPMapperMgr::checkPrivilegeLevel(const std::string &privilege)
{
    if (privilege.empty())
    {
        log<level::ERR>("Privilege level is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege level"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    if (std::find(privMgr.begin(), privMgr.end(), privilege) == privMgr.end())
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege level"),
                              Argument::ARGUMENT_VALUE(privilege.c_str()));
    }
}

} // namespace user
} // namespace phosphor
