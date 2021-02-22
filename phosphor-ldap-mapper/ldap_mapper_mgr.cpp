#include "config.h"

#include "ldap_mapper_mgr.hpp"

#include "ldap_mapper_serialize.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>

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

LDAPMapperMgr::LDAPMapperMgr(sdbusplus::bus::bus& bus, const char* path,
                             const char* filePath) :
    MapperMgrIface(bus, path),
    bus(bus), path(path), persistPath(filePath)
{}

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
        bus, mapperObject.c_str(), persistPath.c_str(), groupName, privilege,
        *this);

    serialize(*entry, entryId, persistPath);

    PrivilegeMapperList.emplace(entryId, std::move(entry));

    return mapperObject;
}

void LDAPMapperMgr::deletePrivilegeMapper(Id id)
{
    // Delete the persistent representation of the privilege mapper.
    std::filesystem::path mapperPath(persistPath);
    mapperPath /= std::to_string(id);
    std::filesystem::remove(mapperPath);

    PrivilegeMapperList.erase(id);
}

void LDAPMapperMgr::checkPrivilegeMapper(const std::string& groupName)
{
    if (groupName.empty())
    {
        log<level::ERR>("Group name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    for (const auto& val : PrivilegeMapperList)
    {
        if (val.second.get()->groupName() == groupName)
        {
            log<level::ERR>("Group name already exists");
            elog<PrivilegeMappingExists>();
        }
    }
}

void LDAPMapperMgr::checkPrivilegeLevel(const std::string& privilege)
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

void LDAPMapperMgr::restore()
{
    std::filesystem::path dir(persistPath);
    if (!std::filesystem::exists(dir) || std::filesystem::is_empty(dir))
    {
        return;
    }

    for (auto& file : std::filesystem::directory_iterator(dir))
    {
        std::string id = file.path().filename().c_str();
        size_t idNum = std::stol(id);
        auto entryPath = std::string(mapperMgrRoot) + '/' + id;
        auto entry = std::make_unique<phosphor::user::LDAPMapperEntry>(
            bus, entryPath.c_str(), persistPath.c_str(), *this);
        if (deserialize(file.path(), *entry))
        {
            entry->Ifaces::emit_object_added();
            PrivilegeMapperList.emplace(idNum, std::move(entry));
            if (idNum > entryId)
            {
                entryId = idNum;
            }
        }
    }
}

} // namespace user
} // namespace phosphor
