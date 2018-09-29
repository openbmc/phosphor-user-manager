#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "config.h"
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
using PrivilegeMappingExists = sdbusplus::xyz::openbmc_project::User::Common::
    Error::PrivilegeMappingExists;

LDAPMapperMgr::LDAPMapperMgr(sdbusplus::bus::bus &bus, const char *path) :
    MapperMgrIface(bus, path), bus(bus), path(path)
{
}

std::string LDAPMapperMgr::create(std::string groupName, std::string privilege)
{
    // The group name is element in the D-Bus object path. Each element in the
    // object path only contain the ASCII characters "[A-Z][a-z][0-9]_". If
    // there is space is the group name then it is deleted. So if the LDAP group
    // name is "Admin Group" the D-Bus object path will be
    // /xyz/openbmc_project/user/ldap/AdminGroup.
    groupName.erase(std::remove(groupName.begin(), groupName.end(), ' '),
                    groupName.end());

    checkPrivilegeMapper(groupName);
    checkPrivilegeLevel(privilege);

    // Object path for the LDAP group privilege mapper entry
    auto mapperObject = std::string(mapperMgrRoot) + "/" + groupName;

    // Create mapping for LDAP privilege mapper entry
    auto entry = std::make_unique<phosphor::user::LDAPMapperEntry>(
        bus, mapperObject.c_str(), privilege, *this);

    serialize(*entry, groupName);

    PrivilegeMapperList.emplace(groupName, std::move(entry));

    return mapperObject;
}

void LDAPMapperMgr::deletePrivilegeMapper(std::string groupName)
{
    // Delete the persistent representation of the privilege mapper.
    fs::path mapperPath(LDAP_MAPPER_PERSIST_PATH);
    mapperPath /= groupName;
    fs::remove(mapperPath);

    PrivilegeMapperList.erase(groupName);
}

void LDAPMapperMgr::checkPrivilegeMapper(const std::string &groupName)
{
    if (groupName.empty())
    {
        log<level::ERR>("Group name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    if (PrivilegeMapperList.find(groupName) != PrivilegeMapperList.end())
    {
        elog<PrivilegeMappingExists>();
    }

    for (const char &ch : groupName)
    {
        if (!std::isalpha(static_cast<unsigned char>(ch)) &&
            !std::isdigit(static_cast<unsigned char>(ch)) && ch != '_')
        {
            log<level::ERR>("Group name contains invalid characters");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group Name"),
                                  Argument::ARGUMENT_VALUE(groupName.c_str()));
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
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(privilege.c_str()));
    }
}

void LDAPMapperMgr::restore()
{
    namespace fs = std::experimental::filesystem;

    fs::path dir(LDAP_MAPPER_PERSIST_PATH);
    if (!fs::exists(dir) || fs::is_empty(dir))
    {
        return;
    }

    for (auto &file : fs::directory_iterator(dir))
    {
        std::string groupName = file.path().filename().c_str();
        auto entryPath = std::string(mapperMgrRoot) + '/' + groupName;
        auto entry = std::make_unique<phosphor::user::LDAPMapperEntry>(
            bus, entryPath.c_str(), *this);
        if (deserialize(file.path(), *entry))
        {
            entry->EntryIface::emit_object_added();
            PrivilegeMapperList.emplace(groupName, std::move(entry));
        }
    }
}

} // namespace user
} // namespace phosphor
