#include "config.h"

#include "ldap_mapper_entry.hpp"

#include "ldap_config.hpp"
#include "ldap_mapper_serialize.hpp"

#include <filesystem>

namespace phosphor
{
namespace ldap
{

LDAPMapperEntry::LDAPMapperEntry(sdbusplus::bus::bus& bus, const char* path,
                                 const char* filePath,
                                 const std::string& groupName,
                                 const std::string& privilege, Config& parent) :
    Interfaces(bus, path, Interfaces::action::defer_emit),
    id(std::stol(std::filesystem::path(path).filename())), manager(parent),
    persistPath(filePath)
{
    Interfaces::privilege(privilege, true);
    Interfaces::groupName(groupName, true);
    Interfaces::emit_object_added();
}

LDAPMapperEntry::LDAPMapperEntry(sdbusplus::bus::bus& bus, const char* path,
                                 const char* filePath, Config& parent) :
    Interfaces(bus, path, Interfaces::action::defer_emit),
    id(std::stol(std::filesystem::path(path).filename())), manager(parent),
    persistPath(filePath)
{}

void LDAPMapperEntry::delete_(void)
{
    manager.deletePrivilegeMapper(id);
}

std::string LDAPMapperEntry::groupName(std::string value)
{
    if (value == Interfaces::groupName())
    {
        return value;
    }

    manager.checkPrivilegeMapper(value);
    auto val = Interfaces::groupName(value);
    serialize(*this, persistPath);
    return val;
}

std::string LDAPMapperEntry::privilege(std::string value)
{
    if (value == Interfaces::privilege())
    {
        return value;
    }

    manager.checkPrivilegeLevel(value);
    auto val = Interfaces::privilege(value);
    serialize(*this, persistPath);
    return val;
}

} // namespace ldap
} // namespace phosphor
