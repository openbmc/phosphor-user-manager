#include "ldap_config_mgr.hpp"
#include "ldap_config.hpp"
#include "ldap_config_serialize.hpp"
#include "ldap_mapper_serialize.hpp"
#include "utils.hpp"

#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>

namespace phosphor
{
namespace ldap
{

constexpr auto nslcdService = "nslcd.service";
constexpr auto nscdService = "nscd.service";
constexpr auto LDAPscheme = "ldap";
constexpr auto LDAPSscheme = "ldaps";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::filesystem;

using Argument = xyz::openbmc_project::Common::InvalidArgument;
using PrivilegeMappingExists = sdbusplus::xyz::openbmc_project::User::Common::
    Error::PrivilegeMappingExists;

using Line = std::string;
using Key = std::string;
using Val = std::string;
using ConfigInfo = std::map<Key, Val>;

Config::Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
               const char* caCertFile, bool secureLDAP,
               std::string lDAPServerURI, std::string lDAPBindDN,
               std::string lDAPBaseDN, std::string&& lDAPBindDNPassword,
               ConfigIface::SearchScope lDAPSearchScope,
               ConfigIface::Type lDAPType, bool lDAPServiceEnabled,
               std::string userNameAttr, std::string groupNameAttr,
               ConfigMgr& parent) :
    Ifaces(bus, path, true),
    secureLDAP(secureLDAP), lDAPBindPassword(std::move(lDAPBindDNPassword)),
    tlsCacertFile(caCertFile), configFilePath(filePath), objectPath(path),
    bus(bus), parent(parent)
{
    ConfigIface::lDAPServerURI(lDAPServerURI);
    ConfigIface::lDAPBindDN(lDAPBindDN);
    ConfigIface::lDAPBaseDN(lDAPBaseDN);
    ConfigIface::lDAPSearchScope(lDAPSearchScope);
    ConfigIface::lDAPType(lDAPType);
    EnableIface::enabled(lDAPServiceEnabled);
    ConfigIface::userNameAttribute(userNameAttr);
    ConfigIface::groupNameAttribute(groupNameAttr);
    // NOTE: Don't update the bindDN password under ConfigIface
    if (enabled())
    {
        writeConfig();
    }
    // save the config.
    configPersistPath = parent.dbusPersistentPath;
    configPersistPath += objectPath;

    // create the persistent directory
    fs::create_directories(configPersistPath);

    configPersistPath += "/config";

    std::ofstream os(configPersistPath, std::ios::binary | std::ios::out);
    // remove the read permission from others
    auto permission =
        fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read;
    fs::permissions(configPersistPath, permission);

    serialize(*this, configPersistPath);

    // Emit deferred signal.
    this->emit_object_added();
    parent.startOrStopService(nslcdService, enabled());
}

Config::Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
               ConfigIface::Type lDAPType, ConfigMgr& parent) :
    Ifaces(bus, path, true),
    configFilePath(filePath), objectPath(path), bus(bus), parent(parent)
{
    ConfigIface::lDAPType(lDAPType);

    configPersistPath = parent.dbusPersistentPath;
    configPersistPath += objectPath;

    // create the persistent directory
    fs::create_directories(configPersistPath);

    configPersistPath += "/config";

    std::ofstream os(configPersistPath, std::ios::binary | std::ios::out);
    // remove the read permission from others
    auto permission =
        fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read;
    fs::permissions(configPersistPath, permission);
}

void Config::writeConfig()
{
    std::stringstream confData;
    auto isPwdTobeWritten = false;
    std::string userNameAttr;

    confData << "uid root\n";
    confData << "gid root\n\n";
    confData << "ldap_version 3\n\n";
    confData << "timelimit 30\n";
    confData << "bind_timelimit 30\n";
    confData << "pagesize 1000\n";
    confData << "referrals off\n\n";
    confData << "uri " << lDAPServerURI() << "\n\n";
    confData << "base " << lDAPBaseDN() << "\n\n";
    confData << "binddn " << lDAPBindDN() << "\n";
    if (!lDAPBindPassword.empty())
    {
        confData << "bindpw " << lDAPBindPassword << "\n";
        isPwdTobeWritten = true;
    }
    confData << "\n";
    switch (lDAPSearchScope())
    {
        case ConfigIface::SearchScope::sub:
            confData << "scope sub\n\n";
            break;
        case ConfigIface::SearchScope::one:
            confData << "scope one\n\n";
            break;
        case ConfigIface::SearchScope::base:
            confData << "scope base\n\n";
            break;
    }
    confData << "base passwd " << lDAPBaseDN() << "\n";
    confData << "base shadow " << lDAPBaseDN() << "\n\n";
    if (secureLDAP == true)
    {
        confData << "ssl on\n";
        confData << "tls_reqcert hard\n";
        confData << "tls_cacertFile " << tlsCacertFile.c_str() << "\n";
    }
    else
    {
        confData << "ssl off\n";
    }
    confData << "\n";
    if (lDAPType() == ConfigIface::Type::ActiveDirectory)
    {
        if (ConfigIface::userNameAttribute().empty())
        {
            ConfigIface::userNameAttribute("sAMAccountName");
        }
        if (ConfigIface::groupNameAttribute().empty())
        {
            ConfigIface::groupNameAttribute("primaryGroupID");
        }
        confData << "filter passwd (&(objectClass=user)(objectClass=person)"
                    "(!(objectClass=computer)))\n";
        confData
            << "filter group (|(objectclass=group)(objectclass=groupofnames) "
               "(objectclass=groupofuniquenames))\n";
        confData << "map passwd uid              "
                 << ConfigIface::userNameAttribute() << "\n";
        confData << "map passwd uidNumber        "
                    "objectSid:S-1-5-21-3623811015-3361044348-30300820\n";
        confData << "map passwd gidNumber        "
                 << ConfigIface::groupNameAttribute() << "\n";
        confData << "map passwd homeDirectory    \"/home/$sAMAccountName\"\n";
        confData << "map passwd gecos            displayName\n";
        confData << "map passwd loginShell       \"/bin/bash\"\n";
        confData << "map group gidNumber         "
                    "objectSid:S-1-5-21-3623811015-3361044348-30300820\n";
        confData << "map group cn                "
                 << ConfigIface::userNameAttribute() << "\n";
    }
    else if (lDAPType() == ConfigIface::Type::OpenLdap)
    {
        if (ConfigIface::userNameAttribute().empty())
        {
            ConfigIface::userNameAttribute("cn");
        }
        if (ConfigIface::groupNameAttribute().empty())
        {
            ConfigIface::groupNameAttribute("gidNumber");
        }
        confData << "filter passwd (objectclass=*)\n";
        confData << "map passwd gecos displayName\n";
        confData << "filter group (objectclass=posixGroup)\n";
        confData << "map passwd uid              "
                 << ConfigIface::userNameAttribute() << "\n";
        confData << "map passwd gidNumber        "
                 << ConfigIface::groupNameAttribute() << "\n";
    }
    try
    {
        std::fstream stream(configFilePath.c_str(), std::fstream::out);
        // remove the read permission from others if password is being written.
        // nslcd forces this behaviour.
        auto permission = fs::perms::owner_read | fs::perms::owner_write |
                          fs::perms::group_read;
        if (isPwdTobeWritten)
        {
            fs::permissions(configFilePath, permission);
        }
        else
        {
            fs::permissions(configFilePath,
                            permission | fs::perms::others_read);
        }

        stream << confData.str();
        stream.flush();
        stream.close();
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return;
}

std::string Config::lDAPBindDNPassword(std::string value)
{
    // Don't update the D-bus object, this is just to
    // facilitate if user wants to change the bind dn password
    // once d-bus object gets created.
    lDAPBindPassword = value;
    try
    {
        if (enabled())
        {
            writeConfig();
        }
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return value;
}

std::string Config::lDAPServerURI(std::string value)
{
    std::string val;
    try
    {
        if (value == lDAPServerURI())
        {
            return value;
        }
        if (isValidLDAPURI(value, LDAPSscheme))
        {
            secureLDAP = true;
        }
        else if (isValidLDAPURI(value, LDAPscheme))
        {
            secureLDAP = false;
        }
        else
        {
            log<level::ERR>("bad LDAP Server URI",
                            entry("LDAPSERVERURI=%s", value.c_str()));
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPServerURI"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        if (secureLDAP && !fs::exists(tlsCacertFile.c_str()))
        {
            log<level::ERR>("LDAP server's CA certificate not provided",
                            entry("TLSCACERTFILE=%s", tlsCacertFile.c_str()));
            elog<NoCACertificate>();
        }
        val = ConfigIface::lDAPServerURI(value);
        if (enabled())
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const InvalidArgument& e)
    {
        throw;
    }
    catch (const NoCACertificate& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return val;
}

std::string Config::lDAPBindDN(std::string value)
{
    std::string val;
    try
    {
        if (value == lDAPBindDN())
        {
            return value;
        }

        if (value.empty())
        {
            log<level::ERR>("Not a valid LDAP BINDDN",
                            entry("LDAPBINDDN=%s", value.c_str()));
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPBindDN"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        val = ConfigIface::lDAPBindDN(value);
        if (enabled())
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const InvalidArgument& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return val;
}

std::string Config::lDAPBaseDN(std::string value)
{
    std::string val;
    try
    {
        if (value == lDAPBaseDN())
        {
            return value;
        }

        if (value.empty())
        {
            log<level::ERR>("Not a valid LDAP BASEDN",
                            entry("BASEDN=%s", value.c_str()));
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPBaseDN"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        val = ConfigIface::lDAPBaseDN(value);
        if (enabled())
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const InvalidArgument& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return val;
}

ConfigIface::SearchScope Config::lDAPSearchScope(ConfigIface::SearchScope value)
{
    ConfigIface::SearchScope val;
    try
    {
        if (value == lDAPSearchScope())
        {
            return value;
        }

        val = ConfigIface::lDAPSearchScope(value);
        if (enabled())
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return val;
}

ConfigIface::Type Config::lDAPType(ConfigIface::Type value)
{
    // Type is readonly it should not be allowed to change
    // we have to send the NotAllowed but we need to make
    // the change in the dbus-interfaces, so sending Internal
    // Failure now.
    elog<InternalFailure>();
    return lDAPType();
}

bool Config::enabled(bool value)
{
    if (value == enabled())
    {
        return value;
    }
    // Let parent decide that can we enable this config.
    // It may happen that other config is already enabled,
    // Current implementation support only one config can
    // be active at a time.
    return parent.enableService(*this, value);
}

bool Config::toggleService(bool value)
{
    bool isEnable = false;
    try
    {
        isEnable = EnableIface::enabled(value);
        if (isEnable)
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, value);
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return isEnable;
}

std::string Config::userNameAttribute(std::string value)
{
    std::string val;
    try
    {
        if (value == userNameAttribute())
        {
            return value;
        }

        val = ConfigIface::userNameAttribute(value);
        if (enabled())
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return val;
}

std::string Config::groupNameAttribute(std::string value)
{
    std::string val;
    try
    {
        if (value == groupNameAttribute())
        {
            return value;
        }

        val = ConfigIface::groupNameAttribute(value);
        if (enabled())
        {
            writeConfig();
        }
        // save the enabled property.
        serialize(*this, configPersistPath);
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return val;
}

ObjectPath Config::create(std::string groupName, std::string privilege)
{
    checkPrivilegeMapper(groupName);
    checkPrivilegeLevel(privilege);

    entryId++;

    // Object path for the LDAP group privilege mapper entry
    fs::path mapperObjectPath = objectPath;
    mapperObjectPath /= "role_map";
    mapperObjectPath /= std::to_string(entryId);

    fs::path persistPath = parent.dbusPersistentPath;
    persistPath += mapperObjectPath;

    // Create mapping for LDAP privilege mapper entry
    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, mapperObjectPath.string().c_str(), persistPath.string().c_str(),
        groupName, privilege, *this);

    serialize(*entry, std::move(persistPath));

    PrivilegeMapperList.emplace(entryId, std::move(entry));
    return mapperObjectPath.string();
}

void Config::deletePrivilegeMapper(Id id)
{
    fs::path mapperObjectPath = objectPath;
    mapperObjectPath /= "role_map";
    mapperObjectPath /= std::to_string(id);

    fs::path persistPath = parent.dbusPersistentPath;
    persistPath += std::move(mapperObjectPath);

    // Delete the persistent representation of the privilege mapper.
    fs::remove(std::move(persistPath));

    PrivilegeMapperList.erase(id);
}
void Config::checkPrivilegeMapper(const std::string& groupName)
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

void Config::checkPrivilegeLevel(const std::string& privilege)
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

void Config::restore()
{
    namespace fs = std::filesystem;
    fs::path dir = parent.dbusPersistentPath;
    dir += objectPath;
    dir /= "role_map";

    if (!fs::exists(dir) || fs::is_empty(dir))
    {
        return;
    }

    for (auto& file : fs::directory_iterator(dir))
    {
        std::string id = file.path().filename().c_str();
        size_t idNum = std::stol(id);

        auto entryPath = objectPath + '/' + "role_map" + '/' + id;
        auto persistPath = parent.dbusPersistentPath + entryPath;
        auto entry = std::make_unique<LDAPMapperEntry>(
            bus, entryPath.c_str(), persistPath.c_str(), *this);
        if (deserialize(file.path(), *entry))
        {
            entry->Interfaces::emit_object_added();
            PrivilegeMapperList.emplace(idNum, std::move(entry));
            if (idNum > entryId)
            {
                entryId = idNum;
            }
        }
    }
}

} // namespace ldap
} // namespace phosphor
