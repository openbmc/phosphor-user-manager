#include "ldap_config.hpp"

#include "ldap_config_mgr.hpp"
#include "ldap_mapper_serialize.hpp"
#include "utils.hpp"

#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>

// Register class version
// From cereal documentation;
// "This macro should be placed at global scope"
CEREAL_CLASS_VERSION(phosphor::ldap::Config, CLASS_VERSION);

namespace phosphor
{
namespace ldap
{

constexpr auto nslcdService = "nslcd.service";
constexpr auto ldapScheme = "ldap";
constexpr auto ldapsScheme = "ldaps";
constexpr auto certObjPath = "/xyz/openbmc_project/certs/client/ldap/1";
constexpr auto certRootPath = "/xyz/openbmc_project/certs/client/ldap";
constexpr auto authObjPath = "/xyz/openbmc_project/certs/authority/ldap";
constexpr auto certIface = "xyz.openbmc_project.Certs.Certificate";
constexpr auto certProperty = "CertificateString";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::filesystem;

using Argument = xyz::openbmc_project::Common::InvalidArgument;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;
using PrivilegeMappingExists = sdbusplus::xyz::openbmc_project::User::Common::
    Error::PrivilegeMappingExists;

using Line = std::string;
using Key = std::string;
using Val = std::string;
using ConfigInfo = std::map<Key, Val>;

Config::Config(sdbusplus::bus_t& bus, const char* path, const char* filePath,
               const char* caCertFile, const char* certFile, bool secureLDAP,
               std::string ldapServerURI, std::string ldapBindDN,
               std::string ldapBaseDN, std::string&& ldapBindDNPassword,
               ConfigIface::SearchScope ldapSearchScope,
               ConfigIface::Type ldapType, bool ldapServiceEnabled,
               std::string userNameAttr, std::string groupNameAttr,
               ConfigMgr& parent) :
    Ifaces(bus, path, Ifaces::action::defer_emit),
    secureLDAP(secureLDAP), ldapBindPassword(std::move(ldapBindDNPassword)),
    tlsCacertFile(caCertFile), tlsCertFile(certFile), configFilePath(filePath),
    objectPath(path), bus(bus), parent(parent),
    certificateInstalledSignal(
        bus, sdbusplus::bus::match::rules::interfacesAdded(certRootPath),
        std::bind(std::mem_fn(&Config::certificateInstalled), this,
                  std::placeholders::_1)),

    cacertificateInstalledSignal(
        bus, sdbusplus::bus::match::rules::interfacesAdded(authObjPath),
        std::bind(std::mem_fn(&Config::certificateInstalled), this,
                  std::placeholders::_1)),

    certificateChangedSignal(
        bus,
        sdbusplus::bus::match::rules::propertiesChanged(certObjPath, certIface),
        std::bind(std::mem_fn(&Config::certificateChanged), this,
                  std::placeholders::_1))
{
    ConfigIface::ldapServerURI(ldapServerURI);
    ConfigIface::ldapBindDN(ldapBindDN);
    ConfigIface::ldapBaseDN(ldapBaseDN);
    ConfigIface::ldapSearchScope(ldapSearchScope);
    ConfigIface::ldapType(ldapType);
    EnableIface::enabled(ldapServiceEnabled);
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

    serialize();

    // Emit deferred signal.
    this->emit_object_added();
    parent.startOrStopService(nslcdService, enabled());
}

Config::Config(sdbusplus::bus_t& bus, const char* path, const char* filePath,
               const char* caCertFile, const char* certFile,
               ConfigIface::Type ldapType, ConfigMgr& parent) :
    Ifaces(bus, path, Ifaces::action::defer_emit),
    secureLDAP(false), tlsCacertFile(caCertFile), tlsCertFile(certFile),
    configFilePath(filePath), objectPath(path), bus(bus), parent(parent),
    certificateInstalledSignal(
        bus, sdbusplus::bus::match::rules::interfacesAdded(certRootPath),
        std::bind(std::mem_fn(&Config::certificateInstalled), this,
                  std::placeholders::_1)),
    cacertificateInstalledSignal(
        bus, sdbusplus::bus::match::rules::interfacesAdded(authObjPath),
        std::bind(std::mem_fn(&Config::certificateInstalled), this,
                  std::placeholders::_1)),
    certificateChangedSignal(
        bus,
        sdbusplus::bus::match::rules::propertiesChanged(certObjPath, certIface),
        std::bind(std::mem_fn(&Config::certificateChanged), this,
                  std::placeholders::_1))
{
    ConfigIface::ldapType(ldapType);

    configPersistPath = parent.dbusPersistentPath;
    configPersistPath += objectPath;

    // create the persistent directory
    fs::create_directories(configPersistPath);

    configPersistPath += "/config";
}

void Config::certificateInstalled(sdbusplus::message_t& /*msg*/)
{
    try
    {
        if (enabled())
        {
            writeConfig();
        }
        parent.startOrStopService(nslcdService, enabled());
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
}

void Config::certificateChanged(sdbusplus::message_t& msg)
{
    std::string objectName;
    std::map<std::string, std::variant<std::string>> msgData;
    msg.read(objectName, msgData);
    auto valPropMap = msgData.find(certProperty);
    {
        if (valPropMap != msgData.end())
        {
            try
            {
                if (enabled())
                {
                    writeConfig();
                }
                parent.startOrStopService(nslcdService, enabled());
            }
            catch (const InternalFailure& e)
            {
                throw;
            }
            catch (const std::exception& e)
            {
                lg2::error("Exception: {ERR}", "ERR", e);
                elog<InternalFailure>();
            }
        }
    }
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
    confData << "uri " << ldapServerURI() << "\n\n";
    confData << "base " << ldapBaseDN() << "\n\n";
    confData << "binddn " << ldapBindDN() << "\n";
    if (!ldapBindPassword.empty())
    {
        confData << "bindpw " << ldapBindPassword << "\n";
        isPwdTobeWritten = true;
    }
    confData << "\n";
    switch (ldapSearchScope())
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
    confData << "base passwd " << ldapBaseDN() << "\n";
    confData << "base shadow " << ldapBaseDN() << "\n\n";
    if (secureLDAP == true)
    {
        confData << "ssl on\n";
        confData << "tls_reqcert hard\n";
        if (fs::is_directory(tlsCacertFile.c_str()))
        {
            confData << "tls_cacertdir " << tlsCacertFile.c_str() << "\n";
        }
        else
        {
            confData << "tls_cacertfile " << tlsCacertFile.c_str() << "\n";
        }
        if (fs::exists(tlsCertFile.c_str()))
        {
            confData << "tls_cert " << tlsCertFile.c_str() << "\n";
            confData << "tls_key " << tlsCertFile.c_str() << "\n";
        }
    }
    else
    {
        confData << "ssl off\n";
    }
    confData << "\n";
    if (ldapType() == ConfigIface::Type::ActiveDirectory)
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
        confData << "map passwd loginShell       \"/bin/sh\"\n";
        confData << "map group gidNumber         "
                    "objectSid:S-1-5-21-3623811015-3361044348-30300820\n";
        confData << "map group cn                "
                 << ConfigIface::userNameAttribute() << "\n";
        confData << "nss_initgroups_ignoreusers ALLLOCAL\n";
    }
    else if (ldapType() == ConfigIface::Type::OpenLdap)
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
        confData << "map passwd loginShell       \"/bin/sh\"\n";
        confData << "nss_initgroups_ignoreusers ALLLOCAL\n";
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
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return;
}

std::string Config::ldapBindDNPassword(std::string value)
{
    // Don't update the D-bus object, this is just to
    // facilitate if user wants to change the bind dn password
    // once d-bus object gets created.
    ldapBindPassword = value;
    try
    {
        if (enabled())
        {
            writeConfig();
            parent.startOrStopService(nslcdService, enabled());
        }
        serialize();
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return value;
}

std::string Config::ldapServerURI(std::string value)
{
    std::string val;
    try
    {
        if (value == ldapServerURI())
        {
            return value;
        }
        if (isValidLDAPURI(value, ldapsScheme))
        {
            secureLDAP = true;
        }
        else if (isValidLDAPURI(value, ldapScheme))
        {
            secureLDAP = false;
        }
        else
        {
            lg2::error("Bad LDAP Server URI {URI}", "URI", value);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("ldapServerURI"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        if (secureLDAP && !fs::exists(tlsCacertFile.c_str()))
        {
            lg2::error("LDAP server CA certificate not found at {PATH}", "PATH",
                       tlsCacertFile);
            elog<NoCACertificate>();
        }
        val = ConfigIface::ldapServerURI(value);
        if (enabled())
        {
            writeConfig();
            parent.startOrStopService(nslcdService, enabled());
        }
        // save the object.
        serialize();
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
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return val;
}

std::string Config::ldapBindDN(std::string value)
{
    std::string val;
    try
    {
        if (value == ldapBindDN())
        {
            return value;
        }

        if (value.empty())
        {
            lg2::error("'{BINDDN}' is not a valid LDAP BindDN", "BINDDN",
                       value);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("ldapBindDN"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        val = ConfigIface::ldapBindDN(value);
        if (enabled())
        {
            writeConfig();
            parent.startOrStopService(nslcdService, enabled());
        }
        // save the object.
        serialize();
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
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return val;
}

std::string Config::ldapBaseDN(std::string value)
{
    std::string val;
    try
    {
        if (value == ldapBaseDN())
        {
            return value;
        }

        if (value.empty())
        {
            lg2::error("'{BASEDN}' is not a valid LDAP BaseDN", "BASEDN",
                       value);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("ldapBaseDN"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        val = ConfigIface::ldapBaseDN(value);
        if (enabled())
        {
            writeConfig();
            parent.startOrStopService(nslcdService, enabled());
        }
        // save the object.
        serialize();
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
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return val;
}

ConfigIface::SearchScope Config::ldapSearchScope(ConfigIface::SearchScope value)
{
    ConfigIface::SearchScope val;
    try
    {
        if (value == ldapSearchScope())
        {
            return value;
        }

        val = ConfigIface::ldapSearchScope(value);
        if (enabled())
        {
            writeConfig();

            parent.startOrStopService(nslcdService, enabled());
        }
        // save the object.
        serialize();
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return val;
}

ConfigIface::Type Config::ldapType(ConfigIface::Type /*value*/)
{
    elog<NotAllowed>(NotAllowedArgument::REASON("ReadOnly Property"));
    return ldapType();
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

bool Config::enableService(bool value)
{
    bool isEnable = false;
    try
    {
        isEnable = EnableIface::enabled(value);
        if (isEnable)
        {
            writeConfig();
        }
        parent.startOrStopService(nslcdService, value);
        serialize();
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
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

            parent.startOrStopService(nslcdService, enabled());
        }
        // save the object.
        serialize();
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
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

            parent.startOrStopService(nslcdService, enabled());
        }
        // save the object.
        serialize();
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }
    return val;
}

template <class Archive>
void Config::save(Archive& archive, const std::uint32_t /*version*/) const
{
    archive(this->enabled());
    archive(ldapServerURI());
    archive(ldapBindDN());
    archive(ldapBaseDN());
    archive(ldapSearchScope());
    archive(ldapBindPassword);
    archive(userNameAttribute());
    archive(groupNameAttribute());
}

template <class Archive>
void Config::load(Archive& archive, const std::uint32_t /*version*/)
{
    bool bVal;
    archive(bVal);
    EnableIface::enabled(bVal);

    std::string str;
    archive(str);
    ConfigIface::ldapServerURI(str);

    archive(str);
    ConfigIface::ldapBindDN(str);

    archive(str);
    ConfigIface::ldapBaseDN(str);

    ConfigIface::SearchScope scope;
    archive(scope);
    ConfigIface::ldapSearchScope(scope);

    archive(str);
    ldapBindPassword = str;

    archive(str);
    ConfigIface::userNameAttribute(str);

    archive(str);
    ConfigIface::groupNameAttribute(str);
}

void Config::serialize()
{

    if (!fs::exists(configPersistPath.c_str()))
    {
        std::ofstream os(configPersistPath.string(),
                         std::ios::binary | std::ios::out);
        auto permission = fs::perms::owner_read | fs::perms::owner_write |
                          fs::perms::group_read;
        fs::permissions(configPersistPath, permission);
        cereal::BinaryOutputArchive oarchive(os);
        oarchive(*this);
    }
    else
    {
        std::ofstream os(configPersistPath.string(),
                         std::ios::binary | std::ios::out);
        cereal::BinaryOutputArchive oarchive(os);
        oarchive(*this);
    }
    return;
}

bool Config::deserialize()
{
    try
    {
        if (fs::exists(configPersistPath))
        {
            std::ifstream is(configPersistPath.c_str(),
                             std::ios::in | std::ios::binary);
            cereal::BinaryInputArchive iarchive(is);
            iarchive(*this);

            if (isValidLDAPURI(ldapServerURI(), ldapScheme))
            {
                secureLDAP = false;
            }
            else if (isValidLDAPURI(ldapServerURI(), ldapsScheme))
            {
                secureLDAP = true;
            }
            return true;
        }
        return false;
    }
    catch (const cereal::Exception& e)
    {
        lg2::error("Exception: {ERR}", "ERR", e);
        std::error_code ec;
        fs::remove(configPersistPath, ec);
        return false;
    }
    catch (const fs::filesystem_error& e)
    {
        return false;
    }
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

    phosphor::ldap::serialize(*entry, std::move(persistPath));

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
        lg2::error("Group name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    for (const auto& val : PrivilegeMapperList)
    {
        if (val.second.get()->groupName() == groupName)
        {
            lg2::error("Group name '{GROUPNAME}' already exists", "GROUPNAME",
                       groupName);
            elog<PrivilegeMappingExists>();
        }
    }
}

void Config::checkPrivilegeLevel(const std::string& privilege)
{
    if (privilege.empty())
    {
        lg2::error("Privilege level is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege level"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    if (std::find(privMgr.begin(), privMgr.end(), privilege) == privMgr.end())
    {
        lg2::error("Invalid privilege '{PRIVILEGE}'", "PRIVILEGE", privilege);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(privilege.c_str()));
    }
}

void Config::restoreRoleMapping()
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
        if (phosphor::ldap::deserialize(file.path(), *entry))
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
