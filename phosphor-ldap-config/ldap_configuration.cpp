#include "ldap_configuration.hpp"
#include <ldap.h>
#include <experimental/filesystem>
#include <fstream>
#include <sstream>

namespace phosphor
{
namespace ldap
{
constexpr auto nslcdService = "nslcd.service";
constexpr auto nscdService = "nscd.service";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

using Line = std::string;
using Key = std::string;
using Val = std::string;
using ConfigInfo = std::map<Key, Val>;

Config::Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
               bool secureLDAP, std::string lDAPServerURI,
               std::string lDAPBindDN, std::string lDAPBaseDN,
               std::string lDAPBindDNpassword,
               ldap_base::Config::SearchScope lDAPSearchScope,
               ldap_base::Config::Type lDAPType, ConfigMgr& parent) :
    ConfigIface(bus, path, true),
    configFilePath(filePath), bus(bus), parent(parent)
{
    ConfigIface::secureLDAP(secureLDAP);
    ConfigIface::lDAPServerURI(lDAPServerURI);
    ConfigIface::lDAPBindDN(lDAPBindDN);
    ConfigIface::lDAPBaseDN(lDAPBaseDN);
    ConfigIface::lDAPBINDDNpassword(lDAPBindDNpassword);
    ConfigIface::lDAPSearchScope(lDAPSearchScope);
    ConfigIface::lDAPType(lDAPType);
    writeConfig();
    parent.restartService(nslcdService);
    // Emit deferred signal.
    this->emit_object_added();
}

void Config::delete_()
{
    parent.deleteObject();
    try
    {
        fs::copy_file(defaultNslcdFile, LDAP_CONFIG_FILE,
                      fs::copy_options::overwrite_existing);
        fs::copy_file(nsSwitchFile, LDAPNsSwitchFile,
                      fs::copy_options::overwrite_existing);
        fs::copy_file(linuxNsSwitchFile, nsSwitchFile,
                      fs::copy_options::overwrite_existing);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to rename Config Files while deleting Object",
                        entry("ERR=%s", e.what()));
        elog<InternalFailure>();
    }

    parent.restartService(nscdService);
    parent.stopService(nslcdService);
}

void Config::writeConfig()
{
    std::stringstream confData;
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
    if (!lDAPBINDDNpassword().empty())
    {
        confData << "bindpw " << lDAPBINDDNpassword() << "\n";
    }
    confData << "\n";
    switch (lDAPSearchScope())
    {
        case ldap_base::Config::SearchScope::sub:
            confData << "scope sub\n\n";
            break;
        case ldap_base::Config::SearchScope::one:
            confData << "scope one\n\n";
            break;
        case ldap_base::Config::SearchScope::base:
            confData << "scope base\n\n";
            break;
    }
    confData << "base passwd " << lDAPBaseDN() << "\n";
    confData << "base shadow " << lDAPBaseDN() << "\n\n";
    if (secureLDAP() == true)
    {
        confData << "ssl on\n";
        confData << "tls_reqcert allow\n";
        confData << "tls_cert /etc/nslcd/certs/cert.pem\n";
    }
    else
    {
        confData << "ssl off\n";
    }
    confData << "\n";
    if (lDAPType() == ldap_base::Config::Type::ActiveDirectory)
    {
        confData << "filter passwd (&(objectClass=user)(objectClass=person)"
                    "(!(objectClass=computer)))\n";
        confData
            << "filter group (|(objectclass=group)(objectclass=groupofnames) "
               "(objectclass=groupofuniquenames))\n";
        confData << "map passwd uid              sAMAccountName\n";
        confData << "map passwd uidNumber        "
                    "objectSid:S-1-5-21-3623811015-3361044348-30300820\n";
        confData << "map passwd gidNumber        primaryGroupID\n";
        confData << "map passwd homeDirectory    \"/home/$sAMAccountName\"\n";
        confData << "map passwd gecos            displayName\n";
        confData << "map passwd loginShell       \"/bin/bash\"\n";
        confData << "map group gidNumber         primaryGroupID\n";
        confData << "map group gidNumber         "
                    "objectSid:S-1-5-21-3623811015-3361044348-30300820\n";
        confData << "map group cn                sAMAccountName\n";
    }
    else if (lDAPType() == ldap_base::Config::Type::OpenLdap)
    {
        confData << "filter passwd (objectclass=*)\n";
        confData << "map passwd uid cn\n";
        confData << "map passwd gecos displayName\n";
    }
    try
    {
        std::fstream stream(configFilePath.c_str(), std::fstream::out);
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

bool Config::secureLDAP(bool value)
{
    bool val = false;
    try
    {
        if (value == secureLDAP())
        {
            return value;
        }

        val = ConfigIface::secureLDAP(value);
        writeConfig();
        parent.restartService(nslcdService);
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

std::string Config::lDAPServerURI(std::string value)
{
    std::string val;
    try
    {
        if (value == lDAPServerURI())
        {
            return value;
        }
        if (!(ldap_is_ldap_url(value.c_str()) ||
              ldap_is_ldaps_url(value.c_str())))
        {
            log<level::ERR>("Not a valid LDAP Server URI"),
                entry("LDAPSERVERURI=%s", value.c_str());
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPServerURI"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }
        val = ConfigIface::lDAPServerURI(value);
        writeConfig();
        parent.restartService(nslcdService);
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
            log<level::ERR>("Not a valid LDAP BINDDN"),
                entry("LDAPBINDDN=%s", value.c_str());
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPBindDN"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        val = ConfigIface::lDAPBindDN(value);
        writeConfig();
        parent.restartService(nslcdService);
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
            log<level::ERR>("Not a valid LDAP BASEDN"),
                entry("BASEDN=%s", value.c_str());
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPBaseDN"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        val = ConfigIface::lDAPBaseDN(value);
        writeConfig();
        parent.restartService(nslcdService);
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

std::string Config::lDAPBINDDNpassword(std::string value)
{
    std::string val;
    try
    {
        if (value == lDAPBINDDNpassword())
        {
            return value;
        }

        val = ConfigIface::lDAPBINDDNpassword(value);
        writeConfig();
        parent.restartService(nslcdService);
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

ldap_base::Config::SearchScope
    Config::lDAPSearchScope(ldap_base::Config::SearchScope value)
{
    ldap_base::Config::SearchScope val;
    try
    {
        if (value == lDAPSearchScope())
        {
            return value;
        }

        val = ConfigIface::lDAPSearchScope(value);
        writeConfig();
        parent.restartService(nslcdService);
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

ldap_base::Config::Type Config::lDAPType(ldap_base::Config::Type value)
{
    ldap_base::Config::Type val;
    try
    {
        if (value == lDAPType())
        {
            return value;
        }

        val = ConfigIface::lDAPType(value);
        writeConfig();
        parent.restartService(nslcdService);
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

void ConfigMgr::restartService(const std::string& service)
{
    try
    {
        auto method = bus.new_method_call(SYSTEMD_BUSNAME, SYSTEMD_PATH,
                                          SYSTEMD_INTERFACE, "RestartUnit");
        method.append(service.c_str(), "replace");
        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        log<level::ERR>("Failed to restart nslcd service",
                        entry("ERR=%s", ex.what()));
        elog<InternalFailure>();
    }
}

void ConfigMgr::stopService(const std::string& service)
{
    try
    {
        auto method = bus.new_method_call(SYSTEMD_BUSNAME, SYSTEMD_PATH,
                                          SYSTEMD_INTERFACE, "StopUnit");
        method.append(service.c_str(), "replace");
        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        log<level::ERR>("Failed to stop nslcd service",
                        entry("ERR=%s", ex.what()));
        elog<InternalFailure>();
    }
}

void ConfigMgr::deleteObject()
{
    configPtr.reset(nullptr);
}

std::string
    ConfigMgr::createConfig(bool secureLDAP, std::string lDAPServerURI,
                            std::string lDAPBindDN, std::string lDAPBaseDN,
                            std::string lDAPBINDDNpassword,
                            ldap_base::Create::SearchScope lDAPSearchScope,
                            ldap_base::Create::Type lDAPType)
{
    if (!(ldap_is_ldap_url(lDAPServerURI.c_str()) ||
          ldap_is_ldaps_url(lDAPServerURI.c_str())))
    {
        log<level::ERR>("Not a valid LDAP Server URI"),
            entry("LDAPSERVERURI=%s", lDAPServerURI.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPServerURI"),
                              Argument::ARGUMENT_VALUE(lDAPServerURI.c_str()));
    }

    if (lDAPBindDN.empty())
    {
        log<level::ERR>("Not a valid LDAP BINDDN"),
            entry("LDAPBINDDN=%s", lDAPBindDN.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("LDAPBindDN"),
                              Argument::ARGUMENT_VALUE(lDAPBindDN.c_str()));
    }

    if (lDAPBaseDN.empty())
    {
        log<level::ERR>("Not a valid LDAP BASEDN"),
            entry("LDAPBASEDN=%s", lDAPBaseDN.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("LDAPBaseDN"),
                              Argument::ARGUMENT_VALUE(lDAPBaseDN.c_str()));
    }

    // With current implementation we support only one LDAP server.
    deleteObject();
    try
    {
        fs::copy_file(nsSwitchFile, linuxNsSwitchFile,
                      fs::copy_options::overwrite_existing);
        fs::copy_file(LDAPNsSwitchFile, nsSwitchFile,
                      fs::copy_options::overwrite_existing);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to rename Config Files while creating Object",
                        entry("ERR=%s", e.what()));
        elog<InternalFailure>();
    }

    auto objPath = std::string(LDAP_CONFIG_DBUS_OBJ_PATH);
    configPtr = std::make_unique<Config>(
        bus, objPath.c_str(), LDAP_CONFIG_FILE, secureLDAP, lDAPServerURI,
        lDAPBindDN, lDAPBaseDN, lDAPBINDDNpassword,
        static_cast<ldap_base::Config::SearchScope>(lDAPSearchScope),
        static_cast<ldap_base::Config::Type>(lDAPType), *this);

    restartService(nslcdService);
    restartService(nscdService);
    return objPath;
}

void ConfigMgr::restore(const char* filePath)
{
    if (!fs::exists(filePath))
    {
        log<level::ERR>("Config file doesn't exists",
                        entry("LDAP_CONFIG_FILE=%s", LDAP_CONFIG_FILE));
        return;
    }

    ConfigInfo configValues;

    try
    {
        std::fstream stream(filePath, std::fstream::in);
        Line line;
        // read characters from stream and places them into line
        while (std::getline(stream, line))
        {
            // remove leading and trailing extra spaces
            auto firstScan = line.find_first_not_of(' ');
            auto first =
                (firstScan == std::string::npos ? line.length() : firstScan);
            auto last = line.find_last_not_of(' ');
            line = line.substr(first, last - first + 1);
            // reduce multiple spaces between two words to a single space
            auto pred = [](char a, char b) {
                return (a == b && a == ' ') ? true : false;
            };

            auto lastPos = std::unique(line.begin(), line.end(), pred);

            line.erase(lastPos, line.end());

            // Ignore if line is empty or starts with '#'
            if (line.empty() || line.at(0) == '#')
            {
                continue;
            }

            Key key;
            std::istringstream isLine(line);
            // extract characters from isLine and stores them into
            // key until the delimitation character ' ' is found.
            // If the delimiter is found, it is extracted and discarded
            // the next input operation will begin after it.
            if (std::getline(isLine, key, ' '))
            {
                Val value;
                // extract characters after delimitation character ' '
                if (std::getline(isLine, value, ' '))
                {
                    // skip line if it starts with "base shadow" or
                    // "base passwd" because we would have 3 entries
                    // ("base lDAPBaseDN" , "base passwd lDAPBaseDN" and
                    // "base shadow lDAPBaseDN") for the property "lDAPBaseDN",
                    // one is enough to restore it.

                    if ((key == "base") &&
                        (value == "passwd" || value == "shadow"))
                    {
                        continue;
                    }
                    // skip the line if it starts with "map passwd".
                    // if config type is AD "map group" entry would be add to
                    // the map configValues. For OpenLdap config file no map
                    // entry would be there.
                    if ((key == "map") && (value == "passwd"))
                    {
                        continue;
                    }
                    configValues[key] = value;
                }
            }
        }

        // extract properties from configValues map
        bool secureLDAP;
        if (configValues["ssl"] == "on")
        {
            secureLDAP = true;
        }
        else
        {
            secureLDAP = false;
        }

        ldap_base::Create::SearchScope lDAPSearchScope;
        if (configValues["scope"] == "sub")
        {
            lDAPSearchScope = ldap_base::Create::SearchScope::sub;
        }
        else if (configValues["scope"] == "one")
        {
            lDAPSearchScope = ldap_base::Create::SearchScope::one;
        }
        else
        {
            lDAPSearchScope = ldap_base::Create::SearchScope::base;
        }

        ldap_base::Create::Type lDAPType;
        // If the file is having a line which starts with "map group"
        if (configValues["map"] == "group")
        {
            lDAPType = ldap_base::Create::Type::ActiveDirectory;
        }
        else
        {
            lDAPType = ldap_base::Create::Type::OpenLdap;
        }

        createConfig(
            secureLDAP, std::move(configValues["uri"]),
            std::move(configValues["binddn"]), std::move(configValues["base"]),
            std::move(configValues["bindpw"]), lDAPSearchScope, lDAPType);
    }
    catch (const InvalidArgument& e)
    {
        // Don't throw - we don't want to create a D-Bus
        // object upon finding empty values in config, as
        // this can be a default config.
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
}
} // namespace ldap
} // namespace phosphor
