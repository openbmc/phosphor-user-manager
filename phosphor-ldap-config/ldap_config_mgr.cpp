#include "ldap_config_mgr.hpp"
#include "ldap_config.hpp"
#include "ldap_config_serialize.hpp"

#include "utils.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace phosphor
{
namespace ldap
{

constexpr auto nscdService = "nscd.service";
constexpr auto LDAPscheme = "ldap";
constexpr auto LDAPSscheme = "ldaps";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::filesystem;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

using Line = std::string;
using Key = std::string;
using Val = std::string;
using ConfigInfo = std::map<Key, Val>;

void ConfigMgr::startOrStopService(const std::string& service, bool start)
{
    if (start)
    {
        restartService(service);
    }
    else
    {
        stopService(service);
    }
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
        log<level::ERR>("Failed to restart service",
                        entry("SERVICE=%s", service.c_str()),
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
        log<level::ERR>("Failed to stop service",
                        entry("SERVICE=%s", service.c_str()),
                        entry("ERR=%s", ex.what()));
        elog<InternalFailure>();
    }
}

void ConfigMgr::deleteObject()
{
    configPtr.reset(nullptr);
}

std::string ConfigMgr::createConfig(
    std::string lDAPServerURI, std::string lDAPBindDN, std::string lDAPBaseDN,
    std::string lDAPBindDNPassword, CreateIface::SearchScope lDAPSearchScope,
    CreateIface::Create::Type lDAPType, std::string groupNameAttribute,
    std::string userNameAttribute)
{
    bool secureLDAP = false;

    if (isValidLDAPURI(lDAPServerURI, LDAPSscheme))
    {
        secureLDAP = true;
    }
    else if (isValidLDAPURI(lDAPServerURI, LDAPscheme))
    {
        secureLDAP = false;
    }
    else
    {
        log<level::ERR>("bad LDAP Server URI",
                        entry("LDAPSERVERURI=%s", lDAPServerURI.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPServerURI"),
                              Argument::ARGUMENT_VALUE(lDAPServerURI.c_str()));
    }

    if (secureLDAP && !fs::exists(tlsCacertFile.c_str()))
    {
        log<level::ERR>("LDAP server's CA certificate not provided",
                        entry("TLSCACERTFILE=%s", tlsCacertFile.c_str()));
        elog<NoCACertificate>();
    }

    if (lDAPBindDN.empty())
    {
        log<level::ERR>("Not a valid LDAP BINDDN",
                        entry("LDAPBINDDN=%s", lDAPBindDN.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("LDAPBindDN"),
                              Argument::ARGUMENT_VALUE(lDAPBindDN.c_str()));
    }

    if (lDAPBaseDN.empty())
    {
        log<level::ERR>("Not a valid LDAP BASEDN",
                        entry("LDAPBASEDN=%s", lDAPBaseDN.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("LDAPBaseDN"),
                              Argument::ARGUMENT_VALUE(lDAPBaseDN.c_str()));
    }

    // With current implementation we support only one LDAP server.
    deleteObject();

    auto objPath = std::string(LDAP_CONFIG_DBUS_OBJ_PATH);
    configPtr = std::make_unique<Config>(
        bus, objPath.c_str(), configFilePath.c_str(), tlsCacertFile.c_str(),
        secureLDAP, lDAPServerURI, lDAPBindDN, lDAPBaseDN,
        std::move(lDAPBindDNPassword),
        static_cast<ConfigIface::SearchScope>(lDAPSearchScope),
        static_cast<ConfigIface::Type>(lDAPType), false, groupNameAttribute,
        userNameAttribute, *this);

    restartService(nscdService);
    return objPath;
}

void ConfigMgr::restore(const char* filePath)
{
    if (!fs::exists(filePath))
    {
        log<level::ERR>("Config file doesn't exists",
                        entry("LDAP_CONFIG_FILE=%s", configFilePath.c_str()));
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

                    // if config type is AD "map group" entry would be add to
                    // the map configValues. For OpenLdap config file no map
                    // entry would be there.
                    if ((key == "map") && (value == "passwd"))
                    {
                        key = key + "_" + value;
                        if (std::getline(isLine, value, ' '))
                        {
                            key += "_" + value;
                        }
                        std::getline(isLine, value, ' ');
                    }
                    configValues[key] = value;
                }
            }
        }

        CreateIface::SearchScope lDAPSearchScope;
        if (configValues["scope"] == "sub")
        {
            lDAPSearchScope = CreateIface::SearchScope::sub;
        }
        else if (configValues["scope"] == "one")
        {
            lDAPSearchScope = CreateIface::SearchScope::one;
        }
        else
        {
            lDAPSearchScope = CreateIface::SearchScope::base;
        }

        CreateIface::Type lDAPType;
        // If the file is having a line which starts with "map group"
        if (configValues["map"] == "group")
        {
            lDAPType = CreateIface::Type::ActiveDirectory;
        }
        else
        {
            lDAPType = CreateIface::Type::OpenLdap;
        }

        // Don't create the config object if either of the field is empty.
        if (configValues["uri"] == "" || configValues["binddn"] == "" ||
            configValues["base"] == "")
        {
            log<level::INFO>(
                "LDAP config parameter value missing",
                entry("URI=%s", configValues["uri"].c_str()),
                entry("BASEDN=%s", configValues["base"].c_str()),
                entry("BINDDN=%s", configValues["binddn"].c_str()));
            return;
        }

        createConfig(std::move(configValues["uri"]),
                     std::move(configValues["binddn"]),
                     std::move(configValues["base"]),
                     std::move(configValues["bindpw"]), lDAPSearchScope,
                     lDAPType, std::move(configValues["map_passwd_uid"]),
                     std::move(configValues["map_passwd_gidNumber"]));

        // Get the enabled property value from the persistent location
        if (!deserialize(dbusPersistentPath, *configPtr))
        {
            log<level::INFO>(
                "Deserialization Failed, continue with service disable");
        }
    }
    catch (const InvalidArgument& e)
    {
        // Don't throw - we don't want to create a D-Bus
        // object upon finding empty values in config, as
        // this can be a default config.
    }
    catch (const NoCACertificate& e)
    {
        // Don't throw - we don't want to create a D-Bus
        // object upon finding "ssl on" without having tls_cacertFile in place,
        // as this can be a default config.
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
