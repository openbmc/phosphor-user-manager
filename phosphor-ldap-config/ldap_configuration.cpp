#include "ldap_configuration.hpp"
#include "utils.hpp"
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
               const char* caCertfile, const char* certfile, bool secureLDAP,
               std::string lDAPServerURI, std::string lDAPBindDN,
               std::string lDAPBaseDN, std::string&& lDAPBindDNPassword,
               ldap_base::Config::SearchScope lDAPSearchScope,
               ldap_base::Config::Type lDAPType, ConfigMgr& parent) :
    ConfigIface(bus, path, true),
    secureLDAP(secureLDAP), configFilePath(filePath), tlsCacertfile(caCertfile),
    tlsCertfile(certfile), lDAPBindDNPassword(std::move(lDAPBindDNPassword)),
    bus(bus), parent(parent),
    certificateInstalledSignal(
        bus,
        sdbusRule::type::signal() + sdbusRule::member("InstallCompleted") +
            sdbusRule::path("/xyz/openbmc_project/certs/client/ldap") +
            sdbusRule::interface("xyz.openbmc_project.Certs.Install"),
        std::bind(std::mem_fn(&Config::certificateInstalled), this,
                  std::placeholders::_1))
{
    ConfigIface::lDAPServerURI(lDAPServerURI);
    ConfigIface::lDAPBindDN(lDAPBindDN);
    ConfigIface::lDAPBaseDN(lDAPBaseDN);
    ConfigIface::lDAPSearchScope(lDAPSearchScope);
    ConfigIface::lDAPType(lDAPType);
    writeConfig();
    parent.restartService(nslcdService);
    // Emit deferred signal.
    this->emit_object_added();
}

void Config::certificateInstalled(sdbusplus::message::message& msg)
{
    try
    {
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
}

void Config::delete_()
{
    parent.deleteObject();
    try
    {
        fs::path configDir = fs::path(configFilePath.c_str()).parent_path();

        fs::copy_file(configDir / defaultNslcdFile, LDAP_CONFIG_FILE,
                      fs::copy_options::overwrite_existing);

        fs::copy_file(configDir / linuxNsSwitchFile, configDir / nsSwitchFile,
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
    auto isPwdTobeWritten = false;

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
    if (!lDAPBindDNPassword.empty())
    {
        confData << "bindpw " << lDAPBindDNPassword << "\n";
        isPwdTobeWritten = true;
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
    if (secureLDAP == true)
    {
        confData << "ssl on\n";
        confData << "tls_reqcert hard\n";
        confData << "tls_cacertfile " << tlsCacertfile.c_str() << "\n";
        if (fs::exists(tlsCertfile.c_str()))
        {
            confData << "tls_cert " << tlsCertfile.c_str() << "\n";
            confData << "tls_key " << tlsCertfile.c_str() << "\n";
        }
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
        confData << "map passwd gecos displayName\n";
        confData << "filter group (objectclass=posixGroup)\n";
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

std::string Config::lDAPServerURI(std::string value)
{
    std::string val;
    try
    {
        if (value == lDAPServerURI())
        {
            return value;
        }

        if (!isValidLDAPSURI(value) && !isValidLDAPURI(value))
        {
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
        writeConfig();
        parent.restartService(nslcdService);
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
        writeConfig();
        parent.restartService(nslcdService);
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
    ConfigMgr::createConfig(std::string lDAPServerURI, std::string lDAPBindDN,
                            std::string lDAPBaseDN,
                            std::string lDAPBindDNPassword,
                            ldap_base::Create::SearchScope lDAPSearchScope,
                            ldap_base::Create::Type lDAPType)
{
    bool secureLDAP = false;

    if (isValidLDAPSURI(lDAPServerURI))
    {
        secureLDAP = true;
    }
    else if (isValidLDAPURI(lDAPServerURI))
    {
        secureLDAP = false;
    }
    else
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("lDAPServerURI"),
                              Argument::ARGUMENT_VALUE(lDAPServerURI.c_str()));
    }

    if (secureLDAP && !fs::exists(tlsCacertfile.c_str()))
    {
        log<level::ERR>("LDAP server's CA certificate not provided",
                        entry("TLSCACERTFILE=%s", tlsCacertfile.c_str()));
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
    try
    {
        fs::path configDir = fs::path(configFilePath.c_str()).parent_path();
        fs::copy_file(configDir / LDAPNsSwitchFile, configDir / nsSwitchFile,
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
        bus, objPath.c_str(), configFilePath.c_str(), tlsCacertfile.c_str(),
        tlsCertfile.c_str(), secureLDAP, lDAPServerURI, lDAPBindDN, lDAPBaseDN,
        std::move(lDAPBindDNPassword),
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

        createConfig(
            std::move(configValues["uri"]), std::move(configValues["binddn"]),
            std::move(configValues["base"]), std::move(configValues["bindpw"]),
            lDAPSearchScope, lDAPType);
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
        // object upon finding "ssl on" without having tls_cacertfile in place,
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
