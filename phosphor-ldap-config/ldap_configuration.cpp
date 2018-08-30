#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "ldap_configuration.hpp"
#include "config.h"
#include <fstream>
#include <sstream>

namespace phosphor
{
namespace ldap
{

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
    parent.restartNslcd();
    // Emit deferred signal.
    this->emit_object_added();
}

void Config::writeConfig()
{
    std::fstream stream(configFilePath.c_str(), std::fstream::out);
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
    confData << "bindpw " << lDAPBINDDNpassword() << "\n\n";
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
        confData << "ssl off\n\n";
    }
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
    stream << confData.str();
    stream.flush();
    stream.close();
    return;
}

bool Config::secureLDAP(bool value)
{
    if (value == secureLDAP())
    {
        return value;
    }

    auto val = ConfigIface::secureLDAP(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

std::string Config::lDAPServerURI(std::string value)
{
    if (value == lDAPServerURI())
    {
        return value;
    }

    auto val = ConfigIface::lDAPServerURI(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

std::string Config::lDAPBindDN(std::string value)
{
    if (value == lDAPBindDN())
    {
        return value;
    }

    auto val = ConfigIface::lDAPBindDN(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

std::string Config::lDAPBaseDN(std::string value)
{
    if (value == lDAPBaseDN())
    {
        return value;
    }

    auto val = ConfigIface::lDAPBaseDN(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

std::string Config::lDAPBINDDNpassword(std::string value)
{
    if (value == lDAPBINDDNpassword())
    {
        return value;
    }

    auto val = ConfigIface::lDAPBINDDNpassword(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

ldap_base::Config::SearchScope
    Config::lDAPSearchScope(ldap_base::Config::SearchScope value)
{
    if (value == lDAPSearchScope())
    {
        return value;
    }

    auto val = ConfigIface::lDAPSearchScope(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

ldap_base::Config::Type Config::lDAPType(ldap_base::Config::Type value)
{
    if (value == lDAPType())
    {
        return value;
    }

    auto val = ConfigIface::lDAPType(value);
    writeConfig();
    parent.restartNslcd();

    return val;
}

void ConfigMgr::restartNslcd()
{
    auto method = bus.new_method_call(SYSTEMD_BUSNAME, SYSTEMD_PATH,
                                      SYSTEMD_INTERFACE, "RestartUnit");
    method.append("nslcd.service", "replace");
    bus.call_noreply(method);
}

void ConfigMgr::stopNslcd()
{
    auto method = bus.new_method_call(SYSTEMD_BUSNAME, SYSTEMD_PATH,
                                      SYSTEMD_INTERFACE, "StopUnit");
    method.append("nslcd.service", "replace");
    bus.call_noreply(method);
}

void ConfigMgr::restartNscd()
{
    auto method = bus.new_method_call(SYSTEMD_BUSNAME, SYSTEMD_PATH,
                                      SYSTEMD_INTERFACE, "RestartUnit");
    method.append("nslcd.service", "replace");
    bus.call_noreply(method);
}

std::string
    ConfigMgr::createConfig(bool secureLDAP, std::string lDAPServerURI,
                            std::string lDAPBindDN, std::string lDAPBaseDN,
                            std::string lDAPBINDDNpassword,
                            ldap_base::Create::SearchScope lDAPSearchScope,
                            ldap_base::Create::Type lDAPType)
{
    // With current implementation we support only one LDAP server.
    if (configPtr)
    {
        configPtr.reset(nullptr);
    }

    auto objPath = std::string(LDAP_CONFIG_DBUS_OBJ_PATH);
    configPtr = std::make_unique<Config>(
        bus, objPath.c_str(), LDAP_CONFIG_FILE, secureLDAP, lDAPServerURI,
        lDAPBindDN, lDAPBaseDN, lDAPBINDDNpassword,
        static_cast<ldap_base::Config::SearchScope>(lDAPSearchScope),
        static_cast<ldap_base::Config::Type>(lDAPType), *this);

    return objPath;
}

} // namespace ldap
} // namespace phosphor
