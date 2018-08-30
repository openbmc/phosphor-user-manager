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

void Config::restartLDAPService()
{
    /*auto bus = sdbusplus::bus::new_default();
    auto method = bus.new_method_call(SYSTEMD_BUSNAME, SYSTEMD_PATH,
                                      SYSTEMD_INTERFACE, "RestartUnit");
    method.append("nslcd.service", "replace");
    bus.call_noreply(method);*/
}

void Config::writeConfig()
{
    fstream stream(configFilePath.c_str(), fstream::out);
    stringstream confData;
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
        confData << "ssl on\n\n";
    }
    else
    {
        confData << "ssl off\n\n";
    }
    if (lDAPType() == ldap_base::Config::Type::ActiveDirectory)
    {
        confData << "filter passwd    (&(objectClass=user)(objectClass=person)"
                    "(!(objectClass=computer)))\n";
        confData << "map passwd uid              sAMAccountName\n";
        confData << "map passwd uidNumber        "
                    "objectSid:S-1-5-21-3623811015-3361044348-30300820\n";
        confData << "map passwd gidNumber        primaryGroupID\n";
        confData << "map passwd homeDirectory    \"/home/$sAMAccountName\"\n";
        confData << "map passwd gecos            displayName\n";
        confData << "map passwd loginShell       \"/bin/bash\"\n";
        confData << "map group gidNumber         primaryGroupID\n";
    }
    else
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

    auto name = ConfigIface::secureLDAP(value);
    writeConfig();
    restartLDAPService();

    return name;
}

string Config::lDAPServerURI(string value)
{
    if (value == lDAPServerURI())
    {
        return value;
    }

    auto name = ConfigIface::lDAPServerURI(value);
    writeConfig();
    restartLDAPService();

    return name;
}

string Config::lDAPBindDN(string value)
{
    if (value == lDAPBindDN())
    {
        return value;
    }

    auto name = ConfigIface::lDAPBindDN(value);
    writeConfig();
    restartLDAPService();

    return name;
}

string Config::lDAPBaseDN(string value)
{
    if (value == lDAPBaseDN())
    {
        return value;
    }

    auto name = ConfigIface::lDAPBaseDN(value);
    writeConfig();
    restartLDAPService();

    return name;
}

string Config::lDAPBINDDNpassword(string value)
{
    if (value == lDAPBINDDNpassword())
    {
        return value;
    }

    auto name = ConfigIface::lDAPBINDDNpassword(value);
    writeConfig();
    restartLDAPService();

    return name;
}

ldap_base::Config::SearchScope
    Config::lDAPSearchScope(ldap_base::Config::SearchScope value)
{
    if (value == lDAPSearchScope())
    {
        return value;
    }

    auto name = ConfigIface::lDAPSearchScope(value);
    writeConfig();
    restartLDAPService();

    return name;
}

ldap_base::Config::Type Config::lDAPType(ldap_base::Config::Type value)
{
    if (value == lDAPType())
    {
        return value;
    }

    auto name = ConfigIface::lDAPType(value);
    writeConfig();
    restartLDAPService();

    return name;
}

string ConfigMgr::createConfig(bool secureLDAP, string lDAPServerURI,
                               string lDAPBindDN, string lDAPBaseDN,
                               string lDAPBINDDNpassword,
                               ldap_base::Create::SearchScope lDAPSearchScope,
                               ldap_base::Create::Type lDAPType)
{
    // With current implementation we support only one LDAP server.
    if (entries.size() != 0)
    {
        entries.erase(entries.begin(), entries.end());
    }

    auto objPath = string(LDAP_CONFIG_DBUS_OBJ_PATH);
    auto e = make_unique<Config>(
        bus, objPath.c_str(), LDAP_CONFIG_FILE, secureLDAP, lDAPServerURI,
        lDAPBindDN, lDAPBaseDN, lDAPBINDDNpassword,
        static_cast<ldap_base::Config::SearchScope>(lDAPSearchScope),
        static_cast<ldap_base::Config::Type>(lDAPType));

    entries.push_back(move(e));
    return objPath;
}

} // namespace ldap
} // namespace phosphor
