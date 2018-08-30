#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "ldap_configuration.hpp"
#include "config.h"
#include <fstream>

namespace phosphor
{
namespace ldap
{

void Configure::restartNslcd()
{
    //TODO need to be updated once we write service for nslcd daemon

}

void Configure::writeConfig()
{
    std::fstream stream(configFilePath.c_str(), std::fstream::out);
    // Defaults entries into nslcd.conf file
    stream << "uid root"  << "\n";
    stream << "gid root"  << "\n";
    stream << "ssl" << " " << secureLDAP() << "\n";
    stream << "uri" << " " << lDAPServerURI() << "\n";
    stream << "binddn" << " " << lDAPBindDN() << "\n";
    stream << "bindpw" << " " << lDAPBINDDNpassword() << "\n";
    stream << "base" << " " << lDAPBaseDN() << "\n";
    stream << "base" << " " << lDAPBaseSearch() << "\n";
    stream << "tls_reqcert never"  << "\n";
    stream << "timelimit 30"  << "\n";
    stream << "bind_timelimit 30"  << "\n";
    stream << "pagesize 1000"  << "\n";
    stream << "referrals off"  << "\n";
    stream << "filter passwd\
        (&(objectClass=user)(objectClass=person)(!(objectClass=computer)))" <<
           "\n";
    stream << "map    passwd uid           sAMAccountName " << "\n";
    stream << "map    passwd uidNumber\
        objectSid:S-1-5-21-3623811015-3361044348-30300820 " << "\n";
    stream << "map    passwd gidNumber     primaryGroupID  " << "\n";
    stream << "map    passwd homeDirectory \"/home/$sAMAccountName\"  " << "\n";
    stream << "map    passwd gecos         displayName  " << "\n";
    stream << "map    passwd loginShell    \"/bin/bash\"  " << "\n";
    stream << "map    group gidNumber      primaryGroupID"  << "\n";

    // Entries into nslcd.conf file based on properties
    // TODO

    if (!stream.is_open())
    {
        return;
    }
    stream.close();
}

bool Configure::secureLDAP(bool value)
{
    if (value == secureLDAP())
    {
        return value;
    }

    auto name = LdapInterface::secureLDAP(value);
    writeConfig();
    restartNslcd();

    return name;
}

std::string Configure::lDAPServerURI(std::string value)
{
    if (value == lDAPServerURI())
    {
        return value;
    }

    auto name = LdapInterface::lDAPServerURI(value);
    writeConfig();
    restartNslcd();

    return name;
}

std::string Configure::lDAPBindDN(std::string value)
{
    if (value == lDAPBindDN())
    {
        return value;
    }

    auto name = LdapInterface::lDAPBindDN(value);
    writeConfig();
    restartNslcd();

    return name;
}

std::string Configure::lDAPBaseDN(std::string value)
{
    if (value == lDAPBaseDN())
    {
        return value;
    }

    auto name = LdapInterface::lDAPBaseDN(value);
    writeConfig();
    restartNslcd();

    return name;
}

std::string Configure::lDAPBINDDNpassword(std::string value)
{
    if (value == lDAPBINDDNpassword())
    {
        return value;
    }

    auto name = LdapInterface::lDAPBINDDNpassword(value);
    writeConfig();
    restartNslcd();

    return name;
}

std::string Configure::lDAPBaseSearch(std::string value)
{
    if (value == lDAPBaseSearch())
    {
        return value;
    }

    auto name = LdapInterface::lDAPBaseSearch(value);
    writeConfig();
    restartNslcd();

    return name;
}

LdapBase::Config::SearchScope Configure::lDAPSearchScope(
    LdapBase::Config::SearchScope  value)
{
    if (value == lDAPSearchScope())
    {
        return value;
    }

    auto name = LdapInterface::lDAPSearchScope(value);
    writeConfig();
    restartNslcd();

    return name;
}

LdapBase::Config::Type Configure::lDAPType(LdapBase::Config::Type  value)
{
    if (value == lDAPType())
    {
        return value;
    }

    auto name = LdapInterface::lDAPType(value);
    writeConfig();
    restartNslcd();

    return name;
}


void Configure::createConfig(
    bool secureLDAP,
    std::string lDAPServerURI,
    std::string lDAPBindDN,
    std::string lDAPBaseDN,
    std::string lDAPBINDDNpassword,
    std::string lDAPBaseSearch,
    LdapBase::Create::SearchScope lDAPSearchScope,
    LdapBase::Create::Type lDAPType)
{
    LdapInterface::secureLDAP(secureLDAP);
    LdapInterface::lDAPServerURI(lDAPServerURI);
    LdapInterface::lDAPBindDN(lDAPBindDN);
    LdapInterface::lDAPBaseDN(lDAPBaseDN);
    LdapInterface::lDAPBINDDNpassword(lDAPBINDDNpassword);
    LdapInterface::lDAPBaseSearch(lDAPBaseSearch);
    LdapInterface::lDAPSearchScope(static_cast<LdapBase::Config::SearchScope>
                                   (lDAPSearchScope));
    LdapInterface::lDAPType(static_cast<LdapBase::Config::Type>(lDAPType));

    writeConfig();
    restartNslcd();

}

} // namespace user
} // namespace phosphor
