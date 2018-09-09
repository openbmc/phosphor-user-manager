#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "ldap_configuration.hpp"
#include "config.h"
#include <sstream>
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

    stream << "# This is the configuration file for the LDAP nameservice"  <<
        "\n";
    stream << "# switch library's nslcd daemon. It configures the mapping"  <<
        "\n";
    stream << "# between NSS names (see /etc/nsswitch.conf) and LDAP"  << "\n";
    stream << "# information in the directory."  << "\n";
    stream << "# See the manual page nslcd.conf(5) for more information."  <<
        "\n\n";
    stream << "# The user and group nslcd should run as."  << "\n";
    stream << "uid root"  << "\n";
    stream << "gid root"  << "\n\n";
    stream << "# The uri pointing to the LDAP server to use for name lookups."
        << "\n";
    stream << "# Multiple entries may be specified. The address that is used"
        << "\n";
    stream << "# here should be resolvable without using LDAP (obviously)."
        << "\n";
    stream << "uri " << lDAPServerURI() << "\n\n";
    stream << "# The LDAP version to use (defaults to 3"  << "\n";
    stream << "# if supported by client library)"  << "\n";
    stream << "ldap_version 3"  << "\n\n";
    stream << "# The distinguished name of the search base."  << "\n";
    stream << "base " << lDAPBaseDN() << "\n\n";
    stream << "# The distinguished name to bind to the server with."  << "\n";
    stream << "# Optional: default is to bind anonymously."  << "\n";
    stream << "binddn " << lDAPBindDN() << "\n";
    stream << ""  << "\n";
    stream << "# The credentials to bind with."  << "\n";
    stream << "# Optional: default is no credentials."  << "\n";
    stream << "# Note that if you set a bindpw you should check the" << "\n";
    stream << "# permissions of this file." << "\n";
    stream << "bindpw " << lDAPBINDDNpassword() << "\n\n";
    stream << "# The default search scope."  << "\n";
    switch (static_cast<int>(lDAPSearchScope()))
    {
        case static_cast<int>(LdapBase::Config::SearchScope::sub):
            stream << "scope " << "sub" << "\n";
            break;
        case static_cast<int>(LdapBase::Config::SearchScope::one):
            stream << "scope " << "one" << "\n";
            break;
        case static_cast<int>(LdapBase::Config::SearchScope::base):
            stream << "scope "<< "base" << "\n";
            break;
    }
    stream << "\n";
    stream << "# Customize certain database lookups."  << "\n";
    stream << "base passwd " << lDAPBaseDN() << "\n";
    stream << "base shadow " << lDAPBaseDN() << "\n\n";
    stream << "# Use StartTLS without verifying the server certificate."
        << "\n";
    stream << "# ssl start_tls"  << "\n";

    if (secureLDAP() == true)
    {
        stream << "ssl on"  << "\n";
    }
    else
    {
        stream << "ssl off"  << "\n";
    }

    stream << "tls_reqcert never"  << "\n\n";
    stream << "# Client certificate and key"  << "\n";
    stream << "# Use these, if your server requires client authentication."
        << "\n";
    stream << "#tls_cert"  << "\n";
    stream << "#tls_key"  << "\n\n";
    stream << "timelimit 30"  << "\n";
    stream << "bind_timelimit 30"  << "\n";
    stream << "pagesize 1000"  << "\n";
    stream << "referrals off"  << "\n\n";
    stream << "filter passwd\
    (&(objectClass=user)(objectClass=person)(!(objectClass=computer)))" <<
    "\n";
    if (lDAPType() == LdapBase::Config::Type::ActiveDirectory)
    {
        stream << "map passwd uid              sAMAccountName"  << "\n";
        stream << "map passwd uidNumber\
        objectSid:S-1-5-21-3623811015-3361044348-30300820" << "\n";
        stream << "map passwd gidNumber        primaryGroupID"  << "\n";
        stream << "map passwd homeDirectory    \"/home/$sAMAccountName\""\
            << "\n";
        stream << "map passwd gecos            displayName"  << "\n";
        stream << "map passwd loginShell       \"/bin/bash\"" << "\n";
        stream << "map group gidNumber         primaryGroupID"  << "\n";
    }
    else
    {
        //TODO Need to updated
    }

    stream.close();
    return;
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
    LdapBase::Create::SearchScope lDAPSearchScope,
    LdapBase::Create::Type lDAPType)
{
    LdapInterface::secureLDAP(secureLDAP);
    LdapInterface::lDAPServerURI(lDAPServerURI);
    LdapInterface::lDAPBindDN(lDAPBindDN);
    LdapInterface::lDAPBaseDN(lDAPBaseDN);
    LdapInterface::lDAPBINDDNpassword(lDAPBINDDNpassword);
    LdapInterface::lDAPSearchScope(static_cast<LdapBase::Config::SearchScope>
                                   (lDAPSearchScope));
    LdapInterface::lDAPType(static_cast<LdapBase::Config::Type>(lDAPType));

    writeConfig();
    restartNslcd();

}

void Configure::restore(const char* filePath)
{
    std::fstream stream(filePath, std::fstream::in);
    std::string line;
    using ConfigInfo = std::map<std::string, std::string>;
    ConfigInfo configValues;

    while (std::getline(stream, line))
    {
        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, ' '))
        {
            std::string value;
            if (key[0] == '#')
            {
                continue;
            }

            if (std::getline(is_line, value))
            {
                if(value == "passwd" || value =="shadow")
                {
                    continue;
                }
                configValues[key] = value;
            }
        }
    }

    if(configValues["ssl"] == "on")
    {
        LdapInterface::secureLDAP(true);
    }
    else
    {
        LdapInterface::secureLDAP(false);
    }
    LdapInterface::lDAPServerURI(configValues["uri"]);
    LdapInterface::lDAPBindDN(configValues["binddn"]);
    LdapInterface::lDAPBaseDN(configValues["base"]);
    LdapInterface::lDAPBINDDNpassword(configValues["bindpw"]);
    if(configValues["scope"] =="sub")
    {
        LdapInterface::lDAPSearchScope(LdapBase::Config::SearchScope::sub);
    }
    else if(configValues["scope"] == "one")
    {
        LdapInterface::lDAPSearchScope(LdapBase::Config::SearchScope::one);
    }
    else
    {
        LdapInterface::lDAPSearchScope(LdapBase::Config::SearchScope::base);
    }
    if(configValues["map"] != "")
    {
        LdapInterface::lDAPType(LdapBase::Config::Type::ActiveDirectory);
    }
    else
    {
        LdapInterface::lDAPType(LdapBase::Config::Type::OpenLdap);
    }
}

} // namespace user
} // namespace phosphor
