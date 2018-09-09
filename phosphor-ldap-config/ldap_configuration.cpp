#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "ldap_configuration.hpp"
#include "config.h"
#include <sstream>
#include <fstream>
#include <sstream>

namespace phosphor
{
namespace ldap
{

void Configure::restartLdapService()
{
    //TODO need to be updated once we write service for nslcd daemon
}

void Configure::writeConfig()
{
    fstream stream(configFilePath.c_str(), fstream::out);
    stringstream confData;

    confData << "# This is the configuration file for the LDAP nameservice\n";
    confData << "# switch library's nslcd daemon. It configures the mapping\n";
    confData << "# between NSS names (see /etc/nsswitch.conf) and LDAP\n";
    confData << "# information in the directory.\n";
    confData << "# See the manual page nslcd.conf(5) for more information.\n\n";
    confData << "# The user and group nslcd should run as.\n";
    confData << "uid root\n";
    confData << "gid root\n\n";
    confData <<
             "# The uri pointing to the LDAP server to use for name lookups.\n";
    confData <<
             "# Multiple entries may be specified. The address that is used\n";
    confData <<
             "# here should be resolvable without using LDAP (obviously).\n";
    confData << "uri " << lDAPServerURI() << "\n\n";
    confData << "# The LDAP version to use (defaults to 3\n";
    confData << "# if supported by client library)\n";
    confData << "ldap_version 3\n\n";
    confData << "# The distinguished name of the search base.\n";
    confData << "base " << lDAPBaseDN() << "\n\n";
    confData << "# The distinguished name to bind to the server with.\n";
    confData << "# Optional: default is to bind anonymously.\n";
    confData << "binddn " << lDAPBindDN() << "\n\n";
    confData << "# The credentials to bind with.\n";
    confData << "# Optional: default is no credentials.\n";
    confData << "# Note that if you set a bindpw you should check the\n";
    confData << "# permissions of this file.\n";
    confData << "bindpw " << lDAPBINDDNpassword() << "\n\n";
    confData << "# The default search scope.\n";
    switch (static_cast<int>(lDAPSearchScope()))
    {
        case static_cast<int>(LdapBase::Config::SearchScope::sub):
            confData << "scope sub\n";
            break;
        case static_cast<int>(LdapBase::Config::SearchScope::one):
            confData << "scope one\n";
            break;
        case static_cast<int>(LdapBase::Config::SearchScope::base):
            confData << "scope base\n";
            break;
    }
    confData << "# Customize certain database lookups.\n";
    confData << "base passwd " << lDAPBaseDN() << "\n";
    confData << "base shadow " << lDAPBaseDN() << "\n\n";
    confData << "# Use StartTLS without verifying the server certificate.\n";
    confData << "# ssl start_tls\n";

    if (secureLDAP() == true)
    {
        confData << "ssl on\n";
    }
    else
    {
        confData << "ssl off\n";
    }

    confData << "tls_reqcert never\n\n";
    confData << "# Client certificate and key\n";
    confData << "# Use these, if your server requires client authentication.\n";
    confData << "#tls_cert\n";
    confData << "#tls_key\n\n";
    confData << "timelimit 30\n";
    confData << "bind_timelimit 30\n";
    confData << "pagesize 1000\n";
    confData << "referrals off\n\n";
    if (lDAPType() == LdapBase::Config::Type::ActiveDirectory)
    {
        confData <<
                 "filter passwd    (&(objectClass=user)(objectClass=person)"
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

bool Configure::secureLDAP(bool value)
{
    if (setPropertyByName("secureLDAP", value))
    {
        writeConfig();
        restartLdapService();
    }
    return value;
}

string Configure::lDAPServerURI(string value)
{
    if (setPropertyByName("LDAPServerURI", value))
    {
        writeConfig();
        restartLdapService();
    }
    return value;
}

string Configure::lDAPBindDN(string value)
{
    if (setPropertyByName("LDAPBindDN", value))
    {
        writeConfig();
        restartLdapService();
    }
    return value;
}

string Configure::lDAPBaseDN(string value)
{
    if (setPropertyByName("LDAPBaseDN", value))
    {
        writeConfig();
        restartLdapService();
    }
    return value;
}

string Configure::lDAPBINDDNpassword(string value)
{

    if (setPropertyByName("LDAPBINDDNpassword", value))
    {
        writeConfig();
        restartLdapService();
    }
    return value;
}

LdapBase::Config::SearchScope Configure::lDAPSearchScope(
    LdapBase::Config::SearchScope  value)
{

    if (setPropertyByName("LDAPSearchScope", value))
    {
        writeConfig();
        restartLdapService();
    }
    return value;
}

LdapBase::Config::Type Configure::lDAPType(LdapBase::Config::Type  value)
{
    if (setPropertyByName("LDAPType", value))
    {
        writeConfig();
        restartLdapService();
    }

    return value;
}

bool Configure::setPropertyByName(const string& name,
                                  const PropertiesVariant& val)
{
    if (val == getPropertyByName(name))
    {
        return false;
    }
    // TODO Validate the property before set
    ConfigIface::setPropertyByName(name, val, false);
    return true;
}

string ConfigMgr::createConfig(map<string, PropertiesVariant> vals)
{
    // With current implementation we support only one LDAP server.
    if (entries.size() != 0)
    {
        entries.erase(entries.begin(), entries.end());
    }
    auto objPath =  string(LDAP_CONFIG_DBUS_PATH) + '/' + "config";
    auto e =  make_unique<Configure>(
                  busConf,
                  objPath.c_str(),
                  configFilePath.c_str(),
                  vals,
                  *this);

    entries.push_back(move(e));
    return objPath;
}

string ConfigMgr::createConfig(
    bool secureLDAP,
    string lDAPServerURI,
    string lDAPBindDN,
    string lDAPBaseDN,
    string lDAPBINDDNpassword,
    LdapBase::Create::SearchScope lDAPSearchScope,
    LdapBase::Create::Type lDAPType)
{
    map<string, PropertiesVariant> vals;

    vals = { {"SecureLDAP", secureLDAP},
        {"LDAPServerURI", lDAPServerURI},
        {"LDAPBindDN", lDAPBindDN},
        {"LDAPBaseDN", lDAPBaseDN},
        {"LDAPBINDDNpassword", lDAPBINDDNpassword},
        {
            "LDAPSearchScope",
            static_cast<LdapBase::Config::SearchScope>(lDAPSearchScope)
        },
        {"LDAPType", static_cast<LdapBase::Config::Type>(lDAPType)}
    };

    auto objPath = createConfig(vals);

    return objPath;
}

void ConfigMgr::restore(const char* filePath)
{
    std::fstream stream(filePath, std::fstream::in);
    std::string line;
    using Key = std::string;

    using ConfigInfo = std::map<std::string, std::string>;
    ConfigInfo configValues;

    // here getline reads characters from stream and places them into line
    while (std::getline(stream, line))
    {
        Key key;
        std::istringstream is_line(line);
        // here getline extracts characters from is_line and stores them into
        // key until the delimitation character ' ' is found.
        // If the delimiter is found, it is extracted and discarded (i.e. it is
        // not stored and the next input operation will begin after it).
        if (std::getline(is_line, key, ' '))
        {
            // skip the line if it starts with "#" or if it is an empty line
            if (key[0] == '#' || key == "")
            {
                continue;
            }

            std::string value;
            // here getline extracts characters after delimitation character ' '
            if (std::getline(is_line, value))
            {
                // skip line if it starts with "map passwd" or "base passwd" or
                // "base shadow"
                if (value == "passwd" || value == "shadow")
                {
                    continue;
                }
                configValues[key] = value;
            }
        }
    }

    map<string, PropertiesVariant> vals;
    if (configValues["ssl"] == "on")
    {
        vals["secureLDAP"] = true;
    }
    else
    {
        vals["secureLDAP"] = false;
    }

    vals["LDAPServerURI"] = configValues["uri"];
    vals["LDAPBindDN"] = configValues["binddn"];
    vals["LDAPBaseDN"] = configValues["base"];
    vals["LDAPBINDDNpassword"] = configValues["bindpw"];

    if (configValues["scope"] == "sub")
    {
        vals["LSearchScope"] = LdapBase::Config::SearchScope::sub;
    }
    else if (configValues["scope"] == "one")
    {
        vals["LSearchScope"] = LdapBase::Config::SearchScope::one;
    }
    else
    {
        vals["LSearchScope"] = LdapBase::Config::SearchScope::base;
    }
    // If the file is having a line which starts with "map group"
    if (configValues["map"] == "group")
    {
        vals["LDAPType"] = LdapBase::Config::Type::ActiveDirectory;
    }
    else
    {
        vals["LDAPType"] = LdapBase::Config::Type::OpenLdap;
    }

    createConfig(vals);
}

} // namespace user
} // namespace phosphor
