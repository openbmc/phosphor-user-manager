#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>
#include <experimental/filesystem>

namespace phosphor
{
namespace ldap
{

namespace LdapBase = sdbusplus::xyz::openbmc_project::User::Ldap::server;
using ConfigIface = sdbusplus::server::object::object<LdapBase::Config>;
using CreateIface = sdbusplus::server::object::object<LdapBase::Create>;
using PropertiesVariant = LdapBase::Config::PropertiesVariant;
using namespace std;
namespace fs = std::experimental::filesystem;

class ConfigMgr;

/** @class Configure
 *  @brief Configuration for LDAP.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Config
 *  APIs, in order to provide LDAP configuration.
 */
class Configure : public ConfigIface
{
  public:
    Configure() = delete;
    ~Configure() = default;
    Configure(const Configure&) = delete;
    Configure& operator=(const Configure&) = delete;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     *  @param[in] vals - map of properties.
     *  @param[in] parent - parent of configure object.
     */

    Configure(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
              map<string, PropertiesVariant> vals, ConfigMgr& parent) :
        ConfigIface(bus, path, true),
        configFilePath(filePath), parent(parent)
    {
        for (const auto& v : vals)
        {
            setPropertyByName(v.first, v.second);
        }
        writeConfig();
        restartLdapService();
        // Emit deferred signal.
        this->emit_object_added();
    }

    using ConfigIface::getPropertyByName;
    using ConfigIface::lDAPBaseDN;
    using ConfigIface::lDAPBindDN
    using ConfigIface::lDAPBINDDNpassword;
    using ConfigIface::lDAPSearchScope;
    using ConfigIface::lDAPServerURI;
    using ConfigIface::lDAPType;
    using ConfigIface::secureLDAP
    using ConfigIface::setPropertyByName;

    /** @brief Sets a property by name.
     *  @param[in] name - A string representation of the property name.
     *  @param[in] val - A variant containing the value to set.
     *  @returns true if property is updated.
     */
    bool setPropertyByName(const string& name, const PropertiesVariant& val);

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - secureLDAP value to be updated.
     *  @returns value of changed secureLDAP.
     */
    bool secureLDAP(bool value) override;

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - lDAPServerURI value to be updated.
     *  @returns value of changed lDAPServerURI.
     */
    string lDAPServerURI(string value) override;

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - lDAPBindDN value to be updated.
     *  @returns value of changed lDAPBindDN.
     */
    string lDAPBindDN(string value) override;

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - lDAPBaseDN value to be updated.
     *  @returns value of changed lDAPBaseDN.
     */
    string lDAPBaseDN(string value) override;

    /** @brief Override that updates lDAPBINDDNpassword property as well.
     *  @param[in] value - lDAPBINDDNpassword value to be updated.
     *  @returns value of changed lDAPBINDDNpassword.
     */
    string lDAPBINDDNpassword(string value) override;

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - lDAPSearchScope value to be updated.
     *  @returns value of changed lDAPSearchScope.
     */
    LdapBase::Config::SearchScope
        lDAPSearchScope(LdapBase::Config::SearchScope value) override;

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - lDAPType value to be updated.
     *  @returns value of changed lDAPType.
     */
    LdapBase::Config::Type lDAPType(LdapBase::Config::Type value) override;

  private:
    string configFilePath{};

    /** @brief This is a reference to Config manager object */
    ConfigMgr& parent;

    /** @brief Create a new LDAP config file.
     */
    virtual void writeConfig();

    /** @brief restart nslcd daemon
     */
    virtual void restartLdapService();
};

/** @class ConfigMgr
 *  @brief Configuration for LDAP.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Create
 *  APIs, in order to provide LDAP configuration.
 */
class ConfigMgr : public CreateIface
{
  public:
    ConfigMgr() = delete;
    ~ConfigMgr() = default;
    ConfigMgr(const ConfigMgr&) = delete;
    ConfigMgr& operator=(const ConfigMgr&) = delete;

    /** @brief ConfigMgr to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     */
    ConfigMgr(sdbusplus::bus::bus& bus, const char* path,
              const char* filePath) :
        CreateIface(bus, path),
        busConf(bus), configFilePath(filePath)
    {
        // TODO  restore config object if config file exists.
    }

    /** @brief concrete implementation of the pure virtual funtion
             xyz.openbmc_project.User.Ldap.Create.createConfig.
      *  @param[in] secureLDAP - Specifies whether to use SSL or not.
      *  @param[in] lDAPServerURI - LDAP URI of the server.
      *  @param[in] lDAPBindDN - distinguished name with which bind to bind
             to the directory server for lookups.
      *  @param[in] lDAPBaseDN -  distinguished name to use as search base.
      *  @param[in] lDAPBINDDNpassword - credentials with which to bind.
      *  @param[in] lDAPSearchScope - the search scope.
      *  @param[in] lDAPType - Specifies the the configured server Type.
      *  @returns the object path of the D-Bus object created.
      */
    string createConfig(bool secureLDAP, string lDAPServerURI,
                        string lDAPBindDN, string lDAPBaseDN,
                        string lDAPBINDDNpassword,
                        LdapBase::Create::SearchScope lDAPSearchScope,
                        LdapBase::Create::Type lDAPType) override;

    /** @brief creates config object.
     *  @param[in] vals - map of properties.
     *  @returns the object path of the D-Bus object created.
     */
    string createConfig(map<string, PropertiesVariant> vals);

  private:
    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& busConf;

    string configFilePath{};
    /** @brief vector of Configure dbus objects */
    vector<unique_ptr<Configure>> entries;

    /** @brief Populate existing config into D-Bus properties
     *  @param[in] filePath - LDAP config file path
     */
    void restore(const char* filePath);
};
} // namespace ldap
} // namespace phosphor
