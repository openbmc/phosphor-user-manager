#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <phosphor-logging/log.hpp>
#include "xyz/openbmc_project/Object/Delete/server.hpp"
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>
#include "config.h"

namespace phosphor
{
namespace ldap
{
using namespace phosphor::logging;
namespace ldap_base = sdbusplus::xyz::openbmc_project::User::Ldap::server;
using ConfigIface = sdbusplus::server::object::object<
    ldap_base::Config, sdbusplus::xyz::openbmc_project::Object::server::Delete>;
using CreateIface = sdbusplus::server::object::object<ldap_base::Create>;
using namespace std;

class ConfigMgr;
class Config;

using ConfigMap = std::map<std::string, std::shared_ptr<Config>>;

/** @class Config
 *  @brief Configuration for LDAP.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Config
 *  APIs, in order to provide LDAP configuration.
 */
class Config : public ConfigIface
{
  public:
    Config() = delete;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    Config(Config&&) = default;
    Config& operator=(Config&&) = default;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     *  @param[in] secureLDAP - Specifies whether to use SSL or not.
     *  @param[in] lDAPServerURI - LDAP URI of the server.
     *  @param[in] lDAPBindDN - distinguished name with which bind to bind
            to the directory server for lookups.
     *  @param[in] lDAPBaseDN -  distinguished name to use as search base.
     *  @param[in] lDAPBINDDNpassword - credentials with which to bind.
     *  @param[in] lDAPSearchScope - the search scope.
     *  @param[in] lDAPType - Specifies the the Configd server Type.
     *  @param[in] parent - parent of config object
     */

    Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
           bool secureLDAP, string lDAPServerURI, string lDAPBindDN,
           string lDAPBaseDN, string lDAPBINDDNpassword,
           ldap_base::Config::SearchScope lDAPSearchScope,
           ldap_base::Config::Type lDAPType, ConfigMgr& parent) :
        ConfigIface(bus, path, true),
        configFilePath(filePath), parent(parent)
    {
        this->lDAPBaseDN(lDAPBaseDN);
        this->lDAPBindDN(lDAPBindDN);
        this->lDAPBINDDNpassword(lDAPBINDDNpassword);
        this->lDAPSearchScope(lDAPSearchScope);
        this->lDAPServerURI(lDAPServerURI);
        this->lDAPType(lDAPType);
        this->secureLDAP(secureLDAP);
        writeConfig();
        restartLDAPService();
        // Emit deferred signal.
        this->emit_object_added();
    }

    using ConfigIface::lDAPBaseDN;
    using ConfigIface::lDAPBindDN;
    using ConfigIface::lDAPBINDDNpassword;
    using ConfigIface::lDAPSearchScope;
    using ConfigIface::lDAPServerURI;
    using ConfigIface::lDAPType;
    using ConfigIface::secureLDAP;
    using ConfigIface::setPropertyByName;

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
    ldap_base::Config::SearchScope
        lDAPSearchScope(ldap_base::Config::SearchScope value) override;

    /** @brief Override that updates the ldap config file as well.
     *  @param[in] value - lDAPType value to be updated.
     *  @returns value of changed lDAPType.
     */
    ldap_base::Config::Type lDAPType(ldap_base::Config::Type value) override;

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

  private:
    string configFilePath{};

    /** @brief Create a new LDAP config file.
     */
    virtual void writeConfig();

    /** @brief restart nslcd daemon
     */
    virtual void restartLDAPService();

    /** @brief This is a reference to Config manager object */
    ConfigMgr& parent;
};

/** @class ConfigMgr
 *  @brief Creates LDAP server configuration.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Create
 *  APIs, in order to create LDAP configuration.
 */
class ConfigMgr : public CreateIface
{
  public:
    ConfigMgr() = delete;
    ~ConfigMgr() = default;
    ConfigMgr(const ConfigMgr&) = delete;
    ConfigMgr& operator=(const ConfigMgr&) = delete;
    ConfigMgr(ConfigMgr&&) = delete;
    ConfigMgr& operator=(ConfigMgr&&) = default;

    /** @brief ConfigMgr to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     */
    ConfigMgr(sdbusplus::bus::bus& bus, const char* path) :
        CreateIface(bus, path, true), bus(bus)
    {
        try
        {
            restore(LDAP_CONFIG_FILE);
        }
        catch (const std::exception& e)
        {
            log<level::ERR>(e.what());
        }

        emit_object_added();
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
     *  @param[in] lDAPType - Specifies the the Configd server Type.
     *  @returns the object path of the D-Bus object created.
     */
    string createConfig(bool secureLDAP, string lDAPServerURI,
                        string lDAPBindDN, string lDAPBaseDN,
                        string lDAPBINDDNpassword,
                        ldap_base::Create::SearchScope lDAPSearchScope,
                        ldap_base::Create::Type lDAPType) override;

    /** @brief delete the dbus object.
     *  @param[in] objpath - object path.
     */
    void deleteObject(const std::string& objpath);

  private:
    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief map of Config dbus objects and their names */
    ConfigMap entries;

    /** @brief Populate existing config into D-Bus properties
     *  @param[in] filePath - LDAP config file path
     */
    void restore(const char* filePath);
};
} // namespace ldap
} // namespace phosphor
