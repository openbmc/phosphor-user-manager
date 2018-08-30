#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>
#include <string>

namespace phosphor
{
namespace ldap
{

namespace ldap_base = sdbusplus::xyz::openbmc_project::User::Ldap::server;
using ConfigIface = sdbusplus::server::object::object<ldap_base::Config>;
using CreateIface = sdbusplus::server::object::object<ldap_base::Create>;

class ConfigMgr;

/** @class Config
 *  @brief Configuration for LDAP.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Config
 *  API, in order to provide LDAP configuration.
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
     *  @param[in] lDAPBindDN - distinguished name with which to bind.
     *  @param[in] lDAPBaseDN -  distinguished name to use as search base.
     *  @param[in] lDAPBindDNpassword - credentials with which to bind.
     *  @param[in] lDAPSearchScope - the search scope.
     *  @param[in] lDAPType - Specifies the LDAP server type which can be AD
            or openLDAP.
     *  @param[in] parent - parent of config object.
     */

    Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
           bool secureLDAP, std::string lDAPServerURI, std::string lDAPBindDN,
           std::string lDAPBaseDN, std::string lDAPBindDNpassword,
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

    /** @brief Update the secure LDAP property.
     *  @param[in] value - secureLDAP value to be updated.
     *  @returns value of changed secureLDAP.
     */
    bool secureLDAP(bool value) override;

    /** @brief Update the Server URI property.
     *  @param[in] value - lDAPServerURI value to be updated.
     *  @returns value of changed lDAPServerURI.
     */
    std::string lDAPServerURI(std::string value) override;

    /** @brief Update the BindDN property.
     *  @param[in] value - lDAPBindDN value to be updated.
     *  @returns value of changed lDAPBindDN.
     */
    std::string lDAPBindDN(std::string value) override;

    /** @brief Update the BaseDN property.
     *  @param[in] value - lDAPBaseDN value to be updated.
     *  @returns value of changed lDAPBaseDN.
     */
    std::string lDAPBaseDN(std::string value) override;

    /** @brief Update the BindDN password property.
     *  @param[in] value - lDAPBINDDNpassword value to be updated.
     *  @returns value of changed lDAPBINDDNpassword.
     */
    std::string lDAPBINDDNpassword(std::string value) override;

    /** @brief Update the Search scope property.
     *  @param[in] value - lDAPSearchScope value to be updated.
     *  @returns value of changed lDAPSearchScope.
     */
    ldap_base::Config::SearchScope
        lDAPSearchScope(ldap_base::Config::SearchScope value) override;

    /** @brief Update the LDAP Type property.
     *  @param[in] value - lDAPType value to be updated.
     *  @returns value of changed lDAPType.
     */
    ldap_base::Config::Type lDAPType(ldap_base::Config::Type value) override;

  private:
    std::string configFilePath{};

    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Create a new LDAP config file.
     */
    virtual void writeConfig();

    /** @brief reference to config manager object */
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
    ConfigMgr& operator=(ConfigMgr&&) = delete;

    /** @brief ConfigMgr to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     */
    ConfigMgr(sdbusplus::bus::bus& bus, const char* path) :
        CreateIface(bus, path), bus(bus)
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
     *  @param[in] lDAPBindDNpassword - credentials with which to bind.
     *  @param[in] lDAPSearchScope - the search scope.
     *  @param[in] lDAPType - Specifies the LDAP server type which can be AD
            or openLDAP.
     *  @returns the object path of the D-Bus object created.
     */
    std::string createConfig(bool secureLDAP, std::string lDAPServerURI,
                             std::string lDAPBindDN, std::string lDAPBaseDN,
                             std::string lDAPBindDNpassword,
                             ldap_base::Create::SearchScope lDAPSearchScope,
                             ldap_base::Create::Type lDAPType) override;

    /** @brief make a call to systemd manager to start/stop/restart given
            service.
     *  @param[in] service - Service to make a call.
     *  @param[in] action - Action to be done.
     */
    virtual void callSystemdMgr(std::string service, std::string action);

  private:
    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Pointer to a Config D-Bus object */
    std::unique_ptr<Config> configPtr;
};
} // namespace ldap
} // namespace phosphor
