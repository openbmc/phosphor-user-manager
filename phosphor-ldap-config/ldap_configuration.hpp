#pragma once

#include "config.h"
#include <xyz/openbmc_project/Object/Delete/server.hpp>
#include <xyz/openbmc_project/Object/Enable/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>

namespace phosphor
{
namespace ldap
{
static constexpr auto defaultNslcdFile = "nslcd.conf.default";
static constexpr auto nsSwitchFile = "nsswitch.conf";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using ConfigIface = sdbusplus::xyz::openbmc_project::User::Ldap::server::Config;
using EnableIface = sdbusplus::xyz::openbmc_project::Object::server::Enable;
using DeleteIface = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using Ifaces =
    sdbusplus::server::object::object<ConfigIface, EnableIface, DeleteIface>;
using CreateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::User::Ldap::server::Create>;

class ConfigMgr;

/** @class Config
 *  @brief Configuration for LDAP.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Config
 *  API, in order to provide LDAP configuration.
 */
class Config : public Ifaces
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
     *  @param[in] caCertFile - LDAP's CA certificate file.
     *  @param[in] secureLDAP - Specifies whether to use SSL or not.
     *  @param[in] lDAPServerURI - LDAP URI of the server.
     *  @param[in] lDAPBindDN - distinguished name with which to bind.
     *  @param[in] lDAPBaseDN -  distinguished name to use as search base.
     *  @param[in] lDAPBindDNPassword - credentials with which to bind.
     *  @param[in] lDAPSearchScope - the search scope.
     *  @param[in] lDAPType - Specifies the LDAP server type which can be AD
     *              or openLDAP.
     *  @param[in] lDAPServiceEnabled - Specifies whether the service would be
     *  enabled or not.
     *  @param[in] groupNameAttribute - Specifies attribute name that contains
     *             the name of the Group in the LDAP server.
     *  @param[in] userNameAttribute - Specifies attribute name that contains
     *             the username in the LDAP server.
     *
     *  @param[in] parent - parent of config object.
     */

    Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
           const char* caCertFile, bool secureLDAP, std::string lDAPServerURI,
           std::string lDAPBindDN, std::string lDAPBaseDN,
           std::string&& lDAPBindDNPassword,
           ConfigIface::SearchScope lDAPSearchScope, ConfigIface::Type lDAPType,
           bool lDAPServiceEnabled, std::string groupNameAttribute,
           std::string userNameAttribute, ConfigMgr& parent);

    using ConfigIface::groupNameAttribute;
    using ConfigIface::lDAPBaseDN;
    using ConfigIface::lDAPBindDN;
    using ConfigIface::lDAPBindDNPassword;
    using ConfigIface::lDAPSearchScope;
    using ConfigIface::lDAPServerURI;
    using ConfigIface::lDAPType;
    using ConfigIface::setPropertyByName;
    using ConfigIface::userNameAttribute;
    using EnableIface::enabled;

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

    /** @brief Update the Search scope property.
     *  @param[in] value - lDAPSearchScope value to be updated.
     *  @returns value of changed lDAPSearchScope.
     */
    ConfigIface::SearchScope
        lDAPSearchScope(ConfigIface::SearchScope value) override;

    /** @brief Update the LDAP Type property.
     *  @param[in] value - lDAPType value to be updated.
     *  @returns value of changed lDAPType.
     */
    ConfigIface::Type lDAPType(ConfigIface::Type value) override;

    /** @brief Update the ldapServiceEnabled property.
     *  @param[in] value - ldapServiceEnabled value to be updated.
     *  @returns value of changed ldapServiceEnabled.
     */
    bool enabled(bool value) override;

    /** @brief Update the userNameAttribute property.
     *  @param[in] value - userNameAttribute value to be updated.
     *  @returns value of changed userNameAttribute.
     */
    std::string userNameAttribute(std::string value) override;

    /** @brief Update the groupNameAttribute property.
     *  @param[in] value - groupNameAttribute value to be updated.
     *  @returns value of changed groupNameAttribute.
     */
    std::string groupNameAttribute(std::string value) override;

    /** @brief Update the BindDNPasword property.
     *  @param[in] value - lDAPBindDNPassword value to be updated.
     *  @returns value of changed lDAPBindDNPassword.
     */
    std::string lDAPBindDNPassword(std::string value) override;

    /** @brief Delete this D-bus object.
     */
    void delete_() override;

    bool secureLDAP;

  private:
    std::string configFilePath{};
    std::string tlsCacertFile{};
    std::string lDAPBindPassword{};

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
     *  @param[in] dbusPersistentPath - Persistent path for LDAP D-Bus property.
     *  @param[in] caCertFile - LDAP's CA certificate file.
     */
    ConfigMgr(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
              const char* dbusPersistentPath, const char* caCertFile) :
        CreateIface(bus, path, true),
        dbusPersistentPath(dbusPersistentPath), configFilePath(filePath),
        bus(bus)
    {
        try
        {
            restore(configFilePath.c_str());
            emit_object_added();
        }
        catch (const std::exception& e)
        {
            configPtr.reset(nullptr);
            log<level::ERR>(e.what());
            elog<InternalFailure>();
        }
    }

    /** @brief concrete implementation of the pure virtual funtion
            xyz.openbmc_project.User.Ldap.Create.createConfig.
     *  @param[in] lDAPServerURI - LDAP URI of the server.
     *  @param[in] lDAPBindDN - distinguished name with which bind to bind
            to the directory server for lookups.
     *  @param[in] lDAPBaseDN -  distinguished name to use as search base.
     *  @param[in] lDAPBindDNPassword - credentials with which to bind.
     *  @param[in] lDAPSearchScope - the search scope.
     *  @param[in] lDAPType - Specifies the LDAP server type which can be AD
            or openLDAP.
     *  @param[in] groupNameAttribute - Specifies attribute name that contains
     *             the name of the Group in the LDAP server.
     *  @param[in] usernameAttribute - Specifies attribute name that contains
     *             the username in the LDAP server.
     *  @returns the object path of the D-Bus object created.
     */
    std::string createConfig(std::string lDAPServerURI, std::string lDAPBindDN,
                             std::string lDAPBaseDN,
                             std::string lDAPBindDNPassword,
                             CreateIface::SearchScope lDAPSearchScope,
                             CreateIface::Type lDAPType,
                             std::string groupNameAttribute,
                             std::string userNameAttribute) override;

    /** @brief restarts given service
     *  @param[in] service - Service to be restarted.
     */
    virtual void restartService(const std::string& service);

    /** @brief stops given service
     *  @param[in] service - Service to be stopped.
     */
    virtual void stopService(const std::string& service);

    /** @brief start or stop the service depending on the given value
     *  @param[in] service - Service to be start/stop.
     *  @param[in] value - true to start the service otherwise stop.
     */
    virtual void startOrStopService(const std::string& service, bool value);

    /** @brief delete the config D-Bus object.
     */
    void deleteObject();

    /* ldap service enabled property would be saved under
     * this path.
     */
    std::string dbusPersistentPath;

  protected:
    std::string configFilePath{};
    std::string tlsCacertFile{};

    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Pointer to a Config D-Bus object */
    std::unique_ptr<Config> configPtr = nullptr;

    /** @brief Populate existing config into D-Bus properties
     *  @param[in] filePath - LDAP config file path
     */
    virtual void restore(const char* filePath);
};
} // namespace ldap
} // namespace phosphor
