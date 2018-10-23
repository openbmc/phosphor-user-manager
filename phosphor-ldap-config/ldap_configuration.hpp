#pragma once

#include "config.h"
#include <xyz/openbmc_project/Object/Delete/server.hpp>
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
static constexpr auto LDAPNsSwitchFile = "nsswitch_ldap.conf";
static constexpr auto linuxNsSwitchFile = "nsswitch_linux.conf";

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace ldap_base = sdbusplus::xyz::openbmc_project::User::Ldap::server;
using ConfigIface = sdbusplus::server::object::object<
    ldap_base::Config, sdbusplus::xyz::openbmc_project::Object::server::Delete>;
using CreateIface = sdbusplus::server::object::object<ldap_base::Create>;
namespace sdbusRule = sdbusplus::bus::match::rules;

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
     *  @param[in] caCertfile - LDAP's CA certificate file.
     *  @param[in] certfile - LDAP's client certificate file.
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
           const char* caCertfile, const char* certfile, bool secureLDAP,
           std::string lDAPServerURI, std::string lDAPBindDN,
           std::string lDAPBaseDN, std::string lDAPBindDNpassword,
           ldap_base::Config::SearchScope lDAPSearchScope,
           ldap_base::Config::Type lDAPType, ConfigMgr& parent);

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

    /** @brief Delete this D-bus object.
     */
    void delete_() override;

  private:
    std::string configFilePath{};
    std::string tlsCacertfile{};
    std::string tlsCertfile{};

    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Create a new LDAP config file.
     */
    virtual void writeConfig();

    /** @brief reference to config manager object */
    ConfigMgr& parent;

    /** @brief React to InstallCompleted signal
     *  @param[in] msg - sdbusplus message
     */
    void certificateInstalled(sdbusplus::message::message& msg);
    sdbusplus::bus::match_t certificateInstalledSignal;
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
     *  @param[in] caCertfile - LDAP's CA certificate file.
     *  @param[in] certfile - LDAP's client certificate file.
     */
    ConfigMgr(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
              const char* caCertfile, const char* certfile) :
        CreateIface(bus, path, true),
        configFilePath(filePath), tlsCacertfile(caCertfile),
        tlsCertfile(certfile), bus(bus)
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

    /** @brief restarts given service
     *  @param[in] service - Service to be restarted.
     */
    virtual void restartService(const std::string& service);

    /** @brief stops given service
     *  @param[in] service - Service to be stopped.
     */
    virtual void stopService(const std::string& service);

    /** @brief delete the config D-Bus object.
     */
    void deleteObject();

  protected:
    std::string configFilePath{};
    std::string tlsCacertfile{};
    std::string tlsCertfile{};

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
