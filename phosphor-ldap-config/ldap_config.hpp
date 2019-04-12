#pragma once

#include "config.h"
#include <xyz/openbmc_project/Object/Enable/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <filesystem>

namespace phosphor
{
namespace ldap
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using ConfigIface = sdbusplus::xyz::openbmc_project::User::Ldap::server::Config;
using EnableIface = sdbusplus::xyz::openbmc_project::Object::server::Enable;
using Ifaces = sdbusplus::server::object::object<ConfigIface, EnableIface>;
using CreateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::User::Ldap::server::Create>;
namespace fs = std::filesystem;
class ConfigMgr;
class MockConfigMgr;

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

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     *  @param[in] lDAPType - Specifies the LDAP server type which can be AD
     *              or openLDAP.
     *  @param[in] parent - parent of config object.
     */
    Config(sdbusplus::bus::bus& bus, const char* path, const char* filePath,
           const char* caCertFile, ConfigIface::Type lDAPType,
           ConfigMgr& parent);

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

    /** @brief Function required by Cereal to perform deserialization.
     *  @tparam Archive - Cereal archive type (binary in our case).
     *  @param[in] archive - reference to Cereal archive.
     *  @param[in] version - Class version that enables handling
     *                       a serialized data across code levels
     */
    template <class Archive>
    void load(Archive& archive, const std::uint32_t version);

    /** @brief Function required by Cereal to perform serialization.
     *  @tparam Archive - Cereal archive type (binary in our case).
     *  @param[in] archive - reference to Cereal archive.
     *  @param[in] version - Class version that enables handling
     *                       a serialized data across code levels
     */
    template <class Archive>
    void save(Archive& archive, const std::uint32_t version) const;

    /** @brief Serialize and persist this object at the persist
     *         location.
     */
    void serialize();

    /** @brief Deserialize LDAP config data from the persistent location
     *         into this object
     *  @return bool - true if the deserialization was successful, false
     *                 otherwise.
     */
    bool deserialize();

    /** @brief enable or disable the service with the given value
     *  @param[in] value - enable/disble
     *  @returns value of changed status
     */
    bool enableService(bool value);

  private:
    bool secureLDAP;
    std::string lDAPBindPassword{};
    std::string tlsCacertFile{};
    std::string configFilePath{};
    std::string objectPath{};
    std::filesystem::path configPersistPath{};

    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Create a new LDAP config file.
     */
    virtual void writeConfig();

    /** @brief reference to config manager object */
    ConfigMgr& parent;

    friend class MockConfigMgr;
};

} // namespace ldap
} // namespace phosphor
