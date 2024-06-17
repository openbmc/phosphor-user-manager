#pragma once

#include "config.h"

#include "ldap_mapper_entry.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Object/Enable/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>
#include <xyz/openbmc_project/User/PrivilegeMapper/server.hpp>

#include <filesystem>
#include <set>
#include <string>

namespace phosphor
{
namespace ldap
{

using ConfigIface = sdbusplus::xyz::openbmc_project::User::Ldap::server::Config;
using EnableIface = sdbusplus::xyz::openbmc_project::Object::server::Enable;
using CreateIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::User::Ldap::server::Create>;
namespace fs = std::filesystem;
using MapperIface =
    sdbusplus::xyz::openbmc_project::User::server::PrivilegeMapper;

using Ifaces =
    sdbusplus::server::object_t<ConfigIface, EnableIface, MapperIface>;
using ObjectPath = sdbusplus::message::object_path;

namespace sdbusRule = sdbusplus::bus::match::rules;

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
    Config(Config&&) = delete;
    Config& operator=(Config&&) = delete;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     *  @param[in] caCertFile - LDAP's CA certificate file.
     *  @param[in] certFile - LDAP's client certificate file.
     *  @param[in] secureLDAP - Specifies whether to use SSL or not.
     *  @param[in] ldapServerURI - LDAP URI of the server.
     *  @param[in] ldapBindDN - distinguished name with which to bind.
     *  @param[in] ldapBaseDN -  distinguished name to use as search base.
     *  @param[in] ldapBindDNPassword - credentials with which to bind.
     *  @param[in] ldapSearchScope - the search scope.
     *  @param[in] ldapType - Specifies the LDAP server type which can be AD
     *              or openLDAP.
     *  @param[in] ldapServiceEnabled - Specifies whether the service would be
     *  enabled or not.
     *  @param[in] groupNameAttribute - Specifies attribute name that contains
     *             the name of the Group in the LDAP server.
     *  @param[in] userNameAttribute - Specifies attribute name that contains
     *             the username in the LDAP server.
     *
     *  @param[in] parent - parent of config object.
     */

    Config(sdbusplus::bus_t& bus, const char* path, const char* filePath,
           const char* caCertFile, const char* certFile, bool secureLDAP,
           std::string ldapServerURI, std::string ldapBindDN,
           std::string ldapBaseDN, std::string&& ldapBindDNPassword,
           ConfigIface::SearchScope ldapSearchScope, ConfigIface::Type ldapType,
           bool ldapServiceEnabled, std::string groupNameAttribute,
           std::string userNameAttribute, ConfigMgr& parent);

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] filePath - LDAP configuration file.
     *  @param[in] ldapType - Specifies the LDAP server type which can be AD
     *              or openLDAP.
     *  @param[in] parent - parent of config object.
     */
    Config(sdbusplus::bus_t& bus, const char* path, const char* filePath,
           const char* caCertFile, const char* certFile,
           ConfigIface::Type ldapType, ConfigMgr& parent);

    using ConfigIface::groupNameAttribute;
    using ConfigIface::ldapBaseDN;
    using ConfigIface::ldapBindDN;
    using ConfigIface::ldapBindDNPassword;
    using ConfigIface::ldapSearchScope;
    using ConfigIface::ldapServerURI;
    using ConfigIface::ldapType;
    using ConfigIface::setPropertyByName;
    using ConfigIface::userNameAttribute;
    using EnableIface::enabled;

    /** @brief Update the Server URI property.
     *  @param[in] value - ldapServerURI value to be updated.
     *  @returns value of changed ldapServerURI.
     */
    std::string ldapServerURI(std::string value) override;

    /** @brief Update the BindDN property.
     *  @param[in] value - ldapBindDN value to be updated.
     *  @returns value of changed ldapBindDN.
     */
    std::string ldapBindDN(std::string value) override;

    /** @brief Update the BaseDN property.
     *  @param[in] value - ldapBaseDN value to be updated.
     *  @returns value of changed ldapBaseDN.
     */
    std::string ldapBaseDN(std::string value) override;

    /** @brief Update the Search scope property.
     *  @param[in] value - ldapSearchScope value to be updated.
     *  @returns value of changed ldapSearchScope.
     */
    ConfigIface::SearchScope
        ldapSearchScope(ConfigIface::SearchScope value) override;

    /** @brief Update the LDAP Type property.
     *  @param[in] value - ldapType value to be updated.
     *  @returns value of changed ldapType.
     */
    ConfigIface::Type ldapType(ConfigIface::Type value) override;

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
     *  @param[in] value - ldapBindDNPassword value to be updated.
     *  @returns value of changed ldapBindDNPassword.
     */
    std::string ldapBindDNPassword(std::string value) override;

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
     *  @param[in] value - enable/disable
     *  @returns value of changed status
     */
    bool enableService(bool value);

    /** @brief Creates a mapping for the group to the privilege
     *
     *  @param[in] groupName - Group Name to which the privilege needs to be
     *                         assigned.
     *  @param[in] privilege - The privilege role associated with the group.
     *
     *  @return On success return the D-Bus object path of the created privilege
     *          mapper entry.
     */
    ObjectPath create(std::string groupName, std::string privilege) override;

    /** @brief Delete privilege mapping for LDAP group
     *
     *  This method deletes the privilege mapping
     *
     *  @param[in] id - id of the object which needs to be deleted.
     */
    void deletePrivilegeMapper(Id id);

    /** @brief Check if LDAP group privilege mapping requested is valid
     *
     *  Check if the privilege mapping already exists for the LDAP group name
     *  and group name is empty.
     *
     *  @param[in] groupName - LDAP group name
     *
     *  @return throw exception if the conditions are not met.
     */
    void checkPrivilegeMapper(const std::string& groupName);

    /** @brief Check if the privilege level is a valid one
     *
     *  @param[in] privilege - Privilege level
     *
     *  @return throw exception if the conditions are not met.
     */
    void checkPrivilegeLevel(const std::string& privilege);

    /** @brief Construct LDAP mapper entry D-Bus objects from their persisted
     *         representations.
     */
    void restoreRoleMapping();

  private:
    bool secureLDAP;
    std::string ldapBindPassword{};
    std::string tlsCacertFile{};
    std::string tlsCertFile{};
    std::string configFilePath{};
    std::string objectPath{};
    std::filesystem::path configPersistPath{};

    /** @brief Persistent sdbusplus D-Bus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Create a new LDAP config file.
     */
    virtual void writeConfig();

    /** @brief reference to config manager object */
    ConfigMgr& parent;

    /** @brief Id of the last privilege mapper entry */
    Id entryId = 0;

    /** @brief container to hold privilege mapper objects */
    std::map<Id, std::unique_ptr<LDAPMapperEntry>> PrivilegeMapperList;

    /** @brief available privileges container */
    std::set<std::string> privMgr = {
        "priv-admin",
        "priv-operator",
        "priv-user",
    };

    /** @brief React to InterfaceAdded signal
     *  @param[in] msg - sdbusplus message
     */
    void certificateInstalled(sdbusplus::message_t& msg);
    sdbusplus::bus::match_t certificateInstalledSignal;

    sdbusplus::bus::match_t cacertificateInstalledSignal;

    /** @brief React to certificate changed signal
     *  @param[in] msg - sdbusplus message
     */
    void certificateChanged(sdbusplus::message_t& msg);
    sdbusplus::bus::match_t certificateChangedSignal;

    friend class MockConfigMgr;
};

} // namespace ldap
} // namespace phosphor
