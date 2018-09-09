#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/User/Ldap/Config/server.hpp>
#include <xyz/openbmc_project/User/Ldap/Create/server.hpp>

namespace phosphor
{
namespace ldap
{

using namespace phosphor::logging;
namespace LdapBase = sdbusplus::xyz::openbmc_project::User::Ldap::server;

template <typename T, typename U>
using LdapObject = typename sdbusplus::server::object::object<T, U>;
using LdapInterface = LdapObject<LdapBase::Config, LdapBase::Create>;


/** @class Configure
 *  @brief Configuration for LDAP.
 *  @details concrete implementation of xyz.openbmc_project.User.Ldap.Config
 *  and xyz.openbmc_project.User.Ldap.Create APIs, in order to provide LDAP
 *  configuration.
 */
class Configure : public LdapInterface
{
    public:
        Configure() = delete;
        ~Configure() = default;
        Configure(const Configure&) = delete;
        Configure& operator=(const Configure&) = delete;
        Configure(Configure&&) = delete;
        Configure& operator=(Configure&&) = delete;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         *  @param[in] filePath - LDAP configuration file.
         */
        Configure(sdbusplus::bus::bus& bus,
                  const char* path,
                  const char* filePath)
            : LdapInterface(bus, path, true),
              configFilePath(filePath)
        {
            try
            {
                restore(configFilePath.c_str());
            }
            catch(const std::exception& e)
            {
                log<level::ERR>(e.what());
            }

            emit_object_added();
        }

        using LdapInterface::secureLDAP;
        using LdapInterface::lDAPServerURI;
        using LdapInterface::lDAPBindDN;
        using LdapInterface::lDAPBaseDN;
        using LdapInterface::lDAPBINDDNpassword;
        using LdapInterface::lDAPSearchScope;
        using LdapInterface::lDAPType;

        /** @brief Override that updates secureLDAP property as well.
          *  @param[in] value - secureLDAP value to be updated.
          *  @returns value of changed secureLDAP.
          */
        bool secureLDAP(bool value) override;

        /** @brief Override that updates lDAPServerURI property as well.
          *  @param[in] value - lDAPServerURI value to be updated.
          *  @returns value of changed lDAPServerURI.
          */
        std::string lDAPServerURI(std::string value) override;

        /** @brief Override that updates lDAPBindDN property as well.
          *  @param[in] value - lDAPBindDN value to be updated.
          *  @returns value of changed lDAPBindDN.
          */
        std::string lDAPBindDN(std::string value) override;

        /** @brief Override that updates lDAPBaseDN property as well.
          *  @param[in] value - lDAPBaseDN value to be updated.
          *  @returns value of changed lDAPBaseDN.
          */
        std::string lDAPBaseDN(std::string value) override;

        /** @brief Override that updates lDAPBINDDNpassword property as well.
          *  @param[in] value - lDAPBINDDNpassword value to be updated.
          *  @returns value of changed lDAPBINDDNpassword.
          */
        std::string lDAPBINDDNpassword(std::string value) override;

        /** @brief Override that updates lDAPSearchScope property as well.
          *  @param[in] value - lDAPSearchScope value to be updated.
          *  @returns value of changed lDAPSearchScope.
          */
        LdapBase::Config::SearchScope lDAPSearchScope(
            LdapBase::Config::SearchScope value) override;

        /** @brief Override that updates lDAPType property as well.
          *  @param[in] value - lDAPType value to be updated.
          *  @returns value of changed lDAPType.
          */
        LdapBase::Config::Type lDAPType(LdapBase::Config::Type value) override;

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
          */
        void createConfig(
            bool secureLDAP,
            std::string lDAPServerURI,
            std::string lDAPBindDN,
            std::string lDAPBaseDN,
            std::string lDAPBINDDNpassword,
            LdapBase::Create::SearchScope lDAPSearchScope,
            LdapBase::Create::Type lDAPType) override;


    private:

        std::string configFilePath{};

        /** @brief Create a new LDAP config file.
         */
        void writeConfig();

        /** @brief restart nslcd daemon
         */
        void restartNslcd();

        /** @brief Populate existing config into D-Bus properties
         *  @param[in] filePath - LDAP config file path
         */
        void restore(const char* filePath);
};

} // namespace user
} // namespace phosphor
