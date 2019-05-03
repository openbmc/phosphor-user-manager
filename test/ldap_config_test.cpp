#include "config.h"
#include "phosphor-ldap-config/ldap_config.hpp"
#include "phosphor-ldap-config/ldap_config_mgr.hpp"
#include "phosphor-ldap-config/ldap_config_serialize.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <sdbusplus/bus.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <sys/types.h>

namespace phosphor
{
namespace ldap
{
namespace fs = std::filesystem;
namespace ldap_base = sdbusplus::xyz::openbmc_project::User::Ldap::server;
using Config = phosphor::ldap::Config;
static constexpr const char* dbusPersistFile = "Config";

class TestLDAPConfig : public testing::Test
{
  public:
    TestLDAPConfig() : bus(sdbusplus::bus::new_default())
    {
    }
    void SetUp() override
    {
        using namespace phosphor::ldap;
        char tmpldap[] = "/tmp/ldap_test.XXXXXX";
        dir = fs::path(mkdtemp(tmpldap));
        fs::path tslCacertFilePath{TLS_CACERT_FILE};
        tslCacertFile = tslCacertFilePath.filename().c_str();
        fs::path confFilePath{LDAP_CONFIG_FILE};
        ldapconfFile = confFilePath.filename().c_str();
        std::fstream fs;
        fs.open(dir / defaultNslcdFile, std::fstream::out);
        fs.close();
        fs.open(dir / nsSwitchFile, std::fstream::out);
        fs.close();
    }

    void TearDown() override
    {
        fs::remove_all(dir);
    }

  protected:
    fs::path dir;
    std::string tslCacertFile;
    std::string ldapconfFile;
    sdbusplus::bus::bus bus;
};

class MockConfigMgr : public phosphor::ldap::ConfigMgr
{
  public:
    MockConfigMgr(sdbusplus::bus::bus& bus, const char* path,
                  const char* filePath, const char* dbusPersistentFile,
                  const char* caCertFile) :
        phosphor::ldap::ConfigMgr(bus, path, filePath, dbusPersistentFile,
                                  caCertFile)
    {
    }
    MOCK_METHOD1(restartService, void(const std::string& service));
    MOCK_METHOD1(stopService, void(const std::string& service));
    std::unique_ptr<Config>& getOpenLdapConfigPtr()
    {
        return openLDAPConfigPtr;
    }

    std::string configBindPassword()
    {
        return getADConfigPtr()->lDAPBindPassword;
    }

    std::unique_ptr<Config>& getADConfigPtr()
    {
        return ADConfigPtr;
    }
    void restore()
    {
        // TODO enable it in later commit.
        // phosphor::ldap::ConfigMgr::restore();
        return;
    }

    void createDefaultObjects()
    {
        phosphor::ldap::ConfigMgr::createDefaultObjects();
    }

    friend class TestLDAPConfig;
};

TEST_F(TestLDAPConfig, testCreate)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCacertfile.c_str());

    EXPECT_CALL(manager, stopService("nslcd.service")).Times(2);
    EXPECT_CALL(manager, restartService("nslcd.service")).Times(2);
    EXPECT_CALL(manager, restartService("nscd.service")).Times(2);
    manager.createConfig(
        "ldap://9.194.251.136/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "uid", "gid");
    manager.getADConfigPtr()->enabled(true);

    manager.createConfig("ldap://9.194.251.137/", "cn=Users",
                         "cn=Users,dc=test", "MyLdap123",
                         ldap_base::Create::SearchScope::sub,
                         ldap_base::Create::Type::OpenLdap, "uid", "gid");
    manager.getOpenLdapConfigPtr()->enabled(false);

    // Below setting of username/groupname attr is to make sure
    // that in-active config should not call the start/stop service.
    manager.getOpenLdapConfigPtr()->userNameAttribute("abc");
    EXPECT_EQ(manager.getOpenLdapConfigPtr()->userNameAttribute(), "abc");

    manager.getOpenLdapConfigPtr()->groupNameAttribute("def");
    EXPECT_EQ(manager.getOpenLdapConfigPtr()->groupNameAttribute(), "def");

    EXPECT_TRUE(fs::exists(configFilePath));
    EXPECT_EQ(manager.getADConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.136/");
    EXPECT_EQ(manager.getADConfigPtr()->lDAPBindDN(), "cn=Users,dc=com");
    EXPECT_EQ(manager.getADConfigPtr()->lDAPBaseDN(), "cn=Users,dc=corp");
    EXPECT_EQ(manager.getADConfigPtr()->lDAPSearchScope(),
              ldap_base::Config::SearchScope::sub);
    EXPECT_EQ(manager.getADConfigPtr()->lDAPType(),
              ldap_base::Config::Type::ActiveDirectory);

    EXPECT_EQ(manager.getADConfigPtr()->userNameAttribute(), "uid");
    EXPECT_EQ(manager.getADConfigPtr()->groupNameAttribute(), "gid");
    EXPECT_EQ(manager.getADConfigPtr()->lDAPBindDNPassword(), "");
    EXPECT_EQ(manager.configBindPassword(), "MyLdap12");
    // change the password
    manager.getADConfigPtr()->lDAPBindDNPassword("MyLdap14");
    EXPECT_EQ(manager.getADConfigPtr()->lDAPBindDNPassword(), "");
    EXPECT_EQ(manager.configBindPassword(), "MyLdap14");
}

TEST_F(TestLDAPConfig, testDefaultObject)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCacertfile.c_str());

    EXPECT_CALL(manager, stopService("nslcd.service")).Times(2);

    manager.createDefaultObjects();

    EXPECT_NE(nullptr, manager.getADConfigPtr());
    EXPECT_NE(nullptr, manager.getOpenLdapConfigPtr());
    EXPECT_EQ(manager.getADConfigPtr()->lDAPType(),
              ldap_base::Config::Type::ActiveDirectory);
    EXPECT_EQ(manager.getOpenLdapConfigPtr()->lDAPType(),
              ldap_base::Config::Type::OpenLdap);
}
/*
TEST_F(TestLDAPConfig, testRestores)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr = new MockConfigMgr(
        bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
        dbusPersistentFilePath.c_str(), tlsCacertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(2);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(
        "ldap://9.194.251.138/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "uid", "gid");
    managerPtr->getConfigPtr()->enabled(false);

    EXPECT_TRUE(fs::exists(configFilePath));
    EXPECT_FALSE(managerPtr->getConfigPtr()->enabled());
    managerPtr->getConfigPtr()->enabled(true);
    // Delete LDAP configuration
    managerPtr->deleteObject();
    EXPECT_TRUE(fs::exists(configFilePath));
    // Restore from configFilePath
    managerPtr->restore(configFilePath.c_str());
    // validate restored properties
    EXPECT_TRUE(managerPtr->getConfigPtr()->enabled());
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.138/");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBindDN(), "cn=Users,dc=com");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBaseDN(), "cn=Users,dc=corp");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPSearchScope(),
              ldap_base::Config::SearchScope::sub);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPType(),
              ldap_base::Config::Type::ActiveDirectory);
    EXPECT_EQ(managerPtr->getConfigPtr()->userNameAttribute(), "uid");
    EXPECT_EQ(managerPtr->getConfigPtr()->groupNameAttribute(), "gid");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBindDNPassword(), "");
    EXPECT_EQ(managerPtr->configBindPassword(), "MyLdap12");
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testLDAPServerURI)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr = new MockConfigMgr(
        bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
        dbusPersistentFilePath.c_str(), tlsCacertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(3);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);

    managerPtr->createConfig(
        "ldap://9.194.251.138/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "attr1", "attr2");
    managerPtr->getConfigPtr()->enabled(true);

    // Change LDAP Server URI
    managerPtr->getConfigPtr()->lDAPServerURI("ldap://9.194.251.139/");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.139/");
    // Change LDAP Server URI
    EXPECT_THROW(
        managerPtr->getConfigPtr()->lDAPServerURI("ldaps://9.194.251.139/"),
        NoCACertificate);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.139/");
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP Server URI
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.139/");
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testLDAPBindDN)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr = new MockConfigMgr(
        bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
        dbusPersistentFilePath.c_str(), tlsCacertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(3);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);

    managerPtr->createConfig(
        "ldap://9.194.251.138/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "attr1", "attr2");
    managerPtr->getConfigPtr()->enabled(true);

    // Change LDAP BindDN
    managerPtr->getConfigPtr()->lDAPBindDN(
        "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBindDN(),
              "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    // Change LDAP BindDN
    EXPECT_THROW(
        {
            try
            {
                managerPtr->getConfigPtr()->lDAPBindDN("");
            }
            catch (const InvalidArgument& e)
            {
                throw;
            }
        },
        InvalidArgument);
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP BindDN after restoring
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBindDN(),
              "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testLDAPBaseDN)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr = new MockConfigMgr(
        bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
        dbusPersistentFilePath.c_str(), tlsCacertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(3);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(
        "ldap://9.194.251.138/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "attr1", "attr2");
    managerPtr->getConfigPtr()->enabled(true);
    // Change LDAP BaseDN
    managerPtr->getConfigPtr()->lDAPBaseDN(
        "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBaseDN(),
              "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    // Change LDAP BaseDN
    EXPECT_THROW(
        {
            try
            {
                managerPtr->getConfigPtr()->lDAPBaseDN("");
            }
            catch (const InvalidArgument& e)
            {
                throw;
            }
        },
        InvalidArgument);
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP BaseDN after restoring
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBaseDN(),
              "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testSearchScope)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr = new MockConfigMgr(
        bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
        dbusPersistentFilePath.c_str(), tlsCacertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(3);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(
        "ldap://9.194.251.138/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "attr1", "attr2");
    managerPtr->getConfigPtr()->enabled(true);

    // Change LDAP SearchScope
    managerPtr->getConfigPtr()->lDAPSearchScope(
        ldap_base::Config::SearchScope::one);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPSearchScope(),
              ldap_base::Config::SearchScope::one);
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP SearchScope after restoring
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPSearchScope(),
              ldap_base::Config::SearchScope::one);
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testLDAPType)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tslCacertFile;
    auto dbusPersistentFilePath =
        std::string(dir.c_str()) + "/" + dbusPersistFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr = new MockConfigMgr(
        bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
        dbusPersistentFilePath.c_str(), tlsCacertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(3);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(
        "ldap://9.194.251.138/", "cn=Users,dc=com", "cn=Users,dc=corp",
        "MyLdap12", ldap_base::Create::SearchScope::sub,
        ldap_base::Create::Type::ActiveDirectory, "attr1", "attr2");
    managerPtr->getConfigPtr()->enabled(true);

    // Change LDAP type
    managerPtr->getConfigPtr()->lDAPType(ldap_base::Config::Type::OpenLdap);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPType(),
              ldap_base::Config::Type::OpenLdap);
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP type after restoring
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPType(),
              ldap_base::Config::Type::OpenLdap);
    delete managerPtr;
}
*/
} // namespace ldap
} // namespace phosphor
