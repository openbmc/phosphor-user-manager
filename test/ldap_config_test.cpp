#include "config.h"
#include "phosphor-ldap-config/ldap_configuration.hpp"

#include <experimental/filesystem>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <sdbusplus/bus.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <fstream>
#include <string>
#include <sys/types.h>

namespace phosphor
{
namespace ldap
{
namespace fs = std::experimental::filesystem;
namespace ldap_base = sdbusplus::xyz::openbmc_project::User::Ldap::server;
using Config = phosphor::ldap::Config;

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
        fs::path tlsCacertFilePath{TLS_CACERT_FILE};
        tlsCacertFile = tlsCacertFilePath.filename().c_str();
        fs::path tlsCertFilePath{TLS_CERT_FILE};
        tlsCertFile = tlsCertFilePath.filename().c_str();
        fs::path confFilePath{LDAP_CONFIG_FILE};
        ldapconfFile = confFilePath.filename().c_str();
        std::fstream fs;
        fs.open(dir / defaultNslcdFile, std::fstream::out);
        fs.close();
        fs.open(dir / nsSwitchFile, std::fstream::out);
        fs.close();
        fs.open(dir / LDAPNsSwitchFile, std::fstream::out);
        fs.close();
        fs.open(dir / linuxNsSwitchFile, std::fstream::out);
        fs.close();
        fs.open(dir / tlsCacertFile, std::fstream::out);
        fs.close();
        fs.open(dir / tlsCertFile, std::fstream::out);
        fs.close();
    }

    void TearDown() override
    {
        fs::remove_all(dir);
    }

  protected:
    fs::path dir;
    std::string tlsCacertFile;
    std::string tlsCertFile;
    std::string ldapconfFile;
    sdbusplus::bus::bus bus;
};

class MockConfigMgr : public phosphor::ldap::ConfigMgr
{
  public:
    MockConfigMgr(sdbusplus::bus::bus& bus, const char* path,
                  const char* filePath, const char* caCertfile,
                  const char* certfile) :
        phosphor::ldap::ConfigMgr(bus, path, filePath, caCertfile, certfile)
    {
    }
    MOCK_METHOD1(restartService, void(const std::string& service));
    MOCK_METHOD1(stopService, void(const std::string& service));
    std::unique_ptr<Config>& getConfigPtr()
    {
        return configPtr;
    }

    void restore(const char* filePath)
    {
        phosphor::ldap::ConfigMgr::restore(filePath);
        return;
    }

    friend class TestLDAPConfig;
};

TEST_F(TestLDAPConfig, testCreate)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(manager, restartService("nslcd.service")).Times(2);
    EXPECT_CALL(manager, restartService("nscd.service")).Times(1);
    manager.createConfig(false, "ldap://9.194.251.136/", "cn=Users,dc=com",
                         "cn=Users,dc=corp", "MyLdap12",
                         ldap_base::Create::SearchScope::sub,
                         ldap_base::Create::Type::ActiveDirectory);

    EXPECT_TRUE(fs::exists(configFilePath));
    EXPECT_EQ(manager.getConfigPtr()->lDAPServerURI(), "ldap://9.194.251.136/");
    EXPECT_EQ(manager.getConfigPtr()->secureLDAP(), false);
    EXPECT_EQ(manager.getConfigPtr()->lDAPBindDN(), "cn=Users,dc=com");
    EXPECT_EQ(manager.getConfigPtr()->lDAPBaseDN(), "cn=Users,dc=corp");
    EXPECT_EQ(manager.getConfigPtr()->lDAPBINDDNpassword(), "MyLdap12");
    EXPECT_EQ(manager.getConfigPtr()->lDAPSearchScope(),
              ldap_base::Config::SearchScope::sub);
    EXPECT_EQ(manager.getConfigPtr()->lDAPType(),
              ldap_base::Config::Type::ActiveDirectory);
}

TEST_F(TestLDAPConfig, testRestores)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;

    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(4);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
    EXPECT_TRUE(fs::exists(configFilePath));
    // Delete LDAP configuration
    managerPtr->deleteObject();
    EXPECT_TRUE(fs::exists(configFilePath));
    // Restore from configFilePath
    managerPtr->restore(configFilePath.c_str());
    // validate restored properties
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.138/");
    EXPECT_EQ(managerPtr->getConfigPtr()->secureLDAP(), false);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBindDN(), "cn=Users,dc=com");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBaseDN(), "cn=Users,dc=corp");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBINDDNpassword(), "MyLdap12");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPSearchScope(),
              ldap_base::Config::SearchScope::sub);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPType(),
              ldap_base::Config::Type::ActiveDirectory);
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testsecureLDAP)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath.c_str()))
    {
        fs::remove(configFilePath.c_str());
    }
    EXPECT_FALSE(fs::exists(configFilePath.c_str()));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());

    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(3);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(1);

    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
    // set secureLDAP to true
    managerPtr->getConfigPtr()->secureLDAP(true);
    EXPECT_EQ(managerPtr->getConfigPtr()->secureLDAP(), true);
    // Delete LDAP configuration
    managerPtr->deleteObject();
    managerPtr->restore(configFilePath.c_str());
    // Check secureLDAP after restoring
    EXPECT_EQ(managerPtr->getConfigPtr(), nullptr);

    delete managerPtr;
}

TEST_F(TestLDAPConfig, testLDAPServerURI)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(5);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);

    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
    // Change LDAP Server URI
    managerPtr->getConfigPtr()->lDAPServerURI("ldap://9.194.251.139");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.139");
    // Change LDAP Server URI
    EXPECT_THROW(
        {
            try
            {
                managerPtr->getConfigPtr()->lDAPServerURI(
                    "ldaps://9.194.251.139");
            }
            catch (const InvalidArgument& e)
            {
                throw;
            }
        },
        InvalidArgument);
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.139");
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP Server URI
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPServerURI(),
              "ldap://9.194.251.139");
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testLDAPBindDN)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(5);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);

    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
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
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(5);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
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

TEST_F(TestLDAPConfig, testLDAPBindDNpassword)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(5);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
    // Change LDAP BindDNpassword
    managerPtr->getConfigPtr()->lDAPBINDDNpassword(
        "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBINDDNpassword(),
              "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    // Delete LDAP configuration
    managerPtr->deleteObject();

    managerPtr->restore(configFilePath.c_str());
    // Check LDAP BindDNpassword after restoring
    EXPECT_EQ(managerPtr->getConfigPtr()->lDAPBINDDNpassword(),
              "cn=Administrator,cn=Users,dc=corp,dc=ibm,dc=com");
    delete managerPtr;
}

TEST_F(TestLDAPConfig, testSearchScope)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapconfFile;
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(5);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
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
    auto tlsCacertfile = std::string(dir.c_str()) + "/" + tlsCacertFile;
    auto tlsCertfile = std::string(dir.c_str()) + "/" + tlsCertFile;
    if (fs::exists(configFilePath))
    {
        fs::remove(configFilePath);
    }
    EXPECT_FALSE(fs::exists(configFilePath));
    MockConfigMgr* managerPtr =
        new MockConfigMgr(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          tlsCacertfile.c_str(), tlsCertfile.c_str());
    EXPECT_CALL(*managerPtr, restartService("nslcd.service")).Times(5);
    EXPECT_CALL(*managerPtr, restartService("nscd.service")).Times(2);
    managerPtr->createConfig(false, "ldap://9.194.251.138/", "cn=Users,dc=com",
                             "cn=Users,dc=corp", "MyLdap12",
                             ldap_base::Create::SearchScope::sub,
                             ldap_base::Create::Type::ActiveDirectory);
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
} // namespace ldap
} // namespace phosphor
