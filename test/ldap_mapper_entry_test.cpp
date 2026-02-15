#include "config.h"

#include "phosphor-ldap-config/ldap_config.hpp"
#include "phosphor-ldap-config/ldap_config_mgr.hpp"
#include "phosphor-ldap-config/ldap_mapper_entry.hpp"

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace ldap
{
namespace fs = std::filesystem;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using PrivilegeMappingExists = sdbusplus::xyz::openbmc_project::User::Common::
    Error::PrivilegeMappingExists;

class MockConfigMgr : public phosphor::ldap::ConfigMgr
{
  public:
    MockConfigMgr(sdbusplus::bus_t& bus, const char* path, const char* filePath,
                  const char* dbusPersistentFile, const char* caCertFile,
                  const char* certFile) :
        phosphor::ldap::ConfigMgr(bus, path, filePath, dbusPersistentFile,
                                  caCertFile, certFile)
    {}
    MOCK_METHOD1(restartService, void(const std::string& service));
    MOCK_METHOD1(stopService, void(const std::string& service));

    std::unique_ptr<Config>& getADConfigPtr()
    {
        return ADConfigPtr;
    }

    void createDefaultObjects()
    {
        phosphor::ldap::ConfigMgr::createDefaultObjects();
    }
};

class TestLDAPMapperEntry : public testing::Test
{
  public:
    TestLDAPMapperEntry() : bus(sdbusplus::bus::new_default()) {}

    void SetUp() override
    {
        char tmpldap[] = "/tmp/ldap_mapper_test.XXXXXX";
        dir = fs::path(mkdtemp(tmpldap));

        fs::path tlsCacertFilePath{TLS_CACERT_PATH};
        tlsCACertFile = tlsCacertFilePath.filename().c_str();
        fs::path tlsCertFilePath{TLS_CERT_FILE};
        tlsCertFile = tlsCertFilePath.filename().c_str();
        fs::path confFilePath{LDAP_CONFIG_FILE};
        ldapConfFile = confFilePath.filename().c_str();

        std::fstream fs;
        fs.open(dir / tlsCACertFile, std::fstream::out);
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
    std::string tlsCACertFile;
    std::string tlsCertFile;
    std::string ldapConfFile;
    sdbusplus::bus_t bus;
};

TEST_F(TestLDAPMapperEntry, testMapperEntryCreation)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    std::string groupName = "testGroup";
    std::string privilege = "priv-admin";
    size_t entryId = 1;
    auto dbusPath = std::string(LDAP_CONFIG_ROOT) +
                    "/active_directory/role_map/" + std::to_string(entryId);
    auto persistPath = dbusPersistentFilePath + dbusPath;

    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(), groupName, privilege,
        *(manager.getADConfigPtr()));

    EXPECT_EQ(entry->groupName(), groupName);
    EXPECT_EQ(entry->privilege(), privilege);
}

TEST_F(TestLDAPMapperEntry, testMapperEntryGroupNameUpdate)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    std::string groupName = "testGroup";
    std::string privilege = "priv-admin";
    size_t entryId = 1;
    auto dbusPath = std::string(LDAP_CONFIG_ROOT) +
                    "/active_directory/role_map/" + std::to_string(entryId);
    auto persistPath = dbusPersistentFilePath + dbusPath;

    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(), groupName, privilege,
        *(manager.getADConfigPtr()));

    std::string newGroupName = "newTestGroup";
    entry->groupName(newGroupName);
    EXPECT_EQ(entry->groupName(), newGroupName);

    entry->groupName(newGroupName);
    EXPECT_EQ(entry->groupName(), newGroupName);
}

TEST_F(TestLDAPMapperEntry, testMapperEntryPrivilegeUpdate)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    std::string groupName = "testGroup";
    std::string privilege = "priv-admin";
    size_t entryId = 1;
    auto dbusPath = std::string(LDAP_CONFIG_ROOT) +
                    "/active_directory/role_map/" + std::to_string(entryId);
    auto persistPath = dbusPersistentFilePath + dbusPath;

    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(), groupName, privilege,
        *(manager.getADConfigPtr()));

    entry->privilege("priv-operator");
    EXPECT_EQ(entry->privilege(), "priv-operator");

    entry->privilege("priv-user");
    EXPECT_EQ(entry->privilege(), "priv-user");

    entry->privilege("priv-user");
    EXPECT_EQ(entry->privilege(), "priv-user");
}

TEST_F(TestLDAPMapperEntry, testMapperEntryInvalidPrivilege)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    std::string groupName = "testGroup";
    std::string privilege = "priv-admin";
    size_t entryId = 1;
    auto dbusPath = std::string(LDAP_CONFIG_ROOT) +
                    "/active_directory/role_map/" + std::to_string(entryId);
    auto persistPath = dbusPersistentFilePath + dbusPath;

    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(), groupName, privilege,
        *(manager.getADConfigPtr()));

    EXPECT_THROW(entry->privilege("invalid-privilege"), InvalidArgument);
    EXPECT_THROW(entry->privilege(""), InvalidArgument);
}

TEST_F(TestLDAPMapperEntry, testMapperEntryDelete)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    auto objPath = manager.getADConfigPtr()->create("admin", "priv-admin");
    std::string pathStr = objPath.str;
    EXPECT_FALSE(pathStr.empty());

    EXPECT_THROW(manager.getADConfigPtr()->checkPrivilegeMapper("admin"),
                 PrivilegeMappingExists);
}

TEST_F(TestLDAPMapperEntry, testMapperEntryEmptyGroupName)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    EXPECT_THROW(manager.getADConfigPtr()->create("", "priv-admin"),
                 InvalidArgument);
}

TEST_F(TestLDAPMapperEntry, testMapperEntryDuplicateGroupName)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    manager.getADConfigPtr()->create("admin", "priv-admin");

    EXPECT_THROW(manager.getADConfigPtr()->create("admin", "priv-operator"),
                 PrivilegeMappingExists);
}

} // namespace ldap
} // namespace phosphor
