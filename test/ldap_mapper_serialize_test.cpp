#include "config.h"

#include "phosphor-ldap-config/ldap_config.hpp"
#include "phosphor-ldap-config/ldap_config_mgr.hpp"
#include "phosphor-ldap-config/ldap_mapper_entry.hpp"
#include "phosphor-ldap-config/ldap_mapper_serialize.hpp"

#include <sdbusplus/bus.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace phosphor
{
namespace ldap
{
namespace fs = std::filesystem;

class MockConfigMgr : public phosphor::ldap::ConfigMgr
{
  public:
    MockConfigMgr(sdbusplus::bus_t& bus, const char* path, const char* filePath,
                  const char* dbusPersistentFile, const char* caCertFile,
                  const char* certFile) :
        phosphor::ldap::ConfigMgr(bus, path, filePath, dbusPersistentFile,
                                  caCertFile, certFile)
    {}

    std::unique_ptr<Config>& getADConfigPtr()
    {
        return ADConfigPtr;
    }

    void createDefaultObjects()
    {
        phosphor::ldap::ConfigMgr::createDefaultObjects();
    }
};

class TestLDAPMapperSerialize : public testing::Test
{
  public:
    TestLDAPMapperSerialize() : bus(sdbusplus::bus::new_default()) {}

    void SetUp() override
    {
        char tmpldap[] = "/tmp/ldap_serialize_test.XXXXXX";
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

TEST_F(TestLDAPMapperSerialize, testSerializeMapperEntry)
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

    auto serializedPath = serialize(*entry, persistPath);
    EXPECT_TRUE(fs::exists(serializedPath));
}

TEST_F(TestLDAPMapperSerialize, testDeserializeMapperEntry)
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

    fs::path serializedPath;

    {
        auto entry1 = std::make_unique<LDAPMapperEntry>(
            bus, dbusPath.c_str(), persistPath.c_str(), groupName, privilege,
            *(manager.getADConfigPtr()));

        serializedPath = serialize(*entry1, persistPath);
        EXPECT_TRUE(fs::exists(serializedPath));
    }

    auto entry2 = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(),
        *(manager.getADConfigPtr()));

    bool result = deserialize(serializedPath, *entry2);
    EXPECT_TRUE(result);
    EXPECT_EQ(entry2->groupName(), groupName);
    EXPECT_EQ(entry2->privilege(), privilege);
}

TEST_F(TestLDAPMapperSerialize, testDeserializeNonExistentFile)
{
    auto configFilePath = std::string(dir.c_str()) + "/" + ldapConfFile;
    auto tlsCACertFilePath = std::string(dir.c_str()) + "/" + tlsCACertFile;
    auto tlsCertFilePath = std::string(dir.c_str()) + "/" + tlsCertFile;
    auto dbusPersistentFilePath = std::string(dir.c_str());

    MockConfigMgr manager(bus, LDAP_CONFIG_ROOT, configFilePath.c_str(),
                          dbusPersistentFilePath.c_str(),
                          tlsCACertFilePath.c_str(), tlsCertFilePath.c_str());
    manager.createDefaultObjects();

    size_t entryId = 1;
    auto dbusPath = std::string(LDAP_CONFIG_ROOT) +
                    "/active_directory/role_map/" + std::to_string(entryId);
    auto persistPath = dbusPersistentFilePath + dbusPath;

    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(),
        *(manager.getADConfigPtr()));

    fs::path nonExistentPath = dir / "non_existent_file";
    bool result = deserialize(nonExistentPath, *entry);
    EXPECT_FALSE(result);
}

TEST_F(TestLDAPMapperSerialize, testSerializeCreatesDirectory)
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

    auto persistPath = dbusPersistentFilePath + "/nested/path" + dbusPath;

    auto entry = std::make_unique<LDAPMapperEntry>(
        bus, dbusPath.c_str(), persistPath.c_str(), groupName, privilege,
        *(manager.getADConfigPtr()));

    auto serializedPath = serialize(*entry, persistPath);
    EXPECT_TRUE(fs::exists(serializedPath));
    EXPECT_TRUE(fs::exists(serializedPath.parent_path()));
}

} // namespace ldap
} // namespace phosphor
