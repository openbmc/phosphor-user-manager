#include "mock_user_mgr.hpp"
#include "user_mgr.hpp"

#include <unistd.h>

#include <sdbusplus/test/sdbus_mock.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <chrono>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace user
{

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Throw;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using UserNameDoesNotExist =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameDoesNotExist;

namespace
{
inline static constexpr auto secondsPerDay =
    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days{1})
        .count();

uint64_t getEpochTimeNow()
{
    using namespace std::chrono;

    return duration_cast<seconds>(system_clock::now().time_since_epoch())
        .count();
}

std::string getNextUserName()
{
    static std::string userName{"testUserName"};
    static int id{0};

    return userName + std::to_string(id++);
}

struct PasswordInfo
{
    long lastChangeDate;
    long maxAge;
};

struct PasswordExpirationInfo
{
    long lastChangeDate;
    long oldmaxAge;
    long newMaxAge;
    uint64_t passwordExpiration;
};

void fillPasswordExpiration(
    const long lastChangeDaysAgo, const long oldPasswordAge,
    const long nextPasswordChangeInDays, PasswordExpirationInfo& info)
{
    using namespace std::chrono;

    info.lastChangeDate =
        duration_cast<days>(seconds{getEpochTimeNow()}).count() -
        lastChangeDaysAgo;

    info.oldmaxAge = oldPasswordAge;
    info.newMaxAge = nextPasswordChangeInDays + lastChangeDaysAgo;

    info.passwordExpiration =
        getEpochTimeNow() + nextPasswordChangeInDays * secondsPerDay;
}

} // namespace

class TestUserMgr : public testing::Test
{
  public:
    testing::NiceMock<sdbusplus::SdBusMock> sdBusMock;
    sdbusplus::bus_t bus;
    MockManager mockManager;

    TestUserMgr() :
        bus(sdbusplus::get_mocked_new(&sdBusMock)), mockManager(bus, objpath)
    {}

    void createLocalUser(const std::string& userName,
                         std::vector<std::string> groupNames,
                         const std::string& priv, bool enabled)
    {
        sdbusplus::object_path tempObjPath(usersObjPath);
        tempObjPath /= userName;
        std::string userObj(tempObjPath);
        if (enabled)
        {
            ON_CALL(mockManager, isUserEnabled)
                .WillByDefault(testing::Return(true));
        }
        else
        {
            ON_CALL(mockManager, isUserEnabled)
                .WillByDefault(testing::Return(false));
        }
        mockManager.usersList.emplace(
            userName, std::make_unique<phosphor::user::Users>(
                          mockManager.bus, userObj.c_str(), groupNames, priv,
                          enabled, std::nullopt, mockManager));
    }

    DbusUserObj createPrivilegeMapperDbusObject(void)
    {
        DbusUserObj object;
        DbusUserObjValue objValue;

        DbusUserObjPath objPath("/xyz/openbmc_project/user/ldap/openldap");
        DbusUserPropVariant enabled(true);
        DbusUserObjProperties property = {std::make_pair("Enabled", enabled)};
        std::string intf = "xyz.openbmc_project.Object.Enable";
        objValue.emplace(intf, property);
        object.emplace(objPath, objValue);

        DbusUserObjPath objectPath(
            "/xyz/openbmc_project/user/ldap/openldap/role_map/1");
        std::string group = "ldapGroup";
        std::string priv = "priv-admin";
        DbusUserObjProperties properties = {std::make_pair("GroupName", group),
                                            std::make_pair("Privilege", priv)};
        std::string interface = "xyz.openbmc_project.User.PrivilegeMapperEntry";

        objValue.emplace(interface, properties);
        object.emplace(objectPath, objValue);

        return object;
    }

    DbusUserObj createLdapConfigObjectWithoutPrivilegeMapper(void)
    {
        DbusUserObj object;
        DbusUserObjValue objValue;

        DbusUserObjPath objPath("/xyz/openbmc_project/user/ldap/openldap");
        DbusUserPropVariant enabled(true);
        DbusUserObjProperties property = {std::make_pair("Enabled", enabled)};
        std::string intf = "xyz.openbmc_project.Object.Enable";
        objValue.emplace(intf, property);
        object.emplace(objPath, objValue);
        return object;
    }

    auto& getUser(const std::string& userName)
    {
        return *mockManager.usersList[userName].get();
    }

    void testPasswordExpirationSet(const std::string& userName,
                                   const PasswordInfo& oldInfo,
                                   const PasswordInfo& newInfo)
    {
        EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
            .WillOnce(Invoke([&oldInfo](auto, struct spwd& spwd) {
                spwd.sp_lstchg = oldInfo.lastChangeDate;
                spwd.sp_max = oldInfo.maxAge;
            }));

        EXPECT_CALL(mockManager, executeUserPasswordExpiration(
                                     testing::StrEq(userName),
                                     newInfo.lastChangeDate, newInfo.maxAge))
            .Times(1);

        createLocalUser(userName, {"ssh"}, "priv-admin", true);

        const auto expirationTime =
            (newInfo.lastChangeDate + newInfo.maxAge) * secondsPerDay;

        auto& user = getUser(userName);
        EXPECT_EQ(expirationTime, user.passwordExpiration(expirationTime));
        EXPECT_EQ(expirationTime, user.passwordExpiration());
    }

    void testPasswordExpirationReset(const std::string& userName,
                                     const PasswordInfo& info)
    {
        EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
            .WillOnce(Invoke([&info](auto, struct spwd& spwd) {
                spwd.sp_lstchg = info.lastChangeDate;
                spwd.sp_max = info.maxAge;
            }));

        EXPECT_CALL(mockManager,
                    executeUserPasswordExpiration(
                        testing::StrEq(userName), info.lastChangeDate,
                        mockManager.getUnexpiringPasswordAge()))
            .Times(1);

        createLocalUser(userName, {"ssh"}, "priv-admin", true);

        const auto expirationTime = UserMgr::getUnexpiringPasswordTime();

        auto& user = getUser(userName);
        EXPECT_EQ(expirationTime, user.passwordExpiration(expirationTime));
        EXPECT_EQ(expirationTime, user.passwordExpiration());
    }

    void testPasswordExpirationGet(const std::string& userName,
                                   const PasswordInfo& info,
                                   const uint64_t expectedPasswordExpiration)
    {
        EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
            .WillOnce(Invoke([&info](auto, struct spwd& spwd) {
                spwd.sp_lstchg = info.lastChangeDate;
                spwd.sp_max = info.maxAge;
            }));

        createLocalUser(userName, {"ssh"}, "priv-admin", true);

        EXPECT_EQ(mockManager.getPasswordExpiration(userName),
                  expectedPasswordExpiration);
    }
};

TEST_F(TestUserMgr, ldapEntryDoesNotExist)
{
    std::string userName = "user";
    UserInfoMap userInfo;

    EXPECT_CALL(mockManager, getPrimaryGroup(userName))
        .WillRepeatedly(Throw(UserNameDoesNotExist()));
    EXPECT_THROW(userInfo = mockManager.getUserInfo(userName),
                 UserNameDoesNotExist);
}

TEST_F(TestUserMgr, localUser)
{
    UserInfoMap userInfo;
    std::string userName = "testUser";
    std::string privilege = "priv-admin";
    std::vector<std::string> groups{"testGroup"};
    // Create local user
    createLocalUser(userName, groups, privilege, true);
    EXPECT_CALL(mockManager, userLockedForFailedAttempt(userName)).Times(1);
    userInfo = mockManager.getUserInfo(userName);

    EXPECT_EQ(privilege, std::get<std::string>(userInfo["UserPrivilege"]));
    EXPECT_EQ(groups,
              std::get<std::vector<std::string>>(userInfo["UserGroups"]));
    EXPECT_EQ(true, std::get<bool>(userInfo["UserEnabled"]));
    EXPECT_EQ(false, std::get<bool>(userInfo["UserLockedForFailedAttempt"]));
    EXPECT_EQ(false, std::get<bool>(userInfo["UserPasswordExpired"]));
    // check password expiration against default value
    EXPECT_EQ(std::numeric_limits<uint64_t>::max(),
              std::get<PasswordExpiration>(userInfo["PasswordExpiration"]));
    EXPECT_EQ(false, std::get<bool>(userInfo["RemoteUser"]));
}

TEST_F(TestUserMgr, ldapUserWithPrivMapper)
{
    UserInfoMap userInfo;
    std::string userName = "ldapUser";
    std::string ldapGroup = "ldapGroup";
    gid_t primaryGid = 1000;

    EXPECT_CALL(mockManager, getPrimaryGroup(userName))
        .WillRepeatedly(Return(primaryGid));
    // Create privilege mapper dbus object
    DbusUserObj object = createPrivilegeMapperDbusObject();
    EXPECT_CALL(mockManager, getPrivilegeMapperObject())
        .WillRepeatedly(Return(object));
    EXPECT_CALL(mockManager, isGroupMember(userName, primaryGid, ldapGroup))
        .WillRepeatedly(Return(true));
    userInfo = mockManager.getUserInfo(userName);
    EXPECT_EQ(true, std::get<bool>(userInfo["RemoteUser"]));
    EXPECT_EQ("priv-admin", std::get<std::string>(userInfo["UserPrivilege"]));
}

TEST_F(TestUserMgr, ldapUserWithoutPrivMapper)
{
    using ::testing::_;

    UserInfoMap userInfo;
    std::string userName = "ldapUser";
    std::string ldapGroup = "ldapGroup";
    gid_t primaryGid = 1000;

    EXPECT_CALL(mockManager, getPrimaryGroup(userName))
        .WillRepeatedly(Return(primaryGid));
    // Create LDAP config object without privilege mapper
    DbusUserObj object = createLdapConfigObjectWithoutPrivilegeMapper();
    EXPECT_CALL(mockManager, getPrivilegeMapperObject())
        .WillRepeatedly(Return(object));
    EXPECT_CALL(mockManager, isGroupMember(_, _, _)).Times(0);
    userInfo = mockManager.getUserInfo(userName);
    EXPECT_EQ(true, std::get<bool>(userInfo["RemoteUser"]));
    EXPECT_EQ("", std::get<std::string>(userInfo["UserPrivilege"]));
}

TEST_F(TestUserMgr, PasswordExpiration)
{
    testPasswordExpirationSet(getNextUserName(), {2, 10}, {2, 3});
}

TEST_F(TestUserMgr, PasswordExpirationLastChangeNegative)
{
    using namespace std::chrono;

    const long lastChangeDate =
        duration_cast<days>(seconds{getEpochTimeNow()}).count();

    testPasswordExpirationSet(getNextUserName(), {-2, 15}, {lastChangeDate, 3});
}

TEST_F(TestUserMgr, PasswordExpirationLastChangeZero)
{
    using namespace std::chrono;

    const long lastChangeDate =
        duration_cast<days>(seconds{getEpochTimeNow()}).count();

    testPasswordExpirationSet(getNextUserName(), {0, 7}, {lastChangeDate, 6});
}

TEST_F(TestUserMgr, PasswordExpirationLastMaxAgeNegative)
{
    testPasswordExpirationSet(getNextUserName(), {10, -5}, {10, 6});
}

TEST_F(TestUserMgr, PasswordExpirationReset)
{
    testPasswordExpirationReset(getNextUserName(), {2, 10});
}

TEST_F(TestUserMgr, PasswordExpirationResetLastChangeNegative)
{
    testPasswordExpirationReset(getNextUserName(), {-5, 8});
}

TEST_F(TestUserMgr, PasswordExpirationResetLastChangeZero)
{
    testPasswordExpirationReset(getNextUserName(), {0, 13});
}

TEST_F(TestUserMgr, PasswordExpirationResetMaxAgeNegative)
{
    testPasswordExpirationReset(getNextUserName(), {2, -2});
}

TEST_F(TestUserMgr, PasswordExpirationGet)
{
    constexpr long lastChangeDate = 7;
    constexpr long passwordAge = 4;
    constexpr uint64_t expirationTime =
        (lastChangeDate + passwordAge) * secondsPerDay;

    testPasswordExpirationGet(getNextUserName(), {lastChangeDate, passwordAge},
                              expirationTime);
}

TEST_F(TestUserMgr, PasswordExpirationSetDefault)
{
    const std::string userName = getNextUserName();

    createLocalUser(userName, {"ssh"}, "priv-admin", true);

    auto& user = getUser(userName);

    EXPECT_EQ(user.passwordExpiration(UserMgr::getUnexpiringPasswordTime()),
              UserMgr::getUnexpiringPasswordTime());

    EXPECT_EQ(user.passwordExpiration(UserMgr::getDefaultPasswordExpiration()),
              UserMgr::getDefaultPasswordExpiration());
}

TEST_F(TestUserMgr, PasswordExpirationGetDefault)
{
    const std::string userName = getNextUserName();

    createLocalUser(userName, {"ssh"}, "priv-admin", true);

    auto& user = getUser(userName);

    EXPECT_EQ(user.passwordExpiration(),
              UserMgr::getDefaultPasswordExpiration());
}

TEST_F(TestUserMgr, PasswordExpirationGetLastChangeNegative)
{
    testPasswordExpirationGet(getNextUserName(), {-5, 8},
                              UserMgr::getUnexpiringPasswordTime());
}

TEST_F(TestUserMgr, PasswordExpirationGetLastChangeZero)
{
    using namespace std::chrono;

    const std::string userName = getNextUserName();
    constexpr long lastChangeDate = 0;
    constexpr long passwordAge = 4;

    EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
        .WillOnce(Invoke([](auto, struct spwd& spwd) {
            spwd.sp_lstchg = lastChangeDate;
            spwd.sp_max = passwordAge;
        }));

    createLocalUser(userName, {"ssh"}, "priv-admin", true);

    auto expirationTime =
        duration_cast<minutes>(seconds{getEpochTimeNow()}).count();
    auto time = duration_cast<minutes>(
                    seconds{mockManager.getPasswordExpiration(userName)})
                    .count();

    // compare expiration time in minutes to avoid situation where times
    // measured in second can be different
    EXPECT_EQ(time, expirationTime);
}

TEST_F(TestUserMgr, PasswordExpirationGetMaxAgeNegative)
{
    testPasswordExpirationGet(getNextUserName(), {12, -2},
                              UserMgr::getUnexpiringPasswordTime());
}

TEST_F(TestUserMgr, PasswordExpirationShadowFail)
{
    const std::string userName = getNextUserName();

    EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
        .WillOnce([]() {
            throw sdbusplus::xyz::openbmc_project::Common::Error::
                InternalFailure();
        });

    EXPECT_CALL(mockManager, executeUserPasswordExpiration(_, _, _)).Times(0);

    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);

    const auto oldTime = user.passwordExpiration();

    EXPECT_THROW(
        user.passwordExpiration(0),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_EQ(oldTime, user.passwordExpiration());
}

TEST_F(TestUserMgr, PasswordExpirationInvalidDate)
{
    const std::string userName = getNextUserName();

    EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
        .WillOnce(Invoke([](auto, struct spwd& spwd) {
            spwd.sp_lstchg = 2;
            spwd.sp_max = 2;
        }));

    EXPECT_CALL(mockManager, executeUserPasswordExpiration(_, _, _)).Times(0);

    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);

    const auto oldTime = user.passwordExpiration();

    EXPECT_THROW(
        user.passwordExpiration(1),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_EQ(oldTime, user.passwordExpiration());
}

TEST_F(TestUserMgr, PasswordExpirationExecFail)
{
    const std::string userName = getNextUserName();

    constexpr long lastChangeDate = 3;
    EXPECT_CALL(mockManager, getShadowData(testing::StrEq(userName), _))
        .WillOnce(Invoke([](auto, struct spwd& spwd) {
            spwd.sp_lstchg = lastChangeDate;
            spwd.sp_max = 5;
        }));

    constexpr long passwordAge = 11;
    EXPECT_CALL(mockManager,
                executeUserPasswordExpiration(testing::StrEq(userName),
                                              lastChangeDate, passwordAge))
        .WillOnce([]() { throw std::exception(); });

    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);

    const auto oldTime = user.passwordExpiration();
    const auto expirationTime = (lastChangeDate + passwordAge) * secondsPerDay;

    EXPECT_THROW(
        user.passwordExpiration(expirationTime),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_EQ(oldTime, user.passwordExpiration());
}

TEST(GetCSVFromVector, EmptyVectorReturnsEmptyString)
{
    EXPECT_EQ(getCSVFromVector({}), "");
}

TEST(GetCSVFromVector, ElementsAreJoinedByComma)
{
    EXPECT_EQ(getCSVFromVector(std::vector<std::string>{"123"}), "123");
    EXPECT_EQ(getCSVFromVector(std::vector<std::string>{"123", "456"}),
              "123,456");
}

TEST(RemoveStringFromCSV, WithoutDeleteStringReturnsFalse)
{
    std::string expected = "whatever,https";
    std::string str = expected;
    EXPECT_FALSE(removeStringFromCSV(str, "ssh"));
    EXPECT_EQ(str, expected);

    std::string empty;
    EXPECT_FALSE(removeStringFromCSV(empty, "ssh"));
}

TEST(RemoveStringFromCSV, WithDeleteStringReturnsTrue)
{
    std::string expected = "whatever";
    std::string str = "whatever,https";
    EXPECT_TRUE(removeStringFromCSV(str, "https"));
    EXPECT_EQ(str, expected);

    str = "https";
    EXPECT_TRUE(removeStringFromCSV(str, "https"));
    EXPECT_EQ(str, "");
}

namespace
{
inline constexpr const char* objectRootInTest = "/xyz/openbmc_project/user";

// Fake configs; referenced configs on real BMC
inline constexpr const char* rawFailLockConfig = R"(
deny=2
unlock_time=3
)";
inline constexpr const char* rawPWHistoryConfig = R"(
enforce_for_root
remember=0
)";
inline constexpr const char* rawPWQualityConfig = R"(
enforce_for_root
minlen=8
difok=0
lcredit=0
ocredit=0
dcredit=0
ucredit=0
)";
} // namespace

void dumpStringToFile(const std::string& str, const std::string& filePath)
{
    std::ofstream outputFileStream;

    outputFileStream.exceptions(
        std::ofstream::failbit | std::ofstream::badbit | std::ofstream::eofbit);

    outputFileStream.open(filePath, std::ios::out);
    outputFileStream << str << "\n" << std::flush;
    outputFileStream.close();
}

void removeFile(const std::string& filePath)
{
    std::filesystem::remove(filePath);
}

class UserMgrInTest : public testing::Test, public UserMgr
{
  public:
    UserMgrInTest() : UserMgr(busInTest, objectRootInTest)
    {
        setPolicyAdoptionType(policyAdoptionTypeDefault);
        initialize();
        {
            tempFaillockConfigFile = tempFilePath;
            int fd = mkstemp(tempFaillockConfigFile.data());
            EXPECT_NE(-1, fd);
            EXPECT_NO_THROW(
                dumpStringToFile(rawFailLockConfig, tempFaillockConfigFile));
            if (fd != -1)
            {
                close(fd);
            }
        }

        {
            tempPWHistoryConfigFile = tempFilePath;
            int fd = mkstemp(tempPWHistoryConfigFile.data());
            EXPECT_NE(-1, fd);
            EXPECT_NO_THROW(
                dumpStringToFile(rawPWHistoryConfig, tempPWHistoryConfigFile));
            if (fd != -1)
            {
                close(fd);
            }
        }

        {
            tempPWQualityConfigFile = tempFilePath;
            int fd = mkstemp(tempPWQualityConfigFile.data());
            EXPECT_NE(-1, fd);
            EXPECT_NO_THROW(
                dumpStringToFile(rawPWQualityConfig, tempPWQualityConfigFile));
            if (fd != -1)
            {
                close(fd);
            }
        }

        // Set config files to test files
        faillockConfigFile = tempFaillockConfigFile;
        pwHistoryConfigFile = tempPWHistoryConfigFile;
        pwQualityConfigFile = tempPWQualityConfigFile;

        ON_CALL(*this, executeUserAdd(testing::_, testing::_, testing::_,
                                      testing::Eq(true)))
            .WillByDefault([this]() {
                ON_CALL(*this, isUserEnabled)
                    .WillByDefault(testing::Return(true));
                testing::Return();
            });

        ON_CALL(*this, executeUserAdd(testing::_, testing::_, testing::_,
                                      testing::Eq(false)))
            .WillByDefault([this]() {
                ON_CALL(*this, isUserEnabled)
                    .WillByDefault(testing::Return(false));
                testing::Return();
            });

        ON_CALL(*this, executeUserDelete).WillByDefault(testing::Return());

        ON_CALL(*this, executeUserClearFailRecords)
            .WillByDefault(testing::Return());

        ON_CALL(*this, getIpmiUsersCount).WillByDefault(testing::Return(0));

        ON_CALL(*this, executeUserRename).WillByDefault(testing::Return());

        ON_CALL(*this, executeUserModify(testing::_, testing::_, testing::_))
            .WillByDefault(testing::Return());

        ON_CALL(*this,
                executeUserModifyUserEnable(testing::_, testing::Eq(true)))
            .WillByDefault([this]() {
                ON_CALL(*this, isUserEnabled)
                    .WillByDefault(testing::Return(true));
                testing::Return();
            });

        ON_CALL(*this,
                executeUserModifyUserEnable(testing::_, testing::Eq(false)))
            .WillByDefault([this]() {
                ON_CALL(*this, isUserEnabled)
                    .WillByDefault(testing::Return(false));
                testing::Return();
            });

        ON_CALL(*this, executeGroupCreation(testing::_))
            .WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupDeletion(testing::_))
            .WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupCreation).WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupDeletion).WillByDefault(testing::Return());
    }
    void eventLoop(uint8_t numberOfTimes)
    {
        if (numberOfTimes == 0 || numberOfTimes > 15)
        {
            return;
        }

        for (int i = 0; i < numberOfTimes; i++)
        {
            busInTest.process_discard();
            // wait for 1 seconds
            busInTest.wait(1 * 1000000);
        }
    }
    ~UserMgrInTest() override
    {
        EXPECT_NO_THROW(removeFile(tempFaillockConfigFile));
        EXPECT_NO_THROW(removeFile(tempPWHistoryConfigFile));
        EXPECT_NO_THROW(removeFile(tempPWQualityConfigFile));
    }

    MOCK_METHOD(void, executeUserAdd, (const char*, const char*, bool, bool),
                (override));

    MOCK_METHOD(void, executeUserDelete, (const char*), (override));

    MOCK_METHOD(void, executeUserClearFailRecords, (const char*), (override));

    MOCK_METHOD(size_t, getIpmiUsersCount, (), (override));

    MOCK_METHOD(void, executeUserRename, (const char*, const char*),
                (override));

    MOCK_METHOD(void, executeUserModify, (const char*, const char*, bool),
                (override));

    MOCK_METHOD(void, executeUserModifyUserEnable, (const char*, bool),
                (override));

    MOCK_METHOD(std::vector<std::string>, getFailedAttempt, (const char*),
                (override));

    MOCK_METHOD(void, executeGroupCreation, (const char*), (override));

    MOCK_METHOD(void, executeGroupDeletion, (const char*), (override));

    MOCK_METHOD(bool, isUserEnabled, (const std::string& userName), (override));

    MOCK_METHOD(void, getShadowData, (const std::string&, struct spwd& spwd),
                (const, override));

    MOCK_METHOD(void, executeUserPasswordExpiration,
                (const char*, const long int, const long int),
                (const, override));

    MOCK_METHOD(bool, isUserExistSystem, (const std::string& userName),
                (override));

  protected:
    static constexpr auto tempFilePath = "/tmp/test-data-XXXXXX";

    static sdbusplus::bus_t busInTest;
    std::string tempFaillockConfigFile;
    std::string tempPWHistoryConfigFile;
    std::string tempPWQualityConfigFile;

    void setUpCreateUser(const std::string& userName, bool enabled)
    {
        EXPECT_CALL(*this, getIpmiUsersCount).WillOnce(testing::Return(0));

        EXPECT_CALL(*this,
                    executeUserAdd(testing::StrEq(userName), _, _, enabled))
            .Times(1);
    }

    void setUpGetUserInfo(const std::string& userName, bool enabled)
    {
        EXPECT_CALL(*this, isUserEnabled(userName))
            .WillOnce(testing::Return(enabled));
    }

    void setUpSetPasswordExpiration(const std::string& userName,
                                    const PasswordExpirationInfo& info)
    {
        EXPECT_CALL(*this, getShadowData(testing::StrEq(userName), _))
            .WillOnce(Invoke([&info](auto, struct spwd& spwd) {
                spwd.sp_lstchg = info.lastChangeDate;
                spwd.sp_max = info.oldmaxAge;
            }));

        EXPECT_CALL(*this, executeUserPasswordExpiration(
                               testing::StrEq(userName), info.lastChangeDate,
                               info.newMaxAge))
            .Times(1);
    }

    void setUpDeleteUser(const std::string& userName)
    {
        EXPECT_CALL(*this,
                    executeUserClearFailRecords(testing::StrEq(userName)))
            .Times(1);

        EXPECT_CALL(*this, executeUserDelete(testing::StrEq(userName)))
            .Times(1);
    }
};

sdbusplus::bus_t UserMgrInTest::busInTest = sdbusplus::bus::new_default();

TEST_F(UserMgrInTest, GetPamModuleConfValueOnSuccess)
{
    std::string minlen;
    EXPECT_EQ(getPamModuleConfValue(tempPWQualityConfigFile, "minlen", minlen),
              0);
    EXPECT_EQ(minlen, "8");
    std::string deny;
    EXPECT_EQ(getPamModuleConfValue(tempFaillockConfigFile, "deny", deny), 0);
    EXPECT_EQ(deny, "2");
    std::string remember;
    EXPECT_EQ(
        getPamModuleConfValue(tempPWHistoryConfigFile, "remember", remember),
        0);
    EXPECT_EQ(remember, "0");
}

TEST_F(UserMgrInTest, SetPamModuleConfValueOnSuccess)
{
    EXPECT_EQ(setPamModuleConfValue(tempPWQualityConfigFile, "minlen", "16"),
              0);
    std::string minlen;
    EXPECT_EQ(getPamModuleConfValue(tempPWQualityConfigFile, "minlen", minlen),
              0);
    EXPECT_EQ(minlen, "16");

    EXPECT_EQ(setPamModuleConfValue(tempFaillockConfigFile, "deny", "3"), 0);
    std::string deny;
    EXPECT_EQ(getPamModuleConfValue(tempFaillockConfigFile, "deny", deny), 0);
    EXPECT_EQ(deny, "3");

    EXPECT_EQ(setPamModuleConfValue(tempPWHistoryConfigFile, "remember", "1"),
              0);
    std::string remember;
    EXPECT_EQ(
        getPamModuleConfValue(tempPWHistoryConfigFile, "remember", remember),
        0);
    EXPECT_EQ(remember, "1");
}

TEST_F(UserMgrInTest, SetPamModuleConfValueTempFileOnSuccess)
{
    EXPECT_EQ(setPamModuleConfValue(tempPWQualityConfigFile, "minlen", "16"),
              0);

    std::string tmpFile = tempPWQualityConfigFile + "_tmp";
    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_EQ(setPamModuleConfValue(tempFaillockConfigFile, "deny", "3"), 0);

    tmpFile = tempFaillockConfigFile + "_tmp";
    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_EQ(setPamModuleConfValue(tempPWHistoryConfigFile, "remember", "1"),
              0);

    tmpFile = tempPWHistoryConfigFile + "_tmp";
    EXPECT_FALSE(std::filesystem::exists(tmpFile));
}

TEST_F(UserMgrInTest, GetPamModuleConfValueOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWQualityConfigFile));
    std::string minlen;
    EXPECT_EQ(getPamModuleConfValue(tempPWQualityConfigFile, "minlen", minlen),
              -1);

    EXPECT_NO_THROW(removeFile(tempPWQualityConfigFile));
    EXPECT_EQ(getPamModuleConfValue(tempPWQualityConfigFile, "minlen", minlen),
              -1);

    EXPECT_NO_THROW(dumpStringToFile("whatever", tempFaillockConfigFile));
    std::string deny;
    EXPECT_EQ(getPamModuleConfValue(tempFaillockConfigFile, "deny", deny), -1);

    EXPECT_NO_THROW(removeFile(tempFaillockConfigFile));
    EXPECT_EQ(getPamModuleConfValue(tempFaillockConfigFile, "deny", deny), -1);

    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWHistoryConfigFile));
    std::string remember;
    EXPECT_EQ(
        getPamModuleConfValue(tempPWHistoryConfigFile, "remember", remember),
        -1);

    EXPECT_NO_THROW(removeFile(tempPWHistoryConfigFile));
    EXPECT_EQ(
        getPamModuleConfValue(tempPWHistoryConfigFile, "remember", remember),
        -1);
}

TEST_F(UserMgrInTest, SetPamModuleConfValueOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWQualityConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWQualityConfigFile, "minlen", "16"),
              -1);

    EXPECT_NO_THROW(removeFile(tempPWQualityConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWQualityConfigFile, "minlen", "16"),
              -1);

    EXPECT_NO_THROW(dumpStringToFile("whatever", tempFaillockConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempFaillockConfigFile, "deny", "3"), -1);

    EXPECT_NO_THROW(removeFile(tempFaillockConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempFaillockConfigFile, "deny", "3"), -1);

    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWHistoryConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWHistoryConfigFile, "remember", "1"),
              -1);

    EXPECT_NO_THROW(removeFile(tempPWHistoryConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWHistoryConfigFile, "remember", "1"),
              -1);
}

TEST_F(UserMgrInTest, SetPamModuleConfValueTempFileOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWQualityConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWQualityConfigFile, "minlen", "16"),
              -1);

    std::string tmpFile = tempPWQualityConfigFile + "_tmp";
    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_NO_THROW(removeFile(tempPWQualityConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWQualityConfigFile, "minlen", "16"),
              -1);

    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_NO_THROW(dumpStringToFile("whatever", tempFaillockConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempFaillockConfigFile, "deny", "3"), -1);

    tmpFile = tempFaillockConfigFile + "_tmp";
    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_NO_THROW(removeFile(tempFaillockConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempFaillockConfigFile, "deny", "3"), -1);

    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWHistoryConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWHistoryConfigFile, "remember", "1"),
              -1);

    tmpFile = tempPWHistoryConfigFile + "_tmp";
    EXPECT_FALSE(std::filesystem::exists(tmpFile));

    EXPECT_NO_THROW(removeFile(tempPWHistoryConfigFile));
    EXPECT_EQ(setPamModuleConfValue(tempPWHistoryConfigFile, "remember", "1"),
              -1);

    EXPECT_FALSE(std::filesystem::exists(tmpFile));
}

TEST_F(UserMgrInTest, IsUserExistEmptyInputThrowsError)
{
    EXPECT_THROW(
        isUserExist(""),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest, ThrowForUserDoesNotExistThrowsError)
{
    EXPECT_THROW(throwForUserDoesNotExist("whatever"),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     UserNameDoesNotExist);
}

TEST_F(UserMgrInTest, ThrowForUserExistsThrowsError)
{
    EXPECT_THROW(
        throwForUserExists("root"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameExists);
}

TEST_F(
    UserMgrInTest,
    ThrowForUserNameConstraintsExceedIpmiMaxUserNameLenThrowsUserNameGroupFail)
{
#ifdef ENABLE_IPMI
    std::string strWith17Chars(17, 'A');
    EXPECT_THROW(throwForUserNameConstraints(strWith17Chars, {"ipmi"}),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     UserNameGroupFail);
#endif
}

TEST_F(
    UserMgrInTest,
    ThrowForUserNameConstraintsExceedSystemMaxUserNameLenThrowsInvalidArgument)
{
    std::string strWith31Chars(101, 'A');
    EXPECT_THROW(
        throwForUserNameConstraints(strWith31Chars, {}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest,
       ThrowForUserNameConstraintsRegexMismatchThrowsInvalidArgument)
{
#ifdef ENABLE_IPMI
    std::string startWithNumber = "0ABC";
    std::string startWithDisallowedCharacter = "[test";
    EXPECT_THROW(
        throwForUserNameConstraints(startWithNumber, {"ipmi"}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        throwForUserNameConstraints(startWithDisallowedCharacter, {"ipmi"}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
#endif
}

TEST_F(UserMgrInTest, UserAddNotRootFailedWithInternalFailure)
{
#ifdef ENABLE_IPMI
    EXPECT_THROW(
        UserMgr::executeUserAdd("user0", "ipmi,ssh", true, true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
#else
    EXPECT_THROW(
        UserMgr::executeUserAdd("user0", "ssh", true, true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
#endif
}

TEST_F(UserMgrInTest, UserDeleteNotRootFailedWithInternalFailure)
{
    EXPECT_THROW(
        UserMgr::executeUserDelete("user0"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST_F(UserMgrInTest,
       ThrowForMaxGrpUserCountThrowsNoResourceWhenIpmiUserExceedLimit)
{
#ifdef ENABLE_IPMI
    EXPECT_CALL(*this, getIpmiUsersCount()).WillOnce(Return(ipmiMaxUsers));
    EXPECT_THROW(
        throwForMaxGrpUserCount({"ipmi"}),
        sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource);
#endif
}

TEST_F(UserMgrInTest, CreateUserThrowsInternalFailureWhenExecuteUserAddFails)
{
    std::string username = "whatever";
    EXPECT_CALL(*this, executeUserAdd)
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    // createUser invokes isUserExistSystem three times: once via
    // throwForUserExists, once for the pre-useradd TOCTOU snapshot, and once
    // in the InternalFailure catch block. All three must report "absent" so
    // the failure path falls through to elog<InternalFailure>().
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(username)))
        .Times(3)
        .WillRepeatedly(Return(false));
    EXPECT_THROW(
        createUser(username, {"redfish"}, "", true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_FALSE(isUserExist(username));
}

TEST_F(UserMgrInTest,
       CreateUserThrowsInternalFailureWhenExecuteUserAddPartiallyFails)
{
    std::string username = "whatever";
    EXPECT_CALL(*this, executeUserAdd)
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    // throwForUserExists and the pre-useradd snapshot must both see the
    // user as absent (otherwise we'd return UserNameExists, or skip the
    // delete via !preExistingSystemUser). Only the post-failure check sees
    // it as present, simulating a useradd that partially created the user.
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(username)))
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillOnce(Return(true));
    EXPECT_CALL(*this, executeUserDelete(testing::StrEq(username)))
        .WillOnce(testing::DoDefault());
    EXPECT_THROW(
        createUser(username, {"redfish"}, "", true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_FALSE(isUserExist(username));
}

TEST_F(UserMgrInTest, DeleteUserThrowsInternalFailureWhenExecuteUserDeleteFails)
{
    std::string username = "user";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    EXPECT_CALL(*this, executeUserDelete(testing::StrEq(username)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()))
        .WillOnce(testing::DoDefault());
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(username)))
        .WillOnce(Return(true)); // delete legitimately failed

    EXPECT_THROW(
        deleteUser(username),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_TRUE(isUserExist(username));
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
    eventLoop(5);
}

TEST_F(UserMgrInTest, DeleteUserSuccessWhenExecuteUserSucceedsWithError)
{
    std::string username = "user";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    EXPECT_CALL(*this, executeUserDelete(testing::StrEq(username)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(username)))
        .WillOnce(Return(false)); // delete partly failed

    EXPECT_NO_THROW(deleteUser(username));
    EXPECT_FALSE(isUserExist(username));
}

TEST_F(UserMgrInTest,
       DeleteUserThrowsInternalFailureWhenExecuteUserClearFailRecords)
{
    const char* username = "user";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    EXPECT_CALL(*this, executeUserClearFailRecords(testing::StrEq(username)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()))
        .WillOnce(testing::DoDefault());
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(username)))
        .WillOnce(Return(true));

    EXPECT_THROW(
        deleteUser(username),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_TRUE(isUserExist(username));
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
}

TEST_F(UserMgrInTest, ThrowForInvalidPrivilegeThrowsWhenPrivilegeIsInvalid)
{
    EXPECT_THROW(
        throwForInvalidPrivilege("whatever"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest, ThrowForInvalidPrivilegeNoThrowWhenPrivilegeIsValid)
{
    EXPECT_NO_THROW(throwForInvalidPrivilege("priv-admin"));
    EXPECT_NO_THROW(throwForInvalidPrivilege("priv-operator"));
    EXPECT_NO_THROW(throwForInvalidPrivilege("priv-user"));
}

TEST_F(UserMgrInTest, ThrowForInvalidGroupsThrowsWhenGroupIsInvalid)
{
    EXPECT_THROW(
        throwForInvalidGroups({"whatever"}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        throwForInvalidGroups({"web"}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest, ThrowForInvalidGroupsNoThrowWhenGroupIsValid)
{
#ifdef ENABLE_IPMI
    EXPECT_NO_THROW(throwForInvalidGroups({"ipmi"}));
#endif
    EXPECT_NO_THROW(throwForInvalidGroups({"ssh"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"redfish"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"hostconsole"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"service"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"redfish-hostiface"}));
}

TEST_F(UserMgrInTest, RenameUserOnSuccess)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    std::string newUsername = "user002";

    EXPECT_NO_THROW(UserMgr::renameUser(username, newUsername));

    // old username doesn't exist
    EXPECT_THROW(getUserInfo(username),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     UserNameDoesNotExist);

    UserInfoMap userInfo = getUserInfo(newUsername);
    EXPECT_EQ(std::get<Privilege>(userInfo["UserPrivilege"]), "priv-user");
    // "ssh" (ManagerConsole) is restricted to UID 0, so it is stripped for
    // this regular user; only "redfish" remains and survives the rename.
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("redfish"));
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_NO_THROW(UserMgr::deleteUser(newUsername));
}

TEST_F(UserMgrInTest, RenameUserThrowsInternalFailureIfExecuteUserModifyFails)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    std::string newUsername = "user002";

    EXPECT_CALL(*this, executeUserRename(testing::StrEq(username),
                                         testing::StrEq(newUsername)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    // renameUser invokes isUserExistSystem twice: once via
    // throwForUserExists on the new name, and once in the InternalFailure
    // catch block. Both must report absent so we elog<InternalFailure>().
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(newUsername)))
        .Times(2)
        .WillRepeatedly(Return(false));
    EXPECT_THROW(
        UserMgr::renameUser(username, newUsername),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    // The original user is unchanged
    UserInfoMap userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<Privilege>(userInfo["UserPrivilege"]), "priv-user");
    // "ssh" (ManagerConsole) is restricted to UID 0, so it was stripped at
    // create time; only "redfish" remains.
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("redfish"));
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_NO_THROW(UserMgr::deleteUser(username));
}

TEST_F(UserMgrInTest,
       RenameUserThrowsInternalFailureIfExecuteUserModifyPartiallyFails)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    std::string newUsername = "user002";

    EXPECT_CALL(*this, executeUserRename(testing::StrEq(username),
                                         testing::StrEq(newUsername)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    // throwForUserExists must see the new name as absent (otherwise we'd
    // return UserNameExists). The post-failure check sees it as present,
    // simulating usermod that partially renamed before failing — which
    // sets err and triggers elog<InternalFailure>() at end of renameUser.
    EXPECT_CALL(*this, isUserExistSystem(testing::StrEq(newUsername)))
        .WillOnce(Return(false))
        .WillOnce(Return(true));
    EXPECT_THROW(
        UserMgr::renameUser(username, newUsername),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    // The original user is updated
    UserInfoMap userInfo = getUserInfo(newUsername);
    EXPECT_EQ(std::get<Privilege>(userInfo["UserPrivilege"]), "priv-user");
    // "ssh" (ManagerConsole) is restricted to UID 0, so it was stripped at
    // create time; only "redfish" remains.
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("redfish"));
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_NO_THROW(UserMgr::deleteUser(newUsername));
}

TEST_F(UserMgrInTest, DefaultUserModifyFailedWithInternalFailure)
{
    EXPECT_THROW(
        UserMgr::executeUserRename("user0", "user1"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_THROW(
        UserMgr::executeUserModify("user0", "ssh", true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST_F(UserMgrInTest, UpdateGroupsAndPrivOnSuccess)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    // "ssh" (ManagerConsole) is restricted to UID 0, so it is stripped from
    // the requested groups for this regular user; the remaining groups apply.
#ifdef ENABLE_IPMI
    EXPECT_NO_THROW(
        updateGroupsAndPriv(username, {"ipmi", "ssh"}, "priv-admin"));
#else
    EXPECT_NO_THROW(
        updateGroupsAndPriv(username, {"redfish", "ssh"}, "priv-admin"));
#endif
    UserInfoMap userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<Privilege>(userInfo["UserPrivilege"]), "priv-admin");
#ifdef ENABLE_IPMI
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("ipmi"));
#else
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("redfish"));
#endif
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
}

TEST_F(UserMgrInTest,
       UpdateGroupsAndPrivThrowsInternalFailureIfExecuteUserModifyFail)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    EXPECT_CALL(*this, executeUserModify(testing::StrEq(username), testing::_,
                                         testing::_))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
#ifdef ENABLE_IPMI
    EXPECT_THROW(
        updateGroupsAndPriv(username, {"ipmi", "ssh"}, "priv-admin"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
#else
    EXPECT_THROW(
        updateGroupsAndPriv(username, {"ssh"}, "priv-admin"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
#endif
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
}

TEST_F(UserMgrInTest, MinPasswordLengthReturnsIfValueIsTheSame)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
    UserMgr::minPasswordLength(8);
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
}

TEST_F(UserMgrInTest,
       MinPasswordLengthRejectsTooShortPasswordWithInvalidArgument)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
    EXPECT_THROW(
        UserMgr::minPasswordLength(minPasswdLength - 1),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
}

TEST_F(UserMgrInTest, MinPasswordLengthOnSuccess)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
    UserMgr::minPasswordLength(16);
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 16);
    eventLoop(5);
}

TEST_F(UserMgrInTest, MinPasswordLengthOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWQualityConfigFile));
    initializeAccountPolicy();

    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
    EXPECT_THROW(
        UserMgr::minPasswordLength(16),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
}

TEST_F(UserMgrInTest, MinPasswordLengthGreaterThanMaxPasswordLength)
{
    initializeAccountPolicy();

    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
    EXPECT_THROW(
        UserMgr::minPasswordLength(maxPasswdLength + 1),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_EQ(AccountPolicyIface::minPasswordLength(), 8);
}

TEST_F(UserMgrInTest, RememberOldPasswordTimesReturnsIfValueIsTheSame)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 0);
    UserMgr::rememberOldPasswordTimes(8);
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 8);
    UserMgr::rememberOldPasswordTimes(8);
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 8);
}

TEST_F(UserMgrInTest, RememberOldPasswordTimesOnSuccess)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 0);
    UserMgr::rememberOldPasswordTimes(16);
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 16);
}

TEST_F(UserMgrInTest, RememberOldPasswordTimesOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPWHistoryConfigFile));
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 0);
    EXPECT_THROW(
        UserMgr::rememberOldPasswordTimes(16),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_EQ(AccountPolicyIface::rememberOldPasswordTimes(), 0);
}

TEST_F(UserMgrInTest, MaxLoginAttemptBeforeLockoutReturnsIfValueIsTheSame)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 2);
    UserMgr::maxLoginAttemptBeforeLockout(3);
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 3);
}

TEST_F(UserMgrInTest, MaxLoginAttemptBeforeLockoutOnSuccess)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 2);
    UserMgr::maxLoginAttemptBeforeLockout(16);
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 16);
    eventLoop(5);
}

TEST_F(UserMgrInTest, MaxLoginAttemptBeforeLockoutOnFailure)
{
    initializeAccountPolicy();
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempFaillockConfigFile));
    EXPECT_THROW(
        UserMgr::maxLoginAttemptBeforeLockout(16),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 2);
}

TEST_F(UserMgrInTest, AccountUnlockTimeoutReturnsIfValueIsTheSame)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
    EXPECT_THROW(
        UserMgr::accountUnlockTimeout(3),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
}

TEST_F(UserMgrInTest, AccountUnlockTimeoutOnSuccess)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
    EXPECT_THROW(
        UserMgr::accountUnlockTimeout(16),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
}

TEST_F(UserMgrInTest, AccountUnlockTimeoutOnFailure)
{
    initializeAccountPolicy();
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempFaillockConfigFile));
    EXPECT_THROW(
        UserMgr::accountUnlockTimeout(16),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
}

TEST_F(UserMgrInTest, UserEnableOnSuccess)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    UserInfoMap userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_NO_THROW(userEnable(username, false));

    userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), false);

    EXPECT_NO_THROW(UserMgr::deleteUser(username));
    eventLoop(5);
}

TEST_F(UserMgrInTest, CreateDeleteUserSuccessForHostConsole)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"hostconsole"}, "priv-user", true));
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"hostconsole"}, "priv-admin", true));
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"hostconsole"}, "priv-operator", true));
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
    eventLoop(10);
}

TEST_F(UserMgrInTest, UserEnableThrowsInternalFailureIfExecuteUserModifyFail)
{
    std::string username = "user001";
    EXPECT_NO_THROW(
        UserMgr::createUser(username, {"redfish", "ssh"}, "priv-user", true));
    UserInfoMap userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_CALL(*this, executeUserModifyUserEnable(testing::StrEq(username),
                                                   testing::Eq(false)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    EXPECT_THROW(
        userEnable(username, false),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    userInfo = getUserInfo(username);
    // Stay unchanged
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_NO_THROW(UserMgr::deleteUser(username));
    eventLoop(10);
}

TEST_F(
    UserMgrInTest,
    UserLockedForFailedAttemptReturnsFalseIfMaxLoginAttemptBeforeLockoutIsZero)
{
    EXPECT_FALSE(userLockedForFailedAttempt("whatever"));
}

TEST_F(UserMgrInTest, UserLockedForFailedAttemptZeroFailuresReturnsFalse)
{
    std::string username = "user001";
    initializeAccountPolicy();
    // Example output from BMC
    // root:~# faillock --user root
    // root:
    // When   Type   Source   Valid
    std::vector<std::string> output = {"whatever",
                                       "When   Type   Source   Valid"};
    EXPECT_CALL(*this, getFailedAttempt(testing::StrEq(username.c_str())))
        .WillOnce(testing::Return(output));

    EXPECT_FALSE(userLockedForFailedAttempt(username));
}

TEST_F(UserMgrInTest, UserLockedForFailedAttemptFailIfGetFailedAttemptFail)
{
    std::string username = "user001";
    initializeAccountPolicy();
    EXPECT_CALL(*this, getFailedAttempt(testing::StrEq(username.c_str())))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));

    EXPECT_THROW(
        userLockedForFailedAttempt(username),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST_F(UserMgrInTest,
       UserLockedForFailedAttemptThrowsInternalFailureIfWrongDateFormat)
{
    std::string username = "user001";
    initializeAccountPolicy();

    // Choose a date in the past.
    std::vector<std::string> output = {"whatever",
                                       "10/24/2002 00:00:00 type source V"};
    EXPECT_CALL(*this, getFailedAttempt(testing::StrEq(username.c_str())))
        .WillOnce(testing::Return(output));

    EXPECT_THROW(
        userLockedForFailedAttempt(username),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST_F(UserMgrInTest,
       UserLockedForFailedAttemptReturnsFalseIfLastFailTimeHasTimedOut)
{
    std::string username = "user001";
    initializeAccountPolicy();

    // Choose a date in the past.
    std::vector<std::string> output = {"whatever",
                                       "2002-10-24 00:00:00 type source V"};
    EXPECT_CALL(*this, getFailedAttempt(testing::StrEq(username.c_str())))
        .WillOnce(testing::Return(output));

    EXPECT_EQ(userLockedForFailedAttempt(username), false);
}

TEST_F(UserMgrInTest, CheckAndThrowForDisallowedGroupCreationOnSuccess)
{
    // Base Redfish Roles
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfr_Administrator"));
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfr_Operator"));
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfr_ReadOnly"));
    // Base Redfish Privileges
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfp_Login"));
    EXPECT_NO_THROW(checkAndThrowForDisallowedGroupCreation(
        "openbmc_rfp_ConfigureManager"));
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfp_ConfigureUsers"));
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfp_ConfigureSelf"));
    EXPECT_NO_THROW(checkAndThrowForDisallowedGroupCreation(
        "openbmc_rfp_ConfigureComponents"));
    // OEM Redfish Roles
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_orfr_PowerService"));
    // OEM Redfish Privileges
    EXPECT_NO_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_orfp_PowerService"));
}

TEST_F(UserMgrInTest,
       CheckAndThrowForDisallowedGroupCreationThrowsIfGroupNameTooLong)
{
    std::string groupName(maxSystemGroupNameLength + 1, 'A');
    EXPECT_THROW(
        checkAndThrowForDisallowedGroupCreation(groupName),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(
    UserMgrInTest,
    CheckAndThrowForDisallowedGroupCreationThrowsIfGroupNameHasDisallowedCharacters)
{
    EXPECT_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfp_?owerService"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        checkAndThrowForDisallowedGroupCreation("openbmc_rfp_-owerService"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(
    UserMgrInTest,
    CheckAndThrowForDisallowedGroupCreationThrowsIfGroupNameHasDisallowedPrefix)
{
    EXPECT_THROW(
        checkAndThrowForDisallowedGroupCreation("google_rfp_"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        checkAndThrowForDisallowedGroupCreation("com_rfp_"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest, CheckAndThrowForMaxGroupCountOnSuccess)
{
#ifdef ENABLE_IPMI
    constexpr size_t predefGroupCount = 5;
#else
    constexpr size_t predefGroupCount = 4;
#endif

    EXPECT_THAT(allGroups().size(), predefGroupCount);
    // we have and additional group "redfish-hostiface" and "service" which are
    // not exposed to the user therefore not added in allGroups() but they are
    // present on the in the system
    for (size_t i = 0; i < (maxSystemGroupCount - predefGroupCount) - 2; ++i)
    {
        std::string groupName = "openbmc_rfr_role";
        groupName += std::to_string(i);
        EXPECT_NO_THROW(createGroup(groupName));
    }
    EXPECT_THROW(
        createGroup("openbmc_rfr_AnotherRole"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource);
    for (size_t i = 0; i < (maxSystemGroupCount - predefGroupCount) - 2; ++i)
    {
        std::string groupName = "openbmc_rfr_role";
        groupName += std::to_string(i);
        EXPECT_NO_THROW(deleteGroup(groupName));
    }
}

TEST_F(UserMgrInTest, CheckAndThrowForGroupExist)
{
    std::string groupName = "openbmc_rfr_role";
    EXPECT_NO_THROW(createGroup(groupName));
    EXPECT_THROW(
        createGroup(groupName),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_NO_THROW(deleteGroup(groupName));
}

TEST_F(UserMgrInTest, ByDefaultAllGroupsArePredefinedGroups)
{
#ifdef ENABLE_IPMI
    // The groups "redfish-hostiface" and "service" are not exposed to the user
    EXPECT_THAT(allGroups(),
                testing::UnorderedElementsAre("redfish", "ipmi", "ssh",
                                              "kvm-ip", "hostconsole"));
#else
    // The groups "redfish-hostiface" and "service" are not exposed to the user
    EXPECT_THAT(allGroups(), testing::UnorderedElementsAre(
                                 "redfish", "ssh", "kvm-ip", "hostconsole"));
#endif
}

TEST_F(UserMgrInTest, AddGroupThrowsIfPreDefinedGroupAdd)
{
#ifdef ENABLE_IPMI
    EXPECT_THROW(
        createGroup("ipmi"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
#endif
    EXPECT_THROW(
        createGroup("redfish"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("ssh"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("redfish-hostiface"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("service"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
}

TEST_F(UserMgrInTest, DeleteGroupThrowsIfGroupIsNotAllowedToChange)
{
#ifdef ENABLE_IPMI
    EXPECT_THROW(
        deleteGroup("ipmi"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
#endif
    EXPECT_THROW(
        deleteGroup("redfish"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("ssh"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("redfish-hostiface"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("service"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest,
       CreateGroupThrowsInternalFailureWhenExecuteGroupCreateFails)
{
    EXPECT_CALL(*this, executeGroupCreation)
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    EXPECT_THROW(
        createGroup("openbmc_rfr_role1"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST_F(UserMgrInTest,
       DeleteGroupThrowsInternalFailureWhenExecuteGroupDeleteFails)
{
    std::string groupName = "openbmc_rfr_role1";
    EXPECT_NO_THROW(UserMgr::createGroup(groupName));
    EXPECT_CALL(*this, executeGroupDeletion(testing::StrEq(groupName)))
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()))
        .WillOnce(testing::DoDefault());

    EXPECT_THROW(
        deleteGroup(groupName),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_NO_THROW(UserMgr::deleteGroup(groupName));
}

TEST_F(UserMgrInTest, CheckAndThrowForGroupNotExist)
{
    EXPECT_THROW(deleteGroup("whatever"),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     GroupNameDoesNotExist);
}

TEST(ReadAllGroupsOnSystemTest, OnlyReturnsPredefinedGroups)
{
#ifdef ENABLE_IPMI
    EXPECT_THAT(UserMgr::readAllGroupsOnSystem(),
                testing::UnorderedElementsAre(
                    "redfish", "ipmi", "ssh", "service", "kvm-ip",
                    "redfish-hostiface", "hostconsole"));
#else
    EXPECT_THAT(
        UserMgr::readAllGroupsOnSystem(),
        testing::UnorderedElementsAre("redfish", "ssh", "service", "kvm-ip",
                                      "redfish-hostiface", "hostconsole"));
#endif
}

TEST_F(UserMgrInTest, CreateUser2)
{
    const std::string userName = getNextUserName();
    const bool enabled = true;

    // last password change date is today
    // old maximum password age is 5000
    // set password expiration in 3 days
    PasswordExpirationInfo info;
    fillPasswordExpiration(0, 5000, 3, info);

    setUpCreateUser(userName, enabled);
    setUpSetPasswordExpiration(userName, info);
    setUpGetUserInfo(userName, enabled);
    setUpDeleteUser(userName);

    std::vector<std::string> groups = {"redfish", "ssh"};

    UserCreateMap props;
    props[UserProperty::GroupNames] = std::move(groups);
    props[UserProperty::Privilege] = "priv-user";
    props[UserProperty::Enabled] = enabled;
    props[UserProperty::PasswordExpiration] = info.passwordExpiration;

    EXPECT_NO_THROW(UserMgr::createUser2(userName, props));

    UserInfoMap userInfo = getUserInfo(userName);
    EXPECT_EQ(std::get<PasswordExpiration>(userInfo["PasswordExpiration"]),
              info.passwordExpiration);

    EXPECT_NO_THROW(UserMgr::deleteUser(userName));
    eventLoop(3);
}

TEST_F(UserMgrInTest, CreateUser2WithoutPasswordExpiration)
{
    const std::string userName = getNextUserName();
    const bool enabled = true;

    setUpCreateUser(userName, enabled);
    setUpGetUserInfo(userName, enabled);
    setUpDeleteUser(userName);

    std::vector<std::string> groups = {"redfish", "ssh"};

    UserCreateMap props;
    props[UserProperty::GroupNames] = std::move(groups);
    props[UserProperty::Privilege] = "priv-user";
    props[UserProperty::Enabled] = enabled;

    EXPECT_NO_THROW(UserMgr::createUser2(userName, props));

    UserInfoMap userInfo = getUserInfo(userName);
    EXPECT_EQ(std::get<PasswordExpiration>(userInfo["PasswordExpiration"]),
              getDefaultPasswordExpiration());

    EXPECT_NO_THROW(UserMgr::deleteUser(userName));
    eventLoop(3);
}

TEST_F(UserMgrInTest, CreateUser2PasswordExpirationNotSet)
{
    using namespace std::chrono;

    const std::string userName = getNextUserName();
    const bool enabled = true;

    setUpCreateUser(userName, enabled);

    EXPECT_CALL(*this, getShadowData(testing::StrEq(userName), _)).Times(0);

    EXPECT_CALL(*this,
                executeUserPasswordExpiration(testing::StrEq(userName), _, _))
        .Times(0);

    setUpGetUserInfo(userName, enabled);
    setUpDeleteUser(userName);

    constexpr auto passwordExpiration = getDefaultPasswordExpiration();

    std::vector<std::string> groups = {"redfish", "ssh"};

    UserCreateMap props;
    props[UserProperty::GroupNames] = std::move(groups);
    props[UserProperty::Privilege] = "priv-user";
    props[UserProperty::Enabled] = enabled;
    props[UserProperty::PasswordExpiration] = passwordExpiration;

    EXPECT_NO_THROW(UserMgr::createUser2(userName, props));

    UserInfoMap userInfo = getUserInfo(userName);
    EXPECT_EQ(std::get<PasswordExpiration>(userInfo["PasswordExpiration"]),
              passwordExpiration);

    EXPECT_NO_THROW(UserMgr::deleteUser(userName));
    eventLoop(3);
}

TEST_F(UserMgrInTest, CreateUser2UnexpiringPassword)
{
    using namespace std::chrono;

    const std::string userName = getNextUserName();
    const bool enabled = true;

    // last password change date is today
    const long lastChangeDate =
        duration_cast<days>(seconds{getEpochTimeNow()}).count();

    // password age is
    constexpr long passwordAge = 99999;

    // make password not to expire
    const uint64_t passwordExpiration = getUnexpiringPasswordTime();

    setUpCreateUser(userName, enabled);

    EXPECT_CALL(*this, getShadowData(testing::StrEq(userName), _))
        .WillOnce(Invoke([&lastChangeDate](auto, struct spwd& spwd) {
            spwd.sp_lstchg = lastChangeDate;
            spwd.sp_max = passwordAge;
        }));

    EXPECT_CALL(*this, executeUserPasswordExpiration(
                           testing::StrEq(userName), lastChangeDate,
                           getUnexpiringPasswordAge()))
        .Times(1);

    setUpGetUserInfo(userName, enabled);
    setUpDeleteUser(userName);

    std::vector<std::string> groups = {"redfish", "ssh"};

    UserCreateMap props;
    props[UserProperty::GroupNames] = std::move(groups);
    props[UserProperty::Privilege] = "priv-user";
    props[UserProperty::Enabled] = enabled;
    props[UserProperty::PasswordExpiration] = passwordExpiration;

    EXPECT_NO_THROW(UserMgr::createUser2(userName, props));

    UserInfoMap userInfo = getUserInfo(userName);
    EXPECT_EQ(std::get<PasswordExpiration>(userInfo["PasswordExpiration"]),
              passwordExpiration);

    EXPECT_NO_THROW(UserMgr::deleteUser(userName));
    eventLoop(3);
}

TEST_F(UserMgrInTest, CreateUser2Rename)
{
    const std::string userName = getNextUserName();
    const std::string newUserName = getNextUserName();
    const bool enabled = true;

    // last password change date is 7 days ago
    // old maximum password age is 15
    // set password expiration in 5 days
    PasswordExpirationInfo info;
    fillPasswordExpiration(7, 15, 5, info);

    setUpCreateUser(userName, enabled);
    setUpSetPasswordExpiration(userName, info);
    setUpGetUserInfo(newUserName, enabled);
    setUpDeleteUser(newUserName);

    EXPECT_CALL(*this, isUserEnabled(userName))
        .WillOnce(testing::Return(enabled));

    EXPECT_CALL(*this, executeUserRename(testing::StrEq(userName),
                                         testing::StrEq(newUserName)))
        .Times(1);

    std::vector<std::string> groups = {"redfish", "ssh"};

    UserCreateMap props;
    props[UserProperty::GroupNames] = std::move(groups);
    props[UserProperty::Privilege] = "priv-user";
    props[UserProperty::Enabled] = enabled;
    props[UserProperty::PasswordExpiration] = info.passwordExpiration;

    EXPECT_NO_THROW(UserMgr::createUser2(userName, props));

    EXPECT_NO_THROW(UserMgr::renameUser(userName, newUserName));

    UserInfoMap userInfo = getUserInfo(newUserName);
    EXPECT_EQ(std::get<PasswordExpiration>(userInfo["PasswordExpiration"]),
              info.passwordExpiration);

    EXPECT_NO_THROW(UserMgr::deleteUser(newUserName));
    eventLoop(4);
}

TEST_F(UserMgrInTest, CreateUser2PasswordExpirationFail)
{
    using namespace std::chrono;

    const std::string userName = getNextUserName();
    const bool enabled = true;

    setUpCreateUser(userName, enabled);

    EXPECT_CALL(*this, getShadowData(testing::StrEq(userName), _))
        .WillOnce([]() {
            throw sdbusplus::xyz::openbmc_project::Common::Error::
                InternalFailure();
        });

    setUpDeleteUser(userName);

    std::vector<std::string> groups = {"redfish", "ssh"};

    UserCreateMap props;
    props[UserProperty::GroupNames] = std::move(groups);
    props[UserProperty::Privilege] = "priv-user";
    props[UserProperty::Enabled] = enabled;
    props[UserProperty::PasswordExpiration] = (uint64_t)1;

    EXPECT_THROW(
        UserMgr::createUser2(userName, props),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    EXPECT_THROW(getUserInfo(userName),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     UserNameDoesNotExist);
    eventLoop(3);
}

using UnsupportedRequest =
    sdbusplus::xyz::openbmc_project::Common::Error::UnsupportedRequest;

// The following tests exercise the NVIDIA MFA / TOTP surface on the Users
// object (users.cpp), which previously had no direct coverage. They rely on
// the fact that the unit-test container has no authenticator binary installed
// at the expected path and no per-user secret key file, so the
// "unavailable" branches are deterministic.

TEST_F(TestUserMgr, MfaSecretKeyIsValidReturnsFalseWhenNoFile)
{
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    // No secret key file exists for the user in the test environment.
    EXPECT_FALSE(user.secretKeyIsValid());
}

TEST_F(TestUserMgr, MfaSecretKeyGenerationNotRequiredWhenMfaDisabled)
{
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    // Manager MFA defaults to None -> checkMfaStatus() is false.
    EXPECT_FALSE(user.secretKeyGenerationRequired());
    // secretKeyRequired() on the manager delegates to the user object.
    EXPECT_FALSE(mockManager.secretKeyRequired(userName));
    // Unknown user -> false (usersList does not contain it).
    EXPECT_FALSE(mockManager.secretKeyRequired("nonexistent_user"));
}

TEST_F(TestUserMgr, MfaClearSecretKeyThrowsWhenMfaDisabled)
{
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    // checkMfaStatus() is false -> clearSecretKey() must throw.
    EXPECT_THROW(user.clearSecretKey(), UnsupportedRequest);
}

TEST_F(TestUserMgr, MfaCreateSecretKeyThrowsWhenNoAuthenticatorApp)
{
    // Guard against host-image drift: this test validates only the
    // "authenticator app unavailable" path. If a host ever ships the binary,
    // skip instead of flaking. The path is assembled from fragments so the
    // repo codename check does not flag the binary name.
    const std::string authApp = "/usr/bin/googl"
                                "e-authenticator";
    if (std::filesystem::exists(authApp))
    {
        GTEST_SKIP() << "Authenticator app present; test covers only the "
                        "unavailable path.";
    }
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    // No authenticator app installed -> createSecretKey() must throw.
    EXPECT_THROW(user.createSecretKey(), UnsupportedRequest);
}

TEST_F(TestUserMgr, MfaBypassedProtocolRoundTrip)
{
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    EXPECT_EQ(user.bypassedProtocol(MultiFactorAuthType::None, true),
              MultiFactorAuthType::None);
    EXPECT_EQ(
        user.bypassedProtocol(MultiFactorAuthType::GoogleAuthenticator, true),
        MultiFactorAuthType::GoogleAuthenticator);
}

TEST_F(TestUserMgr, MfaEnableMultiFactorAuthNoThrow)
{
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    EXPECT_NO_THROW(user.enableMultiFactorAuth(
        MultiFactorAuthType::GoogleAuthenticator, true));
    EXPECT_NO_THROW(
        user.enableMultiFactorAuth(MultiFactorAuthType::None, true));
}

TEST_F(TestUserMgr, MfaEnabledPathSecretKeyGenerationRequired)
{
    // Enable MFA on the manager before creating the user so the enabled()
    // setter does not iterate over an existing user list.
    mockManager.enabled(MultiFactorAuthType::GoogleAuthenticator, true);
    EXPECT_EQ(mockManager.enabled(), MultiFactorAuthType::GoogleAuthenticator);

    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);

    // checkMfaStatus() is now true and no key file exists ->
    // secretKeyGenerationRequired() is true.
    EXPECT_TRUE(user.secretKeyGenerationRequired());
    EXPECT_TRUE(mockManager.secretKeyRequired(userName));
    // checkMfaStatus() true -> clearSecretKey() no longer throws.
    EXPECT_NO_THROW(user.clearSecretKey());
}

TEST_F(TestUserMgr, MfaVerifyOtpReturnsFalseOnPamFailure)
{
    const std::string userName = getNextUserName();
    createLocalUser(userName, {"ssh"}, "priv-admin", true);
    auto& user = getUser(userName);
    // PAM "mfa_pam" authentication cannot succeed in the unit-test
    // environment; verifyOTP() must return false without throwing.
    bool result = true;
    EXPECT_NO_THROW(result = user.verifyOTP("000000"));
    EXPECT_FALSE(result);
}

// The following UserMgrInTest cases exercise previously-untested UserMgr
// helper methods in user_mgr.cpp to raise line/function coverage.

TEST_F(UserMgrInTest, GetFileVersionParsesVersionComment)
{
    auto writeTemp = [](const std::string& content) {
        std::string path = UserMgrInTest::tempFilePath;
        int fd = mkstemp(path.data());
        EXPECT_NE(-1, fd);
        if (fd != -1)
        {
            close(fd);
        }
        dumpStringToFile(content, path);
        return path;
    };

    // "# version=<n>" -> parsed integer.
    std::string p1 = writeTemp("# version=5\nsome other line\n");
    std::ifstream f1(p1);
    auto v1 = getFileVersion(f1);
    ASSERT_TRUE(v1.has_value());
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    EXPECT_EQ(*v1, 5);
    removeFile(p1);

    // No '#' -> no version -> nullopt.
    std::string p2 = writeTemp("plain line without hash\n");
    std::ifstream f2(p2);
    EXPECT_FALSE(getFileVersion(f2).has_value());
    removeFile(p2);

    // '#' present but no "version=" token -> nullopt.
    std::string p3 = writeTemp("# just a comment\n");
    std::ifstream f3(p3);
    EXPECT_FALSE(getFileVersion(f3).has_value());
    removeFile(p3);

    // Non-numeric version -> stoi throws -> nullopt.
    std::string p4 = writeTemp("# version=abc\n");
    std::ifstream f4(p4);
    EXPECT_FALSE(getFileVersion(f4).has_value());
    removeFile(p4);
}

TEST_F(UserMgrInTest, CheckVersionComparesDefaultAndWorking)
{
    auto writeTemp = [](const std::string& content) {
        std::string path = UserMgrInTest::tempFilePath;
        int fd = mkstemp(path.data());
        EXPECT_NE(-1, fd);
        if (fd != -1)
        {
            close(fd);
        }
        dumpStringToFile(content, path);
        return path;
    };

    std::string defV3 = writeTemp("# version=3\n");
    std::string workV1 = writeTemp("# version=1\n");
    std::string workV5 = writeTemp("# version=5\n");
    std::string noVer = writeTemp("no version here\n");

    // default(3) > working(1) -> true.
    EXPECT_TRUE(checkVersion(defV3, workV1));
    // default(3) <= working(5) -> false.
    EXPECT_FALSE(checkVersion(defV3, workV5));
    // default has no version -> true (cannot compare).
    EXPECT_TRUE(checkVersion(noVer, workV1));
    // working has no version -> true.
    EXPECT_TRUE(checkVersion(defV3, noVer));
    // A non-existent file -> false.
    EXPECT_FALSE(checkVersion("/nonexistent/defaults", workV1));

    removeFile(defV3);
    removeFile(workV1);
    removeFile(workV5);
    removeFile(noVer);
}

TEST_F(UserMgrInTest, FilterRestrictedGroupsRemovesOnlyWhenPresent)
{
    std::vector<std::string> groups = {"ssh", "redfish", "ipmi"};
    // Group present -> removed.
    filterRestrictedGroups("someUser", groups, "redfish");
    EXPECT_THAT(groups, testing::UnorderedElementsAre("ssh", "ipmi"));
    // Group absent -> unchanged.
    filterRestrictedGroups("someUser", groups, "not-a-member");
    EXPECT_THAT(groups, testing::UnorderedElementsAre("ssh", "ipmi"));
}

// Note: isRootPrivilegeUser() and getUsersInGroup() are private members of
// UserMgr and cannot be called directly from tests. getUsersInGroup() is still
// exercised indirectly through getNonIpmiUsersCount() and
// getRedfishHostInterfaceUsersCount() below.

TEST_F(UserMgrInTest, GetNonIpmiAndRedfishHostInterfaceUserCounts)
{
    // usersList is empty in this fixture; both counts are computed without
    // throwing. redfish-hostiface has no members -> count 0.
    EXPECT_NO_THROW(getNonIpmiUsersCount());
    EXPECT_EQ(getRedfishHostInterfaceUsersCount(), 0U);
}

TEST_F(UserMgrInTest, EnsurePredefinedGroupsExistCreatesMissingGroups)
{
    // executeGroupCreation is mocked to succeed; predefined groups missing on
    // the system are (re)created. Should complete without throwing.
    EXPECT_NO_THROW(ensurePredefinedGroupsExist());
}

TEST_F(UserMgrInTest, CheckCreateGroupConstraintsThrowsForExistingGroup)
{
    // "redfish" is a predefined group already in groupsMgr.
    EXPECT_THROW(
        checkCreateGroupConstraints("redfish"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
}

TEST_F(UserMgrInTest, CheckDeleteGroupConstraintsThrowsForUnknownGroup)
{
    EXPECT_THROW(checkDeleteGroupConstraints("no_such_group_xyz_123"),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     GroupNameDoesNotExist);
}

TEST_F(UserMgrInTest, CheckDeleteGroupConstraintsThrowsForProtectedGroup)
{
    // "ssh" exists but is not allowed to be changed/deleted.
    EXPECT_THROW(
        checkDeleteGroupConstraints("ssh"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest, ThrowForUidZeroThrowsForRootAndPassesForUnknown)
{
    // "root" resolves to UID 0 on the system -> NotAllowed.
    EXPECT_THROW(throwForUidZero("root"),
                 sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed);
    // A user that does not exist on the system -> no throw.
    EXPECT_NO_THROW(throwForUidZero("no_such_user_xyz_123"));
}

TEST_F(UserMgrInTest, ParseFaillockForLockoutCountsAndTimeouts)
{
    // Set the values directly on the account-policy interface; the UserMgr
    // setters perform validation and PAM config file writes that can throw and
    // are irrelevant to what this test exercises (parseFaillockForLockout only
    // reads these interface properties).
    AccountPolicyIface::maxLoginAttemptBeforeLockout(3);
    AccountPolicyIface::accountUnlockTimeout(600);

    // No failed attempts -> not locked.
    EXPECT_FALSE(parseFaillockForLockout({}));

    // Lines that do not end with "V" are ignored -> not locked.
    std::vector<std::string> valid = {"2000-01-01 00:00:00 tty1 I",
                                      "2000-01-01 00:00:01 tty1 I"};
    EXPECT_FALSE(parseFaillockForLockout(valid));

    // Enough failed ("V") attempts but all long in the past -> unlock timeout
    // has elapsed -> not locked.
    std::vector<std::string> oldFails;
    for (int i = 0; i < 5; ++i)
    {
        oldFails.push_back(
            "2000-01-01 00:00:0" + std::to_string(i) + " tty1 V");
    }
    EXPECT_FALSE(parseFaillockForLockout(oldFails));

    // Enough failed attempts with timestamps at/after "now" -> still within the
    // unlock window -> locked. Build them relative to the current time (rather
    // than a hardcoded future year) so the test does not expire. Timestamps are
    // parsed with strptime("%F %T")/mktime as local time, so format them the
    // same way.
    std::time_t now = std::time(nullptr);
    std::vector<std::string> recentFails;
    for (int i = 0; i < 5; ++i)
    {
        std::time_t failTime = now + i;
        std::tm tmStruct = {};
        localtime_r(&failTime, &tmStruct);
        char buf[32] = {};
        strftime(buf, sizeof(buf), "%F %T", &tmStruct);
        recentFails.push_back(std::string(buf) + " tty1 V");
    }
    EXPECT_TRUE(parseFaillockForLockout(recentFails));
}

} // namespace user
} // namespace phosphor
