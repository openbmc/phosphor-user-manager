#include "mock_user_mgr.hpp"
#include "user_mgr.hpp"

#include <sdbusplus/test/sdbus_mock.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

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

using ::testing::Return;
using ::testing::Throw;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using UserNameDoesNotExist =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameDoesNotExist;

class TestUserMgr : public testing::Test
{
  public:
    sdbusplus::SdBusMock sdBusMock;
    sdbusplus::bus_t bus;
    MockManager mockManager;

    TestUserMgr() :
        bus(sdbusplus::get_mocked_new(&sdBusMock)), mockManager(bus, objpath)
    {}

    void createLocalUser(const std::string& userName,
                         std::vector<std::string> groupNames,
                         const std::string& priv, bool enabled)
    {
        sdbusplus::message::object_path tempObjPath(usersObjPath);
        tempObjPath /= userName;
        std::string userObj(tempObjPath);
        mockManager.usersList.emplace(
            userName, std::make_unique<phosphor::user::Users>(
                          mockManager.bus, userObj.c_str(), groupNames, priv,
                          enabled, mockManager));
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
    EXPECT_EQ("priv-user", std::get<std::string>(userInfo["UserPrivilege"]));
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

    outputFileStream.exceptions(std::ofstream::failbit | std::ofstream::badbit |
                                std::ofstream::eofbit);

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
        tempFaillockConfigFile = "/tmp/test-data-XXXXXX";
        mktemp(tempFaillockConfigFile.data());
        EXPECT_NO_THROW(
            dumpStringToFile(rawFailLockConfig, tempFaillockConfigFile));
        tempPWHistoryConfigFile = "/tmp/test-data-XXXXXX";
        mktemp(tempPWHistoryConfigFile.data());
        EXPECT_NO_THROW(
            dumpStringToFile(rawPWHistoryConfig, tempPWHistoryConfigFile));
        tempPWQualityConfigFile = "/tmp/test-data-XXXXXX";
        mktemp(tempPWQualityConfigFile.data());
        EXPECT_NO_THROW(
            dumpStringToFile(rawPWQualityConfig, tempPWQualityConfigFile));
        // Set config files to test files
        faillockConfigFile = tempFaillockConfigFile;
        pwHistoryConfigFile = tempPWHistoryConfigFile;
        pwQualityConfigFile = tempPWQualityConfigFile;

        ON_CALL(*this, executeUserAdd).WillByDefault(testing::Return());

        ON_CALL(*this, executeUserDelete).WillByDefault(testing::Return());

        ON_CALL(*this, executeUserClearFailRecords)
            .WillByDefault(testing::Return());

        ON_CALL(*this, getIpmiUsersCount).WillByDefault(testing::Return(0));

        ON_CALL(*this, executeUserRename).WillByDefault(testing::Return());

        ON_CALL(*this, executeUserModify(testing::_, testing::_, testing::_))
            .WillByDefault(testing::Return());

        ON_CALL(*this, executeUserModifyUserEnable)
            .WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupCreation(testing::_))
            .WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupDeletion(testing::_))
            .WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupCreation).WillByDefault(testing::Return());

        ON_CALL(*this, executeGroupDeletion).WillByDefault(testing::Return());
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

  protected:
    static sdbusplus::bus_t busInTest;
    std::string tempFaillockConfigFile;
    std::string tempPWHistoryConfigFile;
    std::string tempPWQualityConfigFile;
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
    std::string strWith17Chars(17, 'A');
    EXPECT_THROW(throwForUserNameConstraints(strWith17Chars, {"ipmi"}),
                 sdbusplus::xyz::openbmc_project::User::Common::Error::
                     UserNameGroupFail);
}

TEST_F(
    UserMgrInTest,
    ThrowForUserNameConstraintsExceedSystemMaxUserNameLenThrowsInvalidArgument)
{
    std::string strWith31Chars(31, 'A');
    EXPECT_THROW(
        throwForUserNameConstraints(strWith31Chars, {}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest,
       ThrowForUserNameConstraintsRegexMismatchThrowsInvalidArgument)
{
    std::string startWithNumber = "0ABC";
    EXPECT_THROW(
        throwForUserNameConstraints(startWithNumber, {"ipmi"}),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
}

TEST_F(UserMgrInTest, UserAddNotRootFailedWithInternalFailure)
{
    EXPECT_THROW(
        UserMgr::executeUserAdd("user0", "ipmi,ssh", true, true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
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
    EXPECT_CALL(*this, getIpmiUsersCount()).WillOnce(Return(ipmiMaxUsers));
    EXPECT_THROW(
        throwForMaxGrpUserCount({"ipmi"}),
        sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource);
}

TEST_F(UserMgrInTest, CreateUserThrowsInternalFailureWhenExecuteUserAddFails)
{
    EXPECT_CALL(*this, executeUserAdd)
        .WillOnce(testing::Throw(
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure()));
    EXPECT_THROW(
        createUser("whatever", {"redfish"}, "", true),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
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

    EXPECT_THROW(
        deleteUser(username),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_NO_THROW(UserMgr::deleteUser(username));
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

    EXPECT_THROW(
        deleteUser(username),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
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
}

TEST_F(UserMgrInTest, ThrowForInvalidGroupsNoThrowWhenGroupIsValid)
{
    EXPECT_NO_THROW(throwForInvalidGroups({"ipmi"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"ssh"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"redfish"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"web"}));
    EXPECT_NO_THROW(throwForInvalidGroups({"hostconsole"}));
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
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("redfish", "ssh"));
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
    EXPECT_THROW(
        UserMgr::renameUser(username, newUsername),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    // The original user is unchanged
    UserInfoMap userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<Privilege>(userInfo["UserPrivilege"]), "priv-user");
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("redfish", "ssh"));
    EXPECT_EQ(std::get<UserEnabled>(userInfo["UserEnabled"]), true);

    EXPECT_NO_THROW(UserMgr::deleteUser(username));
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
    EXPECT_NO_THROW(
        updateGroupsAndPriv(username, {"ipmi", "ssh"}, "priv-admin"));
    UserInfoMap userInfo = getUserInfo(username);
    EXPECT_EQ(std::get<Privilege>(userInfo["UserPrivilege"]), "priv-admin");
    EXPECT_THAT(std::get<GroupList>(userInfo["UserGroups"]),
                testing::UnorderedElementsAre("ipmi", "ssh"));
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
    EXPECT_THROW(
        updateGroupsAndPriv(username, {"ipmi", "ssh"}, "priv-admin"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
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
    UserMgr::maxLoginAttemptBeforeLockout(2);
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 2);
}

TEST_F(UserMgrInTest, MaxLoginAttemptBeforeLockoutOnSuccess)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 2);
    UserMgr::maxLoginAttemptBeforeLockout(16);
    EXPECT_EQ(AccountPolicyIface::maxLoginAttemptBeforeLockout(), 16);
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
    UserMgr::accountUnlockTimeout(3);
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
}

TEST_F(UserMgrInTest, AccountUnlockTimeoutOnSuccess)
{
    initializeAccountPolicy();
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 3);
    UserMgr::accountUnlockTimeout(16);
    EXPECT_EQ(AccountPolicyIface::accountUnlockTimeout(), 16);
}

TEST_F(UserMgrInTest, AccountUnlockTimeoutOnFailure)
{
    initializeAccountPolicy();
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempFaillockConfigFile));
    EXPECT_THROW(
        UserMgr::accountUnlockTimeout(16),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
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
    constexpr size_t predefGroupCount = 5;

    EXPECT_THAT(allGroups().size(), predefGroupCount);
    for (size_t i = 0; i < maxSystemGroupCount - predefGroupCount; ++i)
    {
        std::string groupName = "openbmc_rfr_role";
        groupName += std::to_string(i);
        EXPECT_NO_THROW(createGroup(groupName));
    }
    EXPECT_THROW(
        createGroup("openbmc_rfr_AnotherRole"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource);
    for (size_t i = 0; i < maxSystemGroupCount - predefGroupCount; ++i)
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
    EXPECT_THAT(allGroups(),
                testing::UnorderedElementsAre("web", "redfish", "ipmi", "ssh",
                                              "hostconsole"));
}

TEST_F(UserMgrInTest, AddGroupThrowsIfPreDefinedGroupAdd)
{
    EXPECT_THROW(
        createGroup("ipmi"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("web"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("redfish"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("ssh"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
    EXPECT_THROW(
        createGroup("hostconsole"),
        sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists);
}

TEST_F(UserMgrInTest, DeleteGroupThrowsIfGroupIsNotAllowedToChange)
{
    EXPECT_THROW(
        deleteGroup("ipmi"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("web"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("redfish"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("ssh"),
        sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument);
    EXPECT_THROW(
        deleteGroup("hostconsole"),
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
    EXPECT_THAT(UserMgr::readAllGroupsOnSystem(),
                testing::UnorderedElementsAre("web", "redfish", "ipmi", "ssh",
                                              "hostconsole"));
}

} // namespace user
} // namespace phosphor
