#include "mock_user_mgr.hpp"
#include "user_mgr.hpp"

#include <sdbusplus/test/sdbus_mock.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <exception>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

namespace phosphor
{
namespace user
{

using ::testing::Return;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

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

    EXPECT_CALL(mockManager, getLdapGroupName(userName))
        .WillRepeatedly(Return(""));
    EXPECT_THROW(userInfo = mockManager.getUserInfo(userName), InternalFailure);
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

    EXPECT_CALL(mockManager, getLdapGroupName(userName))
        .WillRepeatedly(Return(ldapGroup));
    // Create privilege mapper dbus object
    DbusUserObj object = createPrivilegeMapperDbusObject();
    EXPECT_CALL(mockManager, getPrivilegeMapperObject())
        .WillRepeatedly(Return(object));
    userInfo = mockManager.getUserInfo(userName);
    EXPECT_EQ(true, std::get<bool>(userInfo["RemoteUser"]));
    EXPECT_EQ("priv-admin", std::get<std::string>(userInfo["UserPrivilege"]));
}

TEST_F(TestUserMgr, ldapUserWithoutPrivMapper)
{
    UserInfoMap userInfo;
    std::string userName = "ldapUser";
    std::string ldapGroup = "ldapGroup";

    EXPECT_CALL(mockManager, getLdapGroupName(userName))
        .WillRepeatedly(Return(ldapGroup));
    // Create LDAP config object without privilege mapper
    DbusUserObj object = createLdapConfigObjectWithoutPrivilegeMapper();
    EXPECT_CALL(mockManager, getPrivilegeMapperObject())
        .WillRepeatedly(Return(object));
    userInfo = mockManager.getUserInfo(userName);
    EXPECT_EQ(true, std::get<bool>(userInfo["RemoteUser"]));
    EXPECT_EQ("", std::get<std::string>(userInfo["UserPrivilege"]));
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

// Fake config; referenced config on real BMC
inline constexpr const char* rawConfig = R"(
#
# /etc/pam.d/common-password - password-related modules common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of modules that define the services to be
# used to change user passwords.  The default is pam_unix.

# Explanation of pam_unix options:
#
# The "sha512" option enables salted SHA512 passwords.  Without this option,
# the default is Unix crypt.  Prior releases used the option "md5".
#
# The "obscure" option replaces the old `OBSCURE_CHECKS_ENAB' option in
# login.defs.
#
# See the pam_unix manpage for other options.

# here are the per-package modules (the "Primary" block)
password	[success=ok default=die]	pam_tally2.so debug enforce_for_root reject_username minlen=8 difok=0 lcredit=0 ocredit=0 dcredit=0 ucredit=0 #some comments
password	[success=ok default=die]	pam_cracklib.so debug enforce_for_root reject_username minlen=8 difok=0 lcredit=0 ocredit=0 dcredit=0 ucredit=0 #some comments
password	[success=ok default=die]	pam_ipmicheck.so spec_grp_name=ipmi use_authtok
password	[success=ok ignore=ignore default=die]	pam_pwhistory.so debug enforce_for_root remember=0 use_authtok
password	[success=ok default=die]	pam_unix.so sha512 use_authtok
password	[success=1 default=die] 	pam_ipmisave.so spec_grp_name=ipmi spec_pass_file=/etc/ipmi_pass key_file=/etc/key_file
# here's the fallback if no module succeeds
password	requisite			pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
password	required			pam_permit.so
# and here are more per-package modules (the "Additional" block)
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
        tempPamConfigFile = "/tmp/test-data-XXXXXX";
        mktemp(tempPamConfigFile.data());
        EXPECT_NO_THROW(dumpStringToFile(rawConfig, tempPamConfigFile));
        // Set config files to test files
        pamPasswdConfigFile = tempPamConfigFile;
        pamAuthConfigFile = tempPamConfigFile;

        ON_CALL(*this, executeUserAdd).WillByDefault(testing::Return());

        ON_CALL(*this, executeUserDelete).WillByDefault(testing::Return());

        ON_CALL(*this, getIpmiUsersCount).WillByDefault(testing::Return(0));

        ON_CALL(*this, executeUserRename).WillByDefault(testing::Return());
    }

    ~UserMgrInTest() override
    {
        EXPECT_NO_THROW(removeFile(tempPamConfigFile));
    }

    MOCK_METHOD(void, executeUserAdd, (const char*, const char*, bool, bool),
                (override));

    MOCK_METHOD(void, executeUserDelete, (const char*), (override));

    MOCK_METHOD(size_t, getIpmiUsersCount, (), (override));

    MOCK_METHOD(void, executeUserRename, (const char*, const char*),
                (override));

    static sdbusplus::bus_t busInTest;
    std::string tempPamConfigFile;
};

sdbusplus::bus_t UserMgrInTest::busInTest = sdbusplus::bus::new_default();

TEST_F(UserMgrInTest, GetPamModuleArgValueOnSuccess)
{
    std::string minLen;
    EXPECT_EQ(getPamModuleArgValue("pam_tally2.so", "minlen", minLen), 0);
    EXPECT_EQ(minLen, "8");
    EXPECT_EQ(getPamModuleArgValue("pam_cracklib.so", "minlen", minLen), 0);
    EXPECT_EQ(minLen, "8");
}

TEST_F(UserMgrInTest, SetPamModuleArgValueOnSuccess)
{
    EXPECT_EQ(setPamModuleArgValue("pam_cracklib.so", "minlen", "16"), 0);
    EXPECT_EQ(setPamModuleArgValue("pam_tally2.so", "minlen", "16"), 0);
    std::string minLen;
    EXPECT_EQ(getPamModuleArgValue("pam_tally2.so", "minlen", minLen), 0);
    EXPECT_EQ(minLen, "16");
    EXPECT_EQ(getPamModuleArgValue("pam_cracklib.so", "minlen", minLen), 0);
    EXPECT_EQ(minLen, "16");
}

TEST_F(UserMgrInTest, GetPamModuleArgValueOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPamConfigFile));
    std::string minLen;
    EXPECT_EQ(getPamModuleArgValue("pam_tally2.so", "minlen", minLen), -1);
    EXPECT_EQ(getPamModuleArgValue("pam_cracklib.so", "minlen", minLen), -1);

    EXPECT_NO_THROW(removeFile(tempPamConfigFile));
    EXPECT_EQ(getPamModuleArgValue("pam_tally2.so", "minlen", minLen), -1);
    EXPECT_EQ(getPamModuleArgValue("pam_cracklib.so", "minlen", minLen), -1);
}

TEST_F(UserMgrInTest, SetPamModuleArgValueOnFailure)
{
    EXPECT_NO_THROW(dumpStringToFile("whatever", tempPamConfigFile));
    EXPECT_EQ(setPamModuleArgValue("pam_cracklib.so", "minlen", "16"), -1);
    EXPECT_EQ(setPamModuleArgValue("pam_tally2.so", "minlen", "16"), -1);

    EXPECT_NO_THROW(removeFile(tempPamConfigFile));
    EXPECT_EQ(setPamModuleArgValue("pam_cracklib.so", "minlen", "16"), -1);
    EXPECT_EQ(setPamModuleArgValue("pam_tally2.so", "minlen", "16"), -1);
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
    EXPECT_NO_THROW(throwForInvalidPrivilege("priv-noaccess"));
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
}

} // namespace user
} // namespace phosphor
