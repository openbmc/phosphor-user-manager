/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
#pragma once
#include "json_serializer.hpp"
#include "users.hpp"

#include <shadow.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/AccountPolicy/server.hpp>
#include <xyz/openbmc_project/User/Manager/server.hpp>
#include <xyz/openbmc_project/User/MultiFactorAuthConfiguration/server.hpp>
#include <xyz/openbmc_project/User/TOTPState/server.hpp>

#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace phosphor
{
namespace user
{

inline constexpr size_t ipmiMaxUsers = 15;
inline constexpr size_t maxSystemUsers = 30;
inline constexpr uint8_t minPasswdLength = 8;
extern uint8_t maxPasswdLength; // MAX_PASSWORD_LENGTH;
inline constexpr size_t maxSystemGroupNameLength = 32;
inline constexpr size_t maxSystemGroupCount = 64;

using UserMgrIface = sdbusplus::xyz::openbmc_project::User::server::Manager;
using UserSSHLists =
    std::pair<std::vector<std::string>, std::vector<std::string>>;
using AccountPolicyIface =
    sdbusplus::xyz::openbmc_project::User::server::AccountPolicy;

using MultiFactorAuthConfigurationIface =
    sdbusplus::xyz::openbmc_project::User::server::MultiFactorAuthConfiguration;

using TOTPStateIface = sdbusplus::xyz::openbmc_project::User::server::TOTPState;

using UserProperty =
    sdbusplus::common::xyz::openbmc_project::user::Manager::UserProperty;

using Ifaces = sdbusplus::server::object_t<UserMgrIface, AccountPolicyIface,
                                           MultiFactorAuthConfigurationIface,
                                           TOTPStateIface>;

using Privilege = std::string;
using GroupList = std::vector<std::string>;
using UserEnabled = bool;
using PropertyName = std::string;
using ServiceEnabled = bool;
using PasswordExpiration = uint64_t;

using UserInfo =
    std::variant<Privilege, GroupList, UserEnabled, PasswordExpiration>;

using UserInfoMap = std::map<PropertyName, UserInfo>;

using UserCreateMap = std::map<UserProperty, UserInfo>;

using DbusUserObjPath = sdbusplus::message::object_path;

using DbusUserPropVariant = std::variant<Privilege, ServiceEnabled>;

using DbusUserObjProperties = std::map<PropertyName, DbusUserPropVariant>;

using Interface = std::string;

using DbusUserObjValue = std::map<Interface, DbusUserObjProperties>;

using DbusUserObj = std::map<DbusUserObjPath, DbusUserObjValue>;

using MultiFactorAuthType = sdbusplus::common::xyz::openbmc_project::user::
    MultiFactorAuthConfiguration::Type;
std::string getCSVFromVector(std::span<const std::string> vec);

bool removeStringFromCSV(std::string& csvStr, const std::string& delStr);

template <typename... ArgTypes>
std::vector<std::string> executeCmd(const char* path, ArgTypes&&... tArgs)
{
    int pipefd[2];

    if (pipe(pipefd) == -1)
    {
        lg2::error("Failed to create pipe: {ERROR}", "ERROR", strerror(errno));
        phosphor::logging::elog<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
        return {};
    }

    pid_t pid = fork();

    if (pid == -1)
    {
        lg2::error("Failed to fork process: {ERROR}", "ERROR", strerror(errno));
        phosphor::logging::elog<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
        close(pipefd[0]); // Close read end of pipe
        close(pipefd[1]); // Close write end of pipe
        return {};
    }

    if (pid == 0)         // Child process
    {
        close(pipefd[0]); // Close read end of pipe

        // Redirect write end of the pipe to stdout.
        if (dup2(pipefd[1], STDOUT_FILENO) == -1)
        {
            lg2::error("Failed to redirect stdout: {ERROR}", "ERROR",
                       strerror(errno));
            _exit(EXIT_FAILURE);
        }
        close(pipefd[1]); // Close write end of pipe

        std::vector<const char*> args = {path};
        (args.emplace_back(const_cast<const char*>(tArgs)), ...);
        args.emplace_back(nullptr);

        execv(path, const_cast<char* const*>(args.data()));

        // If exec returns, an error occurred
        lg2::error("Failed to execute command '{PATH}': {ERROR}", "PATH", path,
                   "ERROR", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    // Parent process.

    close(pipefd[1]); // Close write end of pipe

    FILE* fp = fdopen(pipefd[0], "r");
    if (fp == nullptr)
    {
        lg2::error("Failed to open pipe for reading: {ERROR}", "ERROR",
                   strerror(errno));
        close(pipefd[0]);
        phosphor::logging::elog<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
        return {};
    }

    std::vector<std::string> results;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != nullptr)
    {
        std::string line = buffer;
        if (!line.empty() && line.back() == '\n')
        {
            line.pop_back(); // Remove newline character
        }
        results.emplace_back(line);
    }

    fclose(fp);
    close(pipefd[0]);

    int status;
    while (waitpid(pid, &status, 0) == -1)
    {
        // Need to retry on EINTR.
        if (errno == EINTR)
        {
            continue;
        }

        lg2::error("Failed to wait for child process: {ERROR}", "ERROR",
                   strerror(errno));
        phosphor::logging::elog<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
        return {};
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
    {
        lg2::error("Command {PATH} execution failed, return code {RETCODE}",
                   "PATH", path, "RETCODE", WEXITSTATUS(status));
        phosphor::logging::elog<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
    }

    return results;
}

/** @class UserMgr
 *  @brief Responsible for managing user accounts over the D-Bus interface.
 */
class UserMgr : public Ifaces
{
  public:
    UserMgr() = delete;
    ~UserMgr() = default;
    UserMgr(const UserMgr&) = delete;
    UserMgr& operator=(const UserMgr&) = delete;
    UserMgr(UserMgr&&) = delete;
    UserMgr& operator=(UserMgr&&) = delete;

    /** @brief Constructs UserMgr object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     */
    UserMgr(sdbusplus::bus_t& bus, const char* path);

    /** @brief create user method.
     *  This method creates a new user as requested
     *
     *  @param[in] userName - Name of the user which has to be created
     *  @param[in] groupNames - Group names list, to which user has to be added.
     *  @param[in] priv - Privilege of the user.
     *  @param[in] enabled - State of the user enabled / disabled.
     */
    void createUser(std::string userName, std::vector<std::string> groupNames,
                    std::string priv, bool enabled) override;

    /** @brief create user with password expiration method.
     *  This method creates a new user as requested
     *
     *  @param[in] userName - Name of the user which has to be created
     *  @param[in] props - Create user properties.
     */
    void createUser2(std::string userName, UserCreateMap props) override;

    /** @brief rename user method.
     *  This method renames the user as requested
     *
     *  @param[in] userName - current name of the user
     *  @param[in] newUserName - new user name to which it has to be renamed.
     */
    void renameUser(std::string userName, std::string newUserName) override;

    /** @brief delete user method.
     *  This method deletes the user as requested
     *
     *  @param[in] userName - Name of the user which has to be deleted
     */
    void deleteUser(std::string userName);

    /** @brief Update user groups & privilege.
     *  This method updates user groups & privilege
     *
     *  @param[in] userName - user name, for which update is requested
     *  @param[in] groupName - Group to be updated..
     *  @param[in] priv - Privilege to be updated.
     */
    void updateGroupsAndPriv(const std::string& userName,
                             std::vector<std::string> groups,
                             const std::string& priv);

    /** @brief Update user enabled state.
     *  This method enables / disables user
     *
     *  @param[in] userName - user name, for which update is requested
     *  @param[in] enabled - enable / disable the user
     */
    void userEnable(const std::string& userName, bool enabled);

    /** @brief get user enabled state
     *  method to get user enabled state.
     *
     *  @param[in] userName - name of the user
     *  @return - user enabled status (true/false)
     */
    virtual bool isUserEnabled(const std::string& userName);

    /** @brief update minimum password length requirement
     *
     *  @param[in] val - minimum password length
     *  @return - minimum password length
     */
    uint8_t minPasswordLength(uint8_t val) override;

    /** @brief update old password history count
     *
     *  @param[in] val - number of times old passwords has to be avoided
     *  @return - number of times old password has to be avoided
     */
    uint8_t rememberOldPasswordTimes(uint8_t val) override;

    /** @brief update maximum number of failed login attempt before locked
     *  out.
     *
     *  @param[in] val - number of allowed attempt
     *  @return - number of allowed attempt
     */
    uint16_t maxLoginAttemptBeforeLockout(uint16_t val) override;

    /** @brief update timeout to unlock the account
     *
     *  @param[in] val - value in seconds
     *  @return - value in seconds
     */
    uint32_t accountUnlockTimeout(uint32_t val) override;

    /** @brief parses the faillock output for locked user status
     *
     * @param[in] - output from faillock for the user
     * @return - true / false indicating user locked / un-locked
     **/
    bool parseFaillockForLockout(
        const std::vector<std::string>& faillockOutput);

    /** @brief lists user locked state for failed attempt
     *
     * @param[in] - user name
     * @return - true / false indicating user locked / un-locked
     **/
    virtual bool userLockedForFailedAttempt(const std::string& userName);

    /** @brief lists user locked state for failed attempt
     *
     * @param[in]: user name
     * @param[in]: value - false -unlock user account, true - no action taken
     **/
    bool userLockedForFailedAttempt(const std::string& userName,
                                    const bool& value);

    /** @brief shows if the user's password is expired
     *
     * @param[in]: user name
     * @return - true / false indicating user password expired
     **/
    virtual bool userPasswordExpired(const std::string& userName);

    /** @brief returns user info
     * Checks if user is local user, then returns map of properties of user.
     * like user privilege, list of user groups, user enabled state and user
     * locked state. If its not local user, then it checks if its a ldap user,
     * then it gets the privilege mapping of the LDAP group.
     *
     * @param[in] - user name
     * @return -  map of user properties
     **/
    UserInfoMap getUserInfo(std::string userName) override;

    /** @brief get IPMI user count
     *  method to get IPMI user count
     *
     * @return - returns user count
     */
    virtual size_t getIpmiUsersCount(void);

    void createGroup(std::string groupName) override;

    void deleteGroup(std::string groupName) override;
    MultiFactorAuthType enabled() const override
    {
        return MultiFactorAuthConfigurationIface::enabled();
    }
    MultiFactorAuthType enabled(MultiFactorAuthType value,
                                bool skipSignal) override;
    bool secretKeyRequired(std::string userName) override;
    static std::vector<std::string> readAllGroupsOnSystem();
    void load();
    JsonSerializer& getSerializer()
    {
        return serializer;
    }

    /** @brief user password expiration
     *
     * Password expiration is date time when the user password expires. The time
     * is the Epoch time, number of seconds since 1 Jan 1970 00::00::00 UTC.
     *When zero value is returned, it means that password does not expire.
     *
     * @param[in]: user name
     * @return - Epoch time when the user password expires
     **/
    uint64_t getPasswordExpiration(const std::string& userName) const;

    /** @brief update user password expiration
     *
     * Password expiration is date time when the user password expires. The time
     * is the Epoch time, number of seconds since 1 Jan 1970 00::00::00 UTC.
     *When zero value is provided, it means that password does not expire.
     *
     * @param[in]: user name
     * @param[in]: Epoch time when the user password expires
     **/
    void setPasswordExpiration(const std::string& userName,
                               const uint64_t value);

  protected:
    /** @brief get pam argument value
     *  method to get argument value from pam configuration
     *
     *  @param[in] moduleName - name of the module from where arg has to be read
     *  @param[in] argName - argument name
     *  @param[out] argValue - argument value
     *
     *  @return 0 - success state of the function
     */
    int getPamModuleArgValue(const std::string& moduleName,
                             const std::string& argName, std::string& argValue);

    /** @brief get pam argument value
     *  method to get argument value from pam configuration
     *
     *  @param[in] confFile - path of the module config file from where arg has
     * to be read
     *  @param[in] argName - argument name
     *  @param[out] argValue - argument value
     *
     *  @return 0 - success state of the function
     */
    int getPamModuleConfValue(const std::string& confFile,
                              const std::string& argName,
                              std::string& argValue);

    /** @brief set pam argument value
     *  method to set argument value in pam configuration
     *
     *  @param[in] moduleName - name of the module in which argument value has
     * to be set
     *  @param[in] argName - argument name
     *  @param[out] argValue - argument value
     *
     *  @return 0 - success state of the function
     */
    int setPamModuleArgValue(const std::string& moduleName,
                             const std::string& argName,
                             const std::string& argValue);

    /** @brief set pam argument value
     *  method to set argument value in pam configuration
     *
     *  @param[in] confFile - path of the module config file in which argument
     * value has to be set
     *  @param[in] argName - argument name
     *  @param[out] argValue - argument value
     *
     *  @return 0 - success state of the function
     */
    int setPamModuleConfValue(const std::string& confFile,
                              const std::string& argName,
                              const std::string& argValue);

    /** @brief check for user presence
     *  method to check for user existence
     *
     *  @param[in] userName - name of the user
     *  @return -true if user exists and false if not.
     */
    bool isUserExist(const std::string& userName) const;

    size_t getNonIpmiUsersCount();

    /** @brief check user exists
     *  method to check whether user exist, and throw if not.
     *
     *  @param[in] userName - name of the user
     */
    void throwForUserDoesNotExist(const std::string& userName) const;

    /** @brief check user does not exist
     *  method to check whether does not exist, and throw if exists.
     *
     *  @param[in] userName - name of the user
     */
    void throwForUserExists(const std::string& userName);

    /** @brief check user name constraints
     *  method to check user name constraints and throw if failed.
     *
     *  @param[in] userName - name of the user
     *  @param[in] groupNames - user groups
     */
    void throwForUserNameConstraints(
        const std::string& userName,
        const std::vector<std::string>& groupNames);

    /** @brief check group user count
     *  method to check max group user count, and throw if limit reached
     *
     *  @param[in] groupNames - group name
     */
    void throwForMaxGrpUserCount(const std::vector<std::string>& groupNames);

    virtual void executeUserAdd(const char* userName, const char* groups,
                                bool sshRequested, bool enabled);

    virtual void executeUserDelete(const char* userName);

    /** @brief clear user's failure records
     *  method to clear user fail records and throw if failed.
     *
     *  @param[in] userName - name of the user
     */
    virtual void executeUserClearFailRecords(const char* userName);

    virtual void executeUserRename(const char* userName,
                                   const char* newUserName);

    virtual void executeUserModify(const char* userName, const char* newGroups,
                                   bool sshRequested);

    virtual void executeUserModifyUserEnable(const char* userName,
                                             bool enabled);

    virtual void executeGroupCreation(const char* groupName);

    virtual void executeGroupDeletion(const char* groupName);

    virtual void executeUserPasswordExpiration(
        const char* userName, const long int passwordLastChange,
        const long int passwordAge) const;

    virtual std::vector<std::string> getFailedAttempt(const char* userName);

    /** @brief check for valid privielge
     *  method to check valid privilege, and throw if invalid
     *
     *  @param[in] priv - privilege of the user
     */
    void throwForInvalidPrivilege(const std::string& priv);

    /** @brief check for valid groups
     *  method to check valid groups, and throw if invalid
     *
     *  @param[in] groupNames - user groups
     */
    void throwForInvalidGroups(const std::vector<std::string>& groupName);

    void initializeAccountPolicy();

    /** @brief checks if the group creation meets all constraints
     * @param groupName - group to check
     */
    void checkCreateGroupConstraints(const std::string& groupName);

    /** @brief checks if the group deletion meets all constraints
     * @param groupName - group to check
     */
    void checkDeleteGroupConstraints(const std::string& groupName);

    /** @brief checks if the group name is legal and whether it's allowed to
     * change. The daemon doesn't allow arbitrary group to be created
     * @param groupName - group to check
     */
    void checkAndThrowForDisallowedGroupCreation(const std::string& groupName);

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus_t& bus;

    /** @brief object path */
    const std::string path;

    /** @brief serializer for mfa */
    JsonSerializer serializer;
    /** @brief privilege manager container */
    const std::vector<std::string> privMgr = {"priv-admin", "priv-operator",
                                              "priv-user"};

    /** @brief groups manager container */
    std::vector<std::string> groupsMgr;

    /** @brief map container to hold users object */

    std::unordered_map<std::string, std::unique_ptr<phosphor::user::Users>>
        usersList;

    /** @brief get users in group
     *  method to get group user list
     *
     *  @param[in] groupName - group name
     *
     *  @return userList  - list of users in the group.
     */
    std::vector<std::string> getUsersInGroup(const std::string& groupName);

    /** @brief get user & SSH users list
     *  method to get the users and ssh users list.
     *
     *@return - vector of User & SSH user lists
     */
    UserSSHLists getUserAndSshGrpList(void);

    /** @brief initialize the user manager objects
     *  method to initialize the user manager objects accordingly
     *
     */
    void initUserObjects(void);

    /** @brief get service name
     *  method to get dbus service name
     *
     *  @param[in] path - object path
     *  @param[in] intf - interface
     *  @return - service name
     */
    std::string getServiceName(std::string&& path, std::string&& intf);

    /** @brief get primary group ID of specified user
     *
     * @param[in] - userName
     * @return - primary group ID
     */
    virtual gid_t getPrimaryGroup(const std::string& userName) const;

    /** @brief check whether if the user is a member of the group
     *
     * @param[in] - userName
     * @param[in] - ID of the user's primary group
     * @param[in] - groupName
     * @return - true if the user is a member of the group
     */
    virtual bool isGroupMember(const std::string& userName, gid_t primaryGid,
                               const std::string& groupName) const;

  protected:
    /** @brief get privilege mapper object
     *  method to get dbus privilege mapper object
     *
     *  @return - map of user object
     */
    virtual DbusUserObj getPrivilegeMapperObject(void);

    friend class TestUserMgr;

    std::string faillockConfigFile;
    std::string pwHistoryConfigFile;
    std::string pwQualityConfigFile;

  private:
    void createUserImpl(const std::string& userName, UserCreateMap props);

    void setPasswordExpirationImpl(const std::string& userName,
                                   const uint64_t value);

    void deleteUserImpl(const std::string& userName);

  public:
    // This functions need to be public for tests

    /** @brief value of a password maximum age indicating that the password does
     *  not expire
     *
     **/
    static constexpr long int getUnexpiringPasswordAge()
    {
        return -1;
    }

    /** @brief date time value indicating that a password does not expire
     *
     **/
    static constexpr uint64_t getUnexpiringPasswordTime()
    {
        return 0;
    };

    /** @brief date time value indicating that a password expiration is not set
     *
     **/
    static constexpr uint64_t getDefaultPasswordExpiration()
    {
        // default password expiration value
        return std::numeric_limits<uint64_t>::max();
    };

  protected:
    // This function needs to be virtual and protected for tests
    virtual void getShadowData(const std::string& userName,
                               struct spwd& spwd) const;
};

} // namespace user
} // namespace phosphor
