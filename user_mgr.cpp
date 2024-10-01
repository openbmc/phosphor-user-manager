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

#include "config.h"

#include "user_mgr.hpp"

#include "file.hpp"
#include "shadowlock.hpp"
#include "users.hpp"

#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <boost/algorithm/string/split.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <algorithm>
#include <array>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <vector>
namespace phosphor
{
namespace user
{

static constexpr const char* passwdFileName = "/etc/passwd";
static constexpr size_t ipmiMaxUserNameLen = 16;
static constexpr size_t systemMaxUserNameLen = 30;
static constexpr const char* grpSsh = "ssh";
static constexpr int success = 0;
static constexpr int failure = -1;

// pam modules related
static constexpr const char* minPasswdLenProp = "minlen";
static constexpr const char* remOldPasswdCount = "remember";
static constexpr const char* maxFailedAttempt = "deny";
static constexpr const char* unlockTimeout = "unlock_time";
static constexpr const char* defaultFaillockConfigFile =
    "/etc/security/faillock.conf";
static constexpr const char* defaultPWHistoryConfigFile =
    "/etc/security/pwhistory.conf";
static constexpr const char* defaultPWQualityConfigFile =
    "/etc/security/pwquality.conf";

// Object Manager related
static constexpr const char* ldapMgrObjBasePath =
    "/xyz/openbmc_project/user/ldap";

// Object Mapper related
static constexpr const char* objMapperService =
    "xyz.openbmc_project.ObjectMapper";
static constexpr const char* objMapperPath =
    "/xyz/openbmc_project/object_mapper";
static constexpr const char* objMapperInterface =
    "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;
using InsufficientPermission =
    sdbusplus::xyz::openbmc_project::Common::Error::InsufficientPermission;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using UserNameExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameExists;
using UserNameDoesNotExist =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameDoesNotExist;
using UserNameGroupFail =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameGroupFail;
using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using GroupNameExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists;
using GroupNameDoesNotExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameDoesNotExist;

namespace
{
constexpr std::string_view mfaConfPath = "/var/lib/usr_mgr.conf";
// The hardcoded groups in OpenBMC projects
constexpr std::array<const char*, 4> predefinedGroups = {
    "redfish", "ipmi", "ssh", "hostconsole"};

// These prefixes are for Dynamic Redfish authorization. See
// https://github.com/openbmc/docs/blob/master/designs/redfish-authorization.md

// Base role and base privileges are added by Redfish implementation (e.g.,
// BMCWeb) at compile time
constexpr std::array<const char*, 4> allowedGroupPrefix = {
    "openbmc_rfr_",  // OpenBMC Redfish Base Role
    "openbmc_rfp_",  // OpenBMC Redfish Base Privileges
    "openbmc_orfr_", // OpenBMC Redfish OEM Role
    "openbmc_orfp_", // OpenBMC Redfish OEM Privileges
};

void checkAndThrowsForGroupChangeAllowed(const std::string& groupName)
{
    bool allowed = false;
    for (std::string_view prefix : allowedGroupPrefix)
    {
        if (groupName.starts_with(prefix))
        {
            allowed = true;
            break;
        }
    }
    if (!allowed)
    {
        lg2::error("Group name '{GROUP}' is not in the allowed list", "GROUP",
                   groupName);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group Name"),
                              Argument::ARGUMENT_VALUE(groupName.c_str()));
    }
}

} // namespace

std::string getCSVFromVector(std::span<const std::string> vec)
{
    if (vec.empty())
    {
        return "";
    }
    return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                           [](std::string&& val, std::string_view element) {
                               val += ',';
                               val += element;
                               return val;
                           });
}

bool removeStringFromCSV(std::string& csvStr, const std::string& delStr)
{
    std::string::size_type delStrPos = csvStr.find(delStr);
    if (delStrPos != std::string::npos)
    {
        // need to also delete the comma char
        if (delStrPos == 0)
        {
            csvStr.erase(delStrPos, delStr.size() + 1);
        }
        else
        {
            csvStr.erase(delStrPos - 1, delStr.size() + 1);
        }
        return true;
    }
    return false;
}

bool UserMgr::isUserExist(const std::string& userName)
{
    if (userName.empty())
    {
        lg2::error("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }
    if (usersList.find(userName) == usersList.end())
    {
        return false;
    }
    return true;
}

void UserMgr::throwForUserDoesNotExist(const std::string& userName)
{
    if (!isUserExist(userName))
    {
        lg2::error("User '{USERNAME}' does not exist", "USERNAME", userName);
        elog<UserNameDoesNotExist>();
    }
}

void UserMgr::checkAndThrowForDisallowedGroupCreation(
    const std::string& groupName)
{
    if (groupName.size() > maxSystemGroupNameLength ||
        !std::regex_match(groupName.c_str(),
                          std::regex("[a-zA-Z_][a-zA-Z_0-9]*")))
    {
        lg2::error("Invalid group name '{GROUP}'", "GROUP", groupName);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group Name"),
                              Argument::ARGUMENT_VALUE(groupName.c_str()));
    }
    checkAndThrowsForGroupChangeAllowed(groupName);
}

void UserMgr::throwForUserExists(const std::string& userName)
{
    if (isUserExist(userName))
    {
        lg2::error("User '{USERNAME}' already exists", "USERNAME", userName);
        elog<UserNameExists>();
    }
}

void UserMgr::throwForUserNameConstraints(
    const std::string& userName, const std::vector<std::string>& groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (userName.length() > ipmiMaxUserNameLen)
        {
            lg2::error("User '{USERNAME}' exceeds IPMI username length limit "
                       "({LENGTH} > {LIMIT})",
                       "USERNAME", userName, "LENGTH", userName.length(),
                       "LIMIT", ipmiMaxUserNameLen);
            elog<UserNameGroupFail>(
                xyz::openbmc_project::User::Common::UserNameGroupFail::REASON(
                    "IPMI length"));
        }
    }
    if (userName.length() > systemMaxUserNameLen)
    {
        lg2::error("User '{USERNAME}' exceeds system username length limit "
                   "({LENGTH} > {LIMIT})",
                   "USERNAME", userName, "LENGTH", userName.length(), "LIMIT",
                   systemMaxUserNameLen);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid length"));
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-Z_][a-zA-Z_0-9]*")))
    {
        lg2::error("Invalid username '{USERNAME}'", "USERNAME", userName);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid data"));
    }
}

void UserMgr::throwForMaxGrpUserCount(
    const std::vector<std::string>& groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (getIpmiUsersCount() >= ipmiMaxUsers)
        {
            lg2::error("IPMI user limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "IPMI user limit reached"));
        }
    }
    else
    {
        if (usersList.size() > 0 && (usersList.size() - getIpmiUsersCount()) >=
                                        (maxSystemUsers - ipmiMaxUsers))
        {
            lg2::error("Non-ipmi User limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "Non-ipmi user limit reached"));
        }
    }
    return;
}

void UserMgr::throwForInvalidPrivilege(const std::string& priv)
{
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        lg2::error("Invalid privilege '{PRIVILEGE}'", "PRIVILEGE", priv);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(priv.c_str()));
    }
}

void UserMgr::throwForInvalidGroups(const std::vector<std::string>& groupNames)
{
    for (auto& group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) ==
            groupsMgr.end())
        {
            lg2::error("Invalid Group Name '{GROUPNAME}'", "GROUPNAME", group);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("GroupName"),
                                  Argument::ARGUMENT_VALUE(group.c_str()));
        }
    }
}

std::vector<std::string> UserMgr::readAllGroupsOnSystem()
{
    std::vector<std::string> allGroups = {predefinedGroups.begin(),
                                          predefinedGroups.end()};
    // rewinds to the beginning of the group database
    setgrent();
    struct group* gr = getgrent();
    while (gr != nullptr)
    {
        std::string group(gr->gr_name);
        for (std::string_view prefix : allowedGroupPrefix)
        {
            if (group.starts_with(prefix))
            {
                allGroups.push_back(gr->gr_name);
            }
        }
        gr = getgrent();
    }
    // close the group database
    endgrent();
    return allGroups;
}

void UserMgr::createUser(std::string userName,
                         std::vector<std::string> groupNames, std::string priv,
                         bool enabled)
{
    throwForInvalidPrivilege(priv);
    throwForInvalidGroups(groupNames);
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserExists(userName);
    throwForUserNameConstraints(userName, groupNames);
    throwForMaxGrpUserCount(groupNames);

    std::string groups = getCSVFromVector(groupNames);
    bool sshRequested = removeStringFromCSV(groups, grpSsh);

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    if (!priv.empty())
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += priv;
    }
    try
    {
        executeUserAdd(userName.c_str(), groups.c_str(), sshRequested, enabled);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to create new user '{USERNAME}'", "USERNAME",
                   userName);
        elog<InternalFailure>();
    }

    // Add the users object before sending out the signal
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= userName;
    std::string userObj(tempObjPath);
    std::sort(groupNames.begin(), groupNames.end());
    usersList.emplace(
        userName, std::make_unique<phosphor::user::Users>(
                      bus, userObj.c_str(), groupNames, priv, enabled, *this));

    lg2::info("User '{USERNAME}' created successfully", "USERNAME", userName);
    return;
}

void UserMgr::deleteUser(std::string userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    try
    {
        // Clear user fail records
        executeUserClearFailRecords(userName.c_str());

        executeUserDelete(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Delete User '{USERNAME}' failed", "USERNAME", userName);
        elog<InternalFailure>();
    }

    usersList.erase(userName);

    lg2::info("User '{USERNAME}' deleted successfully", "USERNAME", userName);
    return;
}

void UserMgr::checkDeleteGroupConstraints(const std::string& groupName)
{
    if (std::find(groupsMgr.begin(), groupsMgr.end(), groupName) ==
        groupsMgr.end())
    {
        lg2::error("Group '{GROUP}' already exists", "GROUP", groupName);
        elog<GroupNameDoesNotExists>();
    }
    checkAndThrowsForGroupChangeAllowed(groupName);
}

void UserMgr::deleteGroup(std::string groupName)
{
    checkDeleteGroupConstraints(groupName);
    try
    {
        executeGroupDeletion(groupName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Failed to delete group '{GROUP}'", "GROUP", groupName);
        elog<InternalFailure>();
    }

    groupsMgr.erase(std::find(groupsMgr.begin(), groupsMgr.end(), groupName));
    UserMgrIface::allGroups(groupsMgr);
    lg2::info("Successfully deleted group '{GROUP}'", "GROUP", groupName);
}

void UserMgr::checkCreateGroupConstraints(const std::string& groupName)
{
    if (std::find(groupsMgr.begin(), groupsMgr.end(), groupName) !=
        groupsMgr.end())
    {
        lg2::error("Group '{GROUP}' already exists", "GROUP", groupName);
        elog<GroupNameExists>();
    }
    checkAndThrowForDisallowedGroupCreation(groupName);
    if (groupsMgr.size() >= maxSystemGroupCount)
    {
        lg2::error("Group limit reached");
        elog<NoResource>(xyz::openbmc_project::User::Common::NoResource::REASON(
            "Group limit reached"));
    }
}

void UserMgr::createGroup(std::string groupName)
{
    checkCreateGroupConstraints(groupName);
    try
    {
        executeGroupCreation(groupName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Failed to create group '{GROUP}'", "GROUP", groupName);
        elog<InternalFailure>();
    }
    groupsMgr.push_back(groupName);
    UserMgrIface::allGroups(groupsMgr);
}

void UserMgr::renameUser(std::string userName, std::string newUserName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    throwForUserExists(newUserName);
    throwForUserNameConstraints(newUserName,
                                usersList[userName].get()->userGroups());
    try
    {
        executeUserRename(userName.c_str(), newUserName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Rename '{USERNAME}' to '{NEWUSERNAME}' failed", "USERNAME",
                   userName, "NEWUSERNAME", newUserName);
        elog<InternalFailure>();
    }
    const auto& user = usersList[userName];
    std::string priv = user.get()->userPrivilege();
    std::vector<std::string> groupNames = user.get()->userGroups();
    bool enabled = user.get()->userEnabled();
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= newUserName;
    std::string newUserObj(tempObjPath);
    // Special group 'ipmi' needs a way to identify user renamed, in order to
    // update encrypted password. It can't rely only on InterfacesRemoved &
    // InterfacesAdded. So first send out userRenamed signal.
    this->userRenamed(userName, newUserName);
    usersList.erase(userName);
    usersList.emplace(newUserName, std::make_unique<phosphor::user::Users>(
                                       bus, newUserObj.c_str(), groupNames,
                                       priv, enabled, *this));
    return;
}

void UserMgr::updateGroupsAndPriv(const std::string& userName,
                                  std::vector<std::string> groupNames,
                                  const std::string& priv)
{
    throwForInvalidPrivilege(priv);
    throwForInvalidGroups(groupNames);
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    const std::vector<std::string>& oldGroupNames =
        usersList[userName].get()->userGroups();
    std::vector<std::string> groupDiff;
    // Note: already dealing with sorted group lists.
    std::set_symmetric_difference(oldGroupNames.begin(), oldGroupNames.end(),
                                  groupNames.begin(), groupNames.end(),
                                  std::back_inserter(groupDiff));
    if (std::find(groupDiff.begin(), groupDiff.end(), "ipmi") !=
        groupDiff.end())
    {
        throwForUserNameConstraints(userName, groupNames);
        throwForMaxGrpUserCount(groupNames);
    }

    std::string groups = getCSVFromVector(groupNames);
    bool sshRequested = removeStringFromCSV(groups, grpSsh);

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    if (!priv.empty())
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += priv;
    }
    try
    {
        executeUserModify(userName.c_str(), groups.c_str(), sshRequested);
    }
    catch (const InternalFailure& e)
    {
        lg2::error(
            "Unable to modify user privilege / groups for user '{USERNAME}'",
            "USERNAME", userName);
        elog<InternalFailure>();
    }

    std::sort(groupNames.begin(), groupNames.end());
    usersList[userName]->setUserGroups(groupNames);
    usersList[userName]->setUserPrivilege(priv);
    lg2::info("User '{USERNAME}' groups / privilege updated successfully",
              "USERNAME", userName);
}

uint8_t UserMgr::minPasswordLength(uint8_t value)
{
    if (value == AccountPolicyIface::minPasswordLength())
    {
        return value;
    }
    if (value < minPasswdLength)
    {
        lg2::error("Attempting to set minPasswordLength to {VALUE}, less than "
                   "{MINVALUE}",
                   "VALUE", value, "MINVALUE", minPasswdLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("minPasswordLength"),
            Argument::ARGUMENT_VALUE(std::to_string(value).c_str()));
    }
    if (setPamModuleConfValue(pwQualityConfigFile, minPasswdLenProp,
                              std::to_string(value)) != success)
    {
        lg2::error("Unable to set minPasswordLength to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
    return AccountPolicyIface::minPasswordLength(value);
}

uint8_t UserMgr::rememberOldPasswordTimes(uint8_t value)
{
    if (value == AccountPolicyIface::rememberOldPasswordTimes())
    {
        return value;
    }
    if (setPamModuleConfValue(pwHistoryConfigFile, remOldPasswdCount,
                              std::to_string(value)) != success)
    {
        lg2::error("Unable to set rememberOldPasswordTimes to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
    return AccountPolicyIface::rememberOldPasswordTimes(value);
}

uint16_t UserMgr::maxLoginAttemptBeforeLockout(uint16_t value)
{
    if (value == AccountPolicyIface::maxLoginAttemptBeforeLockout())
    {
        return value;
    }
    if (setPamModuleConfValue(faillockConfigFile, maxFailedAttempt,
                              std::to_string(value)) != success)
    {
        lg2::error("Unable to set maxLoginAttemptBeforeLockout to {VALUE}",
                   "VALUE", value);
        elog<InternalFailure>();
    }
    return AccountPolicyIface::maxLoginAttemptBeforeLockout(value);
}

uint32_t UserMgr::accountUnlockTimeout(uint32_t value)
{
    if (value == AccountPolicyIface::accountUnlockTimeout())
    {
        return value;
    }
    if (setPamModuleConfValue(faillockConfigFile, unlockTimeout,
                              std::to_string(value)) != success)
    {
        lg2::error("Unable to set accountUnlockTimeout to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
    return AccountPolicyIface::accountUnlockTimeout(value);
}

int UserMgr::getPamModuleConfValue(const std::string& confFile,
                                   const std::string& argName,
                                   std::string& argValue)
{
    std::ifstream fileToRead(confFile, std::ios::in);
    if (!fileToRead.is_open())
    {
        lg2::error("Failed to open pam configuration file {FILENAME}",
                   "FILENAME", confFile);
        return failure;
    }
    std::string line;
    auto argSearch = argName + "=";
    size_t startPos = 0;
    size_t endPos = 0;
    while (getline(fileToRead, line))
    {
        // skip comments section starting with #
        if ((startPos = line.find('#')) != std::string::npos)
        {
            if (startPos == 0)
            {
                continue;
            }
            // skip comments after meaningful section and process those
            line = line.substr(0, startPos);
        }
        if ((startPos = line.find(argSearch)) != std::string::npos)
        {
            if ((endPos = line.find(' ', startPos)) == std::string::npos)
            {
                endPos = line.size();
            }
            startPos += argSearch.size();
            argValue = line.substr(startPos, endPos - startPos);
            return success;
        }
    }
    return failure;
}

int UserMgr::setPamModuleConfValue(const std::string& confFile,
                                   const std::string& argName,
                                   const std::string& argValue)
{
    std::string tmpConfFile = confFile + "_tmp";
    std::ifstream fileToRead(confFile, std::ios::in);
    std::ofstream fileToWrite(tmpConfFile, std::ios::out);
    if (!fileToRead.is_open() || !fileToWrite.is_open())
    {
        lg2::error("Failed to open pam configuration file {FILENAME}",
                   "FILENAME", confFile);
        // Delete the unused tmp file
        std::remove(tmpConfFile.c_str());
        return failure;
    }
    std::string line;
    auto argSearch = argName + "=";
    size_t startPos = 0;
    size_t endPos = 0;
    bool found = false;
    while (getline(fileToRead, line))
    {
        // skip comments section starting with #
        if ((startPos = line.find('#')) != std::string::npos)
        {
            if (startPos == 0)
            {
                fileToWrite << line << std::endl;
                continue;
            }
            // skip comments after meaningful section and process those
            line = line.substr(0, startPos);
        }
        if ((startPos = line.find(argSearch)) != std::string::npos)
        {
            if ((endPos = line.find(' ', startPos)) == std::string::npos)
            {
                endPos = line.size();
            }
            startPos += argSearch.size();
            fileToWrite << line.substr(0, startPos) << argValue
                        << line.substr(endPos, line.size() - endPos)
                        << std::endl;
            found = true;
            continue;
        }
        fileToWrite << line << std::endl;
    }
    fileToWrite.close();
    fileToRead.close();
    if (found)
    {
        if (std::rename(tmpConfFile.c_str(), confFile.c_str()) == 0)
        {
            return success;
        }
    }
    // No changes, so delete the unused tmp file
    std::remove(tmpConfFile.c_str());
    return failure;
}

void UserMgr::userEnable(const std::string& userName, bool enabled)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    try
    {
        executeUserModifyUserEnable(userName.c_str(), enabled);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to modify user enabled state for '{USERNAME}'",
                   "USERNAME", userName);
        elog<InternalFailure>();
    }

    usersList[userName]->setUserEnabled(enabled);
    lg2::info("User '{USERNAME}' has been {STATUS}", "USERNAME", userName,
              "STATUS", enabled ? "Enabled" : "Disabled");
}

/**
 * faillock app will provide the user failed login list with when the attempt
 * was made, the type, the source, and if it's valid.
 *
 * Valid in this case means that the attempt was made within the fail_interval
 * time. So, we can check this list for the number of valid entries (lines
 * ending with 'V') compared to the maximum allowed to determine if the user is
 * locked out.
 *
 * This data is only refreshed when an attempt is made, so if the user appears
 * to be locked out, we must also check if the most recent attempt was older
 * than the unlock_time to know if the user has since been unlocked.
 **/
bool UserMgr::parseFaillockForLockout(
    const std::vector<std::string>& faillockOutput)
{
    uint16_t failAttempts = 0;
    time_t lastFailedAttempt{};
    for (const std::string& line : faillockOutput)
    {
        if (!line.ends_with("V"))
        {
            continue;
        }

        // Count this failed attempt
        failAttempts++;

        // Update the last attempt time
        // First get the "when" which is the first two words (date and time)
        size_t pos = line.find(" ");
        if (pos == std::string::npos)
        {
            continue;
        }
        pos = line.find(" ", pos + 1);
        if (pos == std::string::npos)
        {
            continue;
        }
        std::string failDateTime = line.substr(0, pos);

        // NOTE: Cannot use std::get_time() here as the implementation of %y in
        // libstdc++ does not match POSIX strptime() before gcc 12.1.0
        // https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=a8d3c98746098e2784be7144c1ccc9fcc34a0888
        std::tm tmStruct = {};
        if (!strptime(failDateTime.c_str(), "%F %T", &tmStruct))
        {
            lg2::error("Failed to parse latest failure date/time");
            elog<InternalFailure>();
        }

        time_t failTimestamp = std::mktime(&tmStruct);
        lastFailedAttempt = std::max(failTimestamp, lastFailedAttempt);
    }

    if (failAttempts < AccountPolicyIface::maxLoginAttemptBeforeLockout())
    {
        return false;
    }

    if (lastFailedAttempt +
            static_cast<time_t>(AccountPolicyIface::accountUnlockTimeout()) <=
        std::time(NULL))
    {
        return false;
    }

    return true;
}

bool UserMgr::userLockedForFailedAttempt(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    if (AccountPolicyIface::maxLoginAttemptBeforeLockout() == 0)
    {
        return false;
    }

    std::vector<std::string> output;
    try
    {
        output = getFailedAttempt(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to read login failure counter");
        elog<InternalFailure>();
    }

    return parseFaillockForLockout(output);
}

bool UserMgr::userLockedForFailedAttempt(const std::string& userName,
                                         const bool& value)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    if (value == true)
    {
        return userLockedForFailedAttempt(userName);
    }

    try
    {
        // Clear user fail records
        executeUserClearFailRecords(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to reset login failure counter");
        elog<InternalFailure>();
    }

    return userLockedForFailedAttempt(userName);
}

bool UserMgr::userPasswordExpired(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};

    struct spwd spwd
    {};
    struct spwd* spwdPtr = nullptr;
    auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen < -1)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }
    std::vector<char> buffer(buflen);
    auto status =
        getspnam_r(userName.c_str(), &spwd, buffer.data(), buflen, &spwdPtr);
    // On success, getspnam_r() returns zero, and sets *spwdPtr to spwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *spwdPtr
    if ((status == 0) && (&spwd == spwdPtr))
    {
        // Determine password validity per "chage" docs, where:
        //   spwd.sp_lstchg == 0 means password is expired, and
        //   spwd.sp_max == -1 means the password does not expire.
        constexpr long secondsPerDay = 60 * 60 * 24;
        long today = static_cast<long>(time(NULL)) / secondsPerDay;
        if ((spwd.sp_lstchg == 0) ||
            ((spwd.sp_max != -1) && ((spwd.sp_max + spwd.sp_lstchg) < today)))
        {
            return true;
        }
    }
    else
    {
        // User entry is missing in /etc/shadow, indicating no SHA password.
        // Treat this as new user without password entry in /etc/shadow
        // TODO: Add property to indicate user password was not set yet
        // https://github.com/openbmc/phosphor-user-manager/issues/8
        return false;
    }

    return false;
}

UserSSHLists UserMgr::getUserAndSshGrpList()
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};

    std::vector<std::string> userList;
    std::vector<std::string> sshUsersList;
    struct passwd pw, *pwp = nullptr;
    std::array<char, 1024> buffer{};

    phosphor::user::File passwd(passwdFileName, "r");
    if ((passwd)() == NULL)
    {
        lg2::error("Error opening {FILENAME}", "FILENAME", passwdFileName);
        elog<InternalFailure>();
    }

    while (true)
    {
        auto r = fgetpwent_r((passwd)(), &pw, buffer.data(), buffer.max_size(),
                             &pwp);
        if ((r != 0) || (pwp == NULL))
        {
            // Any error, break the loop.
            break;
        }
#ifdef ENABLE_ROOT_USER_MGMT
        // Add all users whose UID >= 1000 and < 65534
        // and special UID 0.
        if ((pwp->pw_uid == 0) ||
            ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534)))
#else
        // Add all users whose UID >=1000 and < 65534
        if ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534))
#endif
        {
            std::string userName(pwp->pw_name);
            userList.emplace_back(userName);

            // ssh doesn't have separate group. Check login shell entry to
            // get all users list which are member of ssh group.
            std::string loginShell(pwp->pw_shell);
            if (loginShell == "/bin/sh")
            {
                sshUsersList.emplace_back(userName);
            }
        }
    }
    endpwent();
    return std::make_pair(std::move(userList), std::move(sshUsersList));
}

size_t UserMgr::getIpmiUsersCount()
{
    std::vector<std::string> userList = getUsersInGroup("ipmi");
    return userList.size();
}

size_t UserMgr::getNonIpmiUsersCount()
{
    std::vector<std::string> ipmiUsers = getUsersInGroup("ipmi");
    return usersList.size() - ipmiUsers.size();
}

bool UserMgr::isUserEnabled(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    std::array<char, 4096> buffer{};
    struct spwd spwd;
    struct spwd* resultPtr = nullptr;
    int status = getspnam_r(userName.c_str(), &spwd, buffer.data(),
                            buffer.max_size(), &resultPtr);
    if (!status && (&spwd == resultPtr))
    {
        if (resultPtr->sp_expire >= 0)
        {
            return false; // user locked out
        }
        return true;
    }
    return false; // assume user is disabled for any error.
}

std::vector<std::string> UserMgr::getUsersInGroup(const std::string& groupName)
{
    std::vector<std::string> usersInGroup;
    // Should be more than enough to get the pwd structure.
    std::array<char, 4096> buffer{};
    struct group grp;
    struct group* resultPtr = nullptr;

    int status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.max_size(), &resultPtr);

    if (!status && (&grp == resultPtr))
    {
        for (; *(grp.gr_mem) != NULL; ++(grp.gr_mem))
        {
            usersInGroup.emplace_back(*(grp.gr_mem));
        }
    }
    else
    {
        lg2::error("Group '{GROUPNAME}' not found", "GROUPNAME", groupName);
        // Don't throw error, just return empty userList - fallback
    }
    return usersInGroup;
}

DbusUserObj UserMgr::getPrivilegeMapperObject(void)
{
    DbusUserObj objects;
    try
    {
        std::string basePath = "/xyz/openbmc_project/user/ldap/openldap";
        std::string interface = "xyz.openbmc_project.User.Ldap.Config";

        auto ldapMgmtService =
            getServiceName(std::move(basePath), std::move(interface));
        auto method = bus.new_method_call(
            ldapMgmtService.c_str(), ldapMgrObjBasePath,
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to get the User Service: {ERR}", "ERR", e);
        throw;
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to execute GetManagedObjects at {PATH}: {ERR}",
                   "PATH", ldapMgrObjBasePath, "ERR", e);
        throw;
    }
    return objects;
}

std::string UserMgr::getServiceName(std::string&& path, std::string&& intf)
{
    auto mapperCall = bus.new_method_call(objMapperService, objMapperPath,
                                          objMapperInterface, "GetObject");

    mapperCall.append(std::move(path));
    mapperCall.append(std::vector<std::string>({std::move(intf)}));

    auto mapperResponseMsg = bus.call(mapperCall);

    if (mapperResponseMsg.is_method_error())
    {
        lg2::error("Error in mapper call");
        elog<InternalFailure>();
    }

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        lg2::error("Invalid response from mapper");
        elog<InternalFailure>();
    }

    return mapperResponse.begin()->first;
}

gid_t UserMgr::getPrimaryGroup(const std::string& userName) const
{
    static auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen <= 0)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }

    struct passwd pwd;
    struct passwd* pwdPtr = nullptr;
    std::vector<char> buffer(buflen);

    auto status = getpwnam_r(userName.c_str(), &pwd, buffer.data(),
                             buffer.size(), &pwdPtr);
    // On success, getpwnam_r() returns zero, and set *pwdPtr to pwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *pwdPtr
    if (!status && (&pwd == pwdPtr))
    {
        return pwd.pw_gid;
    }

    lg2::error("User {USERNAME} does not exist", "USERNAME", userName);
    elog<UserNameDoesNotExist>();
}

bool UserMgr::isGroupMember(const std::string& userName, gid_t primaryGid,
                            const std::string& groupName) const
{
    static auto buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buflen <= 0)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }

    struct group grp;
    struct group* grpPtr = nullptr;
    std::vector<char> buffer(buflen);

    auto status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                             buffer.size(), &grpPtr);

    // Groups with a lot of members may require a buffer of bigger size than
    // suggested by _SC_GETGR_R_SIZE_MAX.
    // 32K should be enough for about 2K members.
    constexpr auto maxBufferLength = 32 * 1024;
    while (status == ERANGE && buflen < maxBufferLength)
    {
        buflen *= 2;
        buffer.resize(buflen);

        lg2::debug("Increase buffer for getgrnam_r() to {SIZE}", "SIZE",
                   buflen);

        status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.size(), &grpPtr);
    }

    // On success, getgrnam_r() returns zero, and set *grpPtr to grp.
    // If no matching group record was found, these functions return 0
    // and store NULL in *grpPtr
    if (!status && (&grp == grpPtr))
    {
        if (primaryGid == grp.gr_gid)
        {
            return true;
        }

        for (auto i = 0; grp.gr_mem && grp.gr_mem[i]; ++i)
        {
            if (userName == grp.gr_mem[i])
            {
                return true;
            }
        }
    }
    else if (status == ERANGE)
    {
        lg2::error("Group info of {GROUP} requires too much memory", "GROUP",
                   groupName);
    }
    else
    {
        lg2::error("Group {GROUP} does not exist", "GROUP", groupName);
    }

    return false;
}

void UserMgr::executeGroupCreation(const char* groupName)
{
    executeCmd("/usr/sbin/groupadd", groupName);
}

void UserMgr::executeGroupDeletion(const char* groupName)
{
    executeCmd("/usr/sbin/groupdel", groupName);
}

UserInfoMap UserMgr::getUserInfo(std::string userName)
{
    UserInfoMap userInfo;
    // Check whether the given user is local user or not.
    if (isUserExist(userName))
    {
        const auto& user = usersList[userName];
        userInfo.emplace("UserPrivilege", user.get()->userPrivilege());
        userInfo.emplace("UserGroups", user.get()->userGroups());
        userInfo.emplace("UserEnabled", user.get()->userEnabled());
        userInfo.emplace("UserLockedForFailedAttempt",
                         user.get()->userLockedForFailedAttempt());
        userInfo.emplace("UserPasswordExpired",
                         user.get()->userPasswordExpired());
        userInfo.emplace("RemoteUser", false);
    }
    else
    {
        auto primaryGid = getPrimaryGroup(userName);

        DbusUserObj objects = getPrivilegeMapperObject();

        std::string ldapConfigPath;
        std::string userPrivilege;

        try
        {
            for (const auto& [path, interfaces] : objects)
            {
                auto it = interfaces.find("xyz.openbmc_project.Object.Enable");
                if (it != interfaces.end())
                {
                    auto propIt = it->second.find("Enabled");
                    if (propIt != it->second.end() &&
                        std::get<bool>(propIt->second))
                    {
                        ldapConfigPath = path.str + '/';
                        break;
                    }
                }
            }

            if (ldapConfigPath.empty())
            {
                return userInfo;
            }

            for (const auto& [path, interfaces] : objects)
            {
                if (!path.str.starts_with(ldapConfigPath))
                {
                    continue;
                }

                auto it = interfaces.find(
                    "xyz.openbmc_project.User.PrivilegeMapperEntry");
                if (it != interfaces.end())
                {
                    std::string privilege;
                    std::string groupName;

                    for (const auto& [propName, propValue] : it->second)
                    {
                        if (propName == "GroupName")
                        {
                            groupName = std::get<std::string>(propValue);
                        }
                        else if (propName == "Privilege")
                        {
                            privilege = std::get<std::string>(propValue);
                        }
                    }

                    if (!groupName.empty() && !privilege.empty() &&
                        isGroupMember(userName, primaryGid, groupName))
                    {
                        userPrivilege = privilege;
                        break;
                    }
                }
                if (!userPrivilege.empty())
                {
                    break;
                }
            }

            if (!userPrivilege.empty())
            {
                userInfo.emplace("UserPrivilege", userPrivilege);
            }
            else
            {
                lg2::warning("LDAP group privilege mapping does not exist, "
                             "default \"priv-user\" is used");
                userInfo.emplace("UserPrivilege", "priv-user");
            }
        }
        catch (const std::bad_variant_access& e)
        {
            lg2::error("Error while accessing variant: {ERR}", "ERR", e);
            elog<InternalFailure>();
        }
        userInfo.emplace("RemoteUser", true);
    }

    return userInfo;
}

void UserMgr::initializeAccountPolicy()
{
    std::string valueStr;
    auto value = minPasswdLength;
    unsigned long tmp = 0;
    if (getPamModuleConfValue(pwQualityConfigFile, minPasswdLenProp,
                              valueStr) != success)
    {
        AccountPolicyIface::minPasswordLength(minPasswdLength);
    }
    else
    {
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value = static_cast<decltype(value)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for MinPasswordLength: {ERR}", "ERR", e);
            throw;
        }
        AccountPolicyIface::minPasswordLength(value);
    }
    valueStr.clear();
    if (getPamModuleConfValue(pwHistoryConfigFile, remOldPasswdCount,
                              valueStr) != success)
    {
        AccountPolicyIface::rememberOldPasswordTimes(0);
    }
    else
    {
        value = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value = static_cast<decltype(value)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for RememberOldPasswordTimes: {ERR}", "ERR",
                       e);
            throw;
        }
        AccountPolicyIface::rememberOldPasswordTimes(value);
    }
    valueStr.clear();
    if (getPamModuleConfValue(faillockConfigFile, maxFailedAttempt, valueStr) !=
        success)
    {
        AccountPolicyIface::maxLoginAttemptBeforeLockout(0);
    }
    else
    {
        uint16_t value16 = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value16)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value16 = static_cast<decltype(value16)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for MaxLoginAttemptBeforLockout: {ERR}",
                       "ERR", e);
            throw;
        }
        AccountPolicyIface::maxLoginAttemptBeforeLockout(value16);
    }
    valueStr.clear();
    if (getPamModuleConfValue(faillockConfigFile, unlockTimeout, valueStr) !=
        success)
    {
        AccountPolicyIface::accountUnlockTimeout(0);
    }
    else
    {
        uint32_t value32 = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value32)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value32 = static_cast<decltype(value32)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for AccountUnlockTimeout: {ERR}", "ERR", e);
            throw;
        }
        AccountPolicyIface::accountUnlockTimeout(value32);
    }
}

void UserMgr::initUserObjects(void)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    std::vector<std::string> userNameList;
    std::vector<std::string> sshGrpUsersList;
    UserSSHLists userSSHLists = getUserAndSshGrpList();
    userNameList = std::move(userSSHLists.first);
    sshGrpUsersList = std::move(userSSHLists.second);

    if (!userNameList.empty())
    {
        std::map<std::string, std::vector<std::string>> groupLists;
        // We only track users that are in the |predefinedGroups|
        // The other groups don't contain real BMC users.
        for (const char* grp : predefinedGroups)
        {
            if (grp == grpSsh)
            {
                groupLists.emplace(grp, sshGrpUsersList);
            }
            else
            {
                std::vector<std::string> grpUsersList = getUsersInGroup(grp);
                groupLists.emplace(grp, grpUsersList);
            }
        }
        for (auto& grp : privMgr)
        {
            std::vector<std::string> grpUsersList = getUsersInGroup(grp);
            groupLists.emplace(grp, grpUsersList);
        }

        for (auto& user : userNameList)
        {
            std::vector<std::string> userGroups;
            std::string userPriv;
            for (const auto& grp : groupLists)
            {
                std::vector<std::string> tempGrp = grp.second;
                if (std::find(tempGrp.begin(), tempGrp.end(), user) !=
                    tempGrp.end())
                {
                    if (std::find(privMgr.begin(), privMgr.end(), grp.first) !=
                        privMgr.end())
                    {
                        userPriv = grp.first;
                    }
                    else
                    {
                        userGroups.emplace_back(grp.first);
                    }
                }
            }
            // Add user objects to the Users path.
            sdbusplus::message::object_path tempObjPath(usersObjPath);
            tempObjPath /= user;
            std::string objPath(tempObjPath);
            std::sort(userGroups.begin(), userGroups.end());
            usersList.emplace(user, std::make_unique<phosphor::user::Users>(
                                        bus, objPath.c_str(), userGroups,
                                        userPriv, isUserEnabled(user), *this));
            addToWatch(user);
        }
    }
}
void UserMgr::addToWatch(const std::string& userName)
{
    // Add user objects to the Users path.
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= userName;
    std::string objPath(tempObjPath);

    std::string path = std::format("{}/bypassedprotocol", userName);
    serializer.addPropertyMatch(
        bus, tempObjPath, "xyz.openbmc_project.User.TOTPAuthenticator",
        "BypassedProtocol", [this, path](std::string_view value) {
            serializer.serialize(path, value);
        });
}
void UserMgr::load()
{
    if (std::filesystem::exists(mfaConfPath))
    {
        serializer.load();
        std::string authtype;
        serializer.deserialize("authtype", authtype);
        MultiFactorAuthConfiguration::Type type =
            MultiFactorAuthConfiguration::convertTypeFromString(authtype);
        enabled(type, true);
    }
    else
    {
        serializer.serialize("authtype",
                             MultiFactorAuthConfiguration::convertTypeToString(
                                 MultiFactorAuthType::None));
        enabled(MultiFactorAuthType::None, true);
    }
    for (auto& user : usersList)
    {
        user.second->load(serializer);
    }
    serializer.store();
}
void UserMgr::addWatchForPersistency()
{
    serializer.addPropertyMatch(
        bus, "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.MultiFactorAuthConfiguration", "Enabled",
        [this](std::string_view value) {
            serializer.serialize("authtype", value);
        });
    serializer.addObjectAddMatch(
        bus, "/xyz/openbmc_project/user",
        "xyz.openbmc_project.User.TOTPAuthenticator",
        [this](const std::string& path) {
            std::string user =
                path.substr(path.find_last_of('/') + 1, path.size());
            lg2::info("User {USER} has been added", "USER", user);
            auto userObject =
                usersList | std::ranges::views::filter([&user](auto& u) {
                    return u.first == user;
                });
            for (auto& u : userObject)
            {
                u.second->load(serializer);
            }
            addToWatch(user);
        });
}
UserMgr::UserMgr(sdbusplus::bus_t& bus, const char* path) :
    Ifaces(bus, path, Ifaces::action::defer_emit), bus(bus), path(path),
    faillockConfigFile(defaultFaillockConfigFile),
    pwHistoryConfigFile(defaultPWHistoryConfigFile),
    pwQualityConfigFile(defaultPWQualityConfigFile),
    serializer(mfaConfPath.data())
{
    UserMgrIface::allPrivileges(privMgr);
    groupsMgr = readAllGroupsOnSystem();
    std::sort(groupsMgr.begin(), groupsMgr.end());
    UserMgrIface::allGroups(groupsMgr);
    initializeAccountPolicy();
    initUserObjects();
    addWatchForPersistency();
    // emit the signal
    this->emit_object_added();
}

void UserMgr::executeUserAdd(const char* userName, const char* groups,
                             bool sshRequested, bool enabled)
{
    // set EXPIRE_DATE to 0 to disable user, PAM takes 0 as expire on
    // 1970-01-01, that's an implementation-defined behavior
    executeCmd("/usr/sbin/useradd", userName, "-G", groups, "-m", "-N", "-s",
               (sshRequested ? "/bin/sh" : "/sbin/nologin"), "-e",
               (enabled ? "" : "1970-01-01"));
}

void UserMgr::executeUserDelete(const char* userName)
{
    executeCmd("/usr/sbin/userdel", userName, "-r");
}

void UserMgr::executeUserClearFailRecords(const char* userName)
{
    executeCmd("/usr/sbin/faillock", "--user", userName, "--reset");
}

void UserMgr::executeUserRename(const char* userName, const char* newUserName)
{
    std::string newHomeDir = "/home/";
    newHomeDir += newUserName;
    executeCmd("/usr/sbin/usermod", "-l", newUserName, userName, "-d",
               newHomeDir.c_str(), "-m");
}

void UserMgr::executeUserModify(const char* userName, const char* newGroups,
                                bool sshRequested)
{
    executeCmd("/usr/sbin/usermod", userName, "-G", newGroups, "-s",
               (sshRequested ? "/bin/sh" : "/sbin/nologin"));
}

void UserMgr::executeUserModifyUserEnable(const char* userName, bool enabled)
{
    // set EXPIRE_DATE to 0 to disable user, PAM takes 0 as expire on
    // 1970-01-01, that's an implementation-defined behavior
    executeCmd("/usr/sbin/usermod", userName, "-e",
               (enabled ? "" : "1970-01-01"));
}

std::vector<std::string> UserMgr::getFailedAttempt(const char* userName)
{
    return executeCmd("/usr/sbin/faillock", "--user", userName);
}

std::set<MultiFactorAuthType>& allAuthTypes()
{
    using namespace sdbusplus::common::xyz::openbmc_project::user::details;
    static std::set<MultiFactorAuthType> authTypeSet;
    if (authTypeSet.empty())
    {
        for (const auto& item : mappingMultiFactorAuthConfigurationType)
        {
            authTypeSet.insert(std::get<1>(item));
        }
    }
    return authTypeSet;
}
MultiFactorAuthType UserMgr::enabled(MultiFactorAuthType value, bool skipSignal)
{
    switch (value)
    {
        case MultiFactorAuthType::None:
            for (auto type : allAuthTypes())
            {
                for (auto& u : usersList)
                {
                    u.second->enableMultiFactorAuth(type, false);
                }
            }
            break;
        case MultiFactorAuthType::GoogleAuthenticator:
            for (auto& u : usersList)
            {
                u.second->enableMultiFactorAuth(
                    MultiFactorAuthType::GoogleAuthenticator, true);
            }
            break;
    }
    return MultiFactorAuthConfigurationIface::enabled(value, skipSignal);
}

} // namespace user
} // namespace phosphor
