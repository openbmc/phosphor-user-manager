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

#include <shadow.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <regex>
#include <algorithm>
#include <boost/process/child.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "shadowlock.hpp"
#include "file.hpp"
#include "user_mgr.hpp"
#include "users.hpp"
#include "config.h"

namespace phosphor
{
namespace user
{

static constexpr const char *passwdFileName = "/etc/passwd";
static constexpr size_t ipmiMaxUsers = 15;
static constexpr size_t ipmiMaxUserNameLen = 16;
static constexpr size_t systemMaxUserNameLen = 30;
static constexpr size_t maxSystemUsers = 30;
static constexpr const char *grpSsh = "ssh";

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

template <typename... ArgTypes>
static void executeCmd(const char *path, ArgTypes &&... tArgs)
{
    boost::process::child execProg(path, const_cast<char *>(tArgs)...);
    execProg.wait();
    int retCode = execProg.exit_code();
    if (retCode)
    {
        log<level::ERR>("Command execution failed", entry("PATH=%s", path),
                        entry("RETURN_CODE:%d", retCode));
        elog<InternalFailure>();
    }
    return;
}

void UserMgr::throwForUserDoesNotExist(const std::string &userName)
{
    if (userName.empty())
    {
        log<level::ERR>("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }
    if (usersList.find(userName) == usersList.end())
    {
        log<level::ERR>("User does not exist",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<UserNameDoesNotExist>();
    }
}

void UserMgr::throwForUserExists(const std::string &userName)
{
    if (userName.empty())
    {
        log<level::ERR>("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }
    if (usersList.find(userName) != usersList.end())
    {
        log<level::ERR>("User already exists",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<UserNameExists>();
    }
}

void UserMgr::throwForUserNameConstraints(
    const std::string &userName, const std::vector<std::string> &groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (userName.length() > ipmiMaxUserNameLen)
        {
            log<level::ERR>("IPMI user name length limitation",
                            entry("SIZE=%d", userName.length()));
            elog<UserNameGroupFail>(
                xyz::openbmc_project::User::Common::UserNameGroupFail::REASON(
                    "IPMI length"));
        }
    }
    if (userName.length() > systemMaxUserNameLen)
    {
        log<level::ERR>("User name length limitation",
                        entry("SIZE=%d", userName.length()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid length"));
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        log<level::ERR>("Invalid user name",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid data"));
    }
}

void UserMgr::throwForMaxGrpUserCount(
    const std::vector<std::string> &groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (getIpmiUsersCount() >= ipmiMaxUsers)
        {
            log<level::ERR>("IPMI user limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "ipmi user count reached"));
        }
    }
    else
    {
        if (usersList.size() > 0 && (usersList.size() - getIpmiUsersCount()) >=
                                        (maxSystemUsers - ipmiMaxUsers))
        {
            log<level::ERR>("Non-ipmi User limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "Non-ipmi user count reached"));
        }
    }
    return;
}

void UserMgr::createUser(std::string userName,
                         std::vector<std::string> groupNames, std::string priv,
                         bool enabled)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    throwForUserExists(userName);
    throwForUserNameConstraints(userName, groupNames);
    throwForMaxGrpUserCount(groupNames);
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE("Invalid"));
    }

    std::string addGroup;
    bool sshRequested = false;
    for (const auto &group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) !=
            groupsMgr.end())
        {
            if (group == grpSsh)
            {
                sshRequested = true;
                continue;
            }
            if (addGroup.empty())
            {
                addGroup = group;
            }
            else
            {
                addGroup += "," + group;
            }
        }
        else
        {
            log<level::ERR>("Invalid Group Name listed");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("GroupName"),
                                  Argument::ARGUMENT_VALUE("Invalid"));
        }
    }

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    addGroup += "," + priv;
    try
    {
        executeCmd("/usr/sbin/useradd", userName.c_str(), "-G",
                   addGroup.c_str(), "-M", "-N", "-s",
                   (sshRequested ? "/bin/bash" : "/bin/nologin"), "-e",
                   (enabled ? "" : "1970-01-02"));
    }
    catch (const InternalFailure &e)
    {
        log<level::ERR>("Unable to create new user");
        elog<InternalFailure>();
    }

    // Add the users object before sending out the signal
    std::string userObj = std::string(usersObjPath) + "/" + userName;
    std::sort(groupNames.begin(), groupNames.end());
    usersList.emplace(
        userName, std::move(std::make_unique<phosphor::user::Users>(
                      bus, userObj.c_str(), groupNames, priv, enabled, *this)));

    log<level::INFO>("User created successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::deleteUser(std::string userName)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    throwForUserDoesNotExist(userName);
    try
    {
        executeCmd("/usr/sbin/userdel", userName.c_str());
    }
    catch (const InternalFailure &e)
    {
        log<level::ERR>("User delete failed",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<InternalFailure>();
    }

    usersList.erase(userName);

    log<level::INFO>("User deleted successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::renameUser(std::string userName, std::string newUserName)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    throwForUserDoesNotExist(userName);
    throwForUserExists(newUserName);
    throwForUserNameConstraints(newUserName,
                                usersList[userName].get()->userGroups());
    try
    {
        executeCmd("/usr/sbin/usermod", "-l", newUserName.c_str(),
                   userName.c_str());
    }
    catch (const InternalFailure &e)
    {
        log<level::ERR>("User rename failed",
                        entry("USER_NAME=%s", userName.c_str()));
        elog<InternalFailure>();
    }
    phosphor::user::Users *usersPtr = usersList[userName].get();
    std::string priv = usersPtr->userPrivilege();
    std::vector<std::string> groupNames = usersPtr->userGroups();
    bool enabled = usersPtr->userEnabled();
    std::string newUserObj = std::string(usersObjPath) + "/" + newUserName;
    // Special group 'ipmi' needs a way to identify user renamed, in order to
    // update encrypted password. It can't rely only on InterfacesRemoved &
    // InterfacesAdded. So first send out userRenamed signal.
    this->userRenamed(userName, newUserName);
    usersList.erase(userName);
    usersList.emplace(
        newUserName,
        std::move(std::make_unique<phosphor::user::Users>(
            bus, newUserObj.c_str(), groupNames, priv, enabled, *this)));
    return;
}

void UserMgr::updateGroupsAndPriv(const std::string &userName,
                                  const std::vector<std::string> &groupNames,
                                  const std::string &priv)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    throwForUserDoesNotExist(userName);
    const std::vector<std::string> &oldGroupNames =
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
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE("Invalid"));
    }

    std::string addGroup;
    bool sshRequested = false;
    for (auto group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) !=
            groupsMgr.end())
        {
            if (group == grpSsh)
            {
                sshRequested = true;
                continue;
            }
            if (addGroup.empty())
            {
                addGroup += group;
            }
            else
            {
                addGroup += "," + group;
            }
        }
        else
        {
            log<level::ERR>("Invalid Group Name listed");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("GroupName"),
                                  Argument::ARGUMENT_VALUE("Invalid"));
        }
    }
    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    addGroup += "," + priv;
    try
    {
        executeCmd("/usr/sbin/usermod", userName.c_str(), "-G",
                   addGroup.c_str(), "-s",
                   (sshRequested ? "/bin/bash" : "/bin/nologin"));
    }
    catch (const InternalFailure &e)
    {
        log<level::ERR>("Unable to modify user privilege / groups");
        elog<InternalFailure>();
    }

    log<level::INFO>("User groups / privilege updated successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::userEnable(const std::string &userName, bool enabled)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    throwForUserDoesNotExist(userName);
    try
    {
        executeCmd("/usr/sbin/usermod", userName.c_str(), "-e",
                   (enabled ? "" : "1970-01-02"));
    }
    catch (const InternalFailure &e)
    {
        log<level::ERR>("Unable to modify user enabled state");
        elog<InternalFailure>();
    }

    log<level::INFO>("User enabled/disabled state updated successfully",
                     entry("USER_NAME=%s", userName.c_str()),
                     entry("ENABLED=%d", enabled));
    return;
}
void UserMgr::getUserAndSshGrpList(std::vector<std::string> &userList,
                                   std::vector<std::string> &sshUsersList)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    struct passwd pw, *pwp = nullptr;
    std::array<char, 1024> buffer{};

    phosphor::user::File passwd(passwdFileName, "r");
    if ((passwd)() == NULL)
    {
        log<level::ERR>("Error opening the passwd file");
        return;
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
        // All users whose UID >= 1000 and < 65534
        if ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534))
        {
            std::string userName(pwp->pw_name);
            userList.emplace_back(userName);

            // ssh doesn't have separate group. Check login shell entry to
            // get all users list which are member of ssh group.
            std::string loginShell(pwp->pw_shell);
            if (loginShell == "/bin/bash")
            {
                sshUsersList.emplace_back(userName);
            }
        }
    }
    endpwent();
}

size_t UserMgr::getIpmiUsersCount()
{
    std::vector<std::string> userList;
    getGroupUsers("ipmi", userList);
    return userList.size();
}

bool UserMgr::isUserEnabled(const std::string &userName)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    std::array<char, 4096> buffer{};
    struct spwd spwd;
    struct spwd *resultPtr = nullptr;
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

void UserMgr::getGroupUsers(const std::string &groupName,
                            std::vector<std::string> &userList)
{
    // Should be more than enough to get the pwd structure.
    std::array<char, 4096> buffer{};
    struct group grp;
    struct group *resultPtr = nullptr;

    int status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.max_size(), &resultPtr);

    if (!status && (&grp == resultPtr))
    {
        for (; *(grp.gr_mem) != NULL; ++(grp.gr_mem))
        {
            userList.emplace_back(*(grp.gr_mem));
        }
    }
    else
    {
        log<level::ERR>("Group not found",
                        entry("GROUP=%s", groupName.c_str()));
        // Don't throw error, just return empty userList - fallback
    }
}

void UserMgr::initUserObjects(void)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    std::vector<std::string> userNameList;
    std::vector<std::string> sshGrpUsersList;
    getUserAndSshGrpList(userNameList, sshGrpUsersList);

    if (!userNameList.empty())
    {
        std::map<std::string, std::vector<std::string>> groupLists;
        for (auto &grp : groupsMgr)
        {
            if (grp == grpSsh)
            {
                groupLists.emplace(grp, sshGrpUsersList);
            }
            else
            {
                std::vector<std::string> grpUsersList;
                getGroupUsers(grp, grpUsersList);
                groupLists.emplace(grp, grpUsersList);
            }
        }
        for (auto &grp : privMgr)
        {
            std::vector<std::string> grpUsersList;
            getGroupUsers(grp, grpUsersList);
            groupLists.emplace(grp, grpUsersList);
        }

        for (auto &user : userNameList)
        {
            std::vector<std::string> userGroups;
            std::string userPriv;
            for (const auto &grp : groupLists)
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
            auto objPath = std::string(usersObjPath) + "/" + user;
            std::sort(userGroups.begin(), userGroups.end());
            usersList.emplace(user,
                              std::move(std::make_unique<phosphor::user::Users>(
                                  bus, objPath.c_str(), userGroups, userPriv,
                                  isUserEnabled(user), *this)));
        }
    }
}

UserMgr::UserMgr(sdbusplus::bus::bus &bus, const char *path) :
    UserMgrIface(bus, path), bus(bus), path(path)
{
    UserMgrIface::allPrivileges(privMgr);
    std::sort(groupsMgr.begin(), groupsMgr.end());
    UserMgrIface::allGroups(groupsMgr);
    initUserObjects();
}

} // namespace user
} // namespace phosphor
