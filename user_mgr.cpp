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

namespace phosphor {
namespace user {

static const char *PASSWD_FILE_NAME = "/etc/passwd";

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
using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;

using Argument = xyz::openbmc_project::Common::InvalidArgument;

template <typename... ArgTypes>
void executeFile(const char *path, ArgTypes &&... tArgs)
{
    char *args[] = {const_cast<char *>(tArgs)..., nullptr};

    pid_t pid = fork();
    if (pid == 0)
    {
        execv(path, args);
        log<level::ERR>("Cmd execution failed", entry("PATH=%d", path));
        elog<InternalFailure>();
    }
    else if (pid < 0)
    {
        log<level::ERR>("Fork error");
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        int ret_status = -1;
        if (waitpid(pid, &ret_status, 0) != pid)
        {
            log<level::ERR>("Cmd Execution failed", entry("PATH=%s", path));
            elog<InternalFailure>();
        }
    }
    return;
}

void UserMgr::addUser(std::string userName, std::vector<std::string> groupNames,
                      std::string priv)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();

    if (userName.empty())
    {
        log<level::ERR>("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("userName"),
                              Argument::ARGUMENT_VALUE(userName.c_str()));
    }
    if (usersList.find(userName) != usersList.end())
    {
        log<level::INFO>("User already exists",
                         entry("USER_NAME=%s", userName.c_str()));
        elog<UserNameExists>();
    }
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(priv.c_str()));
    }

    std::string addGroup;
    bool sshRequested = false;
    for (const auto &group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) !=
            groupsMgr.end())
        {
            if (group == "ssh")
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
                                  Argument::ARGUMENT_VALUE(group.c_str()));
        }
    }

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    addGroup += "," + priv;
    try
    {
        executeFile("/usr/sbin/useradd", "useradd", userName.c_str(), "-G",
                    addGroup.c_str(), "-M", "-N", "-s",
                    (sshRequested ? "/bin/bash" : "/bin/nologin"));
    }
    catch (...)
    {
        log<level::ERR>("Unable to add new user name");
        elog<InternalFailure>();
    }

    // Add the users object before sending out the signal
    std::string userObj = std::string(USERS_OBJECT_PATH) + "/" + userName;
    usersList.emplace(userName,
                      std::move(std::make_unique<phosphor::user::Users>(
                          bus, userObj.c_str(), groupNames, priv, *this)));

    this->userUpdated(UserMgr::UserUpdate::Added, userName, groupNames, priv);

    log<level::INFO>("User added successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::deleteUser(std::string userName)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();

    // TODO: Need to implement this as C++ code
    // TODO: Based on the group, call the corresponding registered D-Bus API
    if (userName.empty())
    {
        log<level::ERR>("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("userName"),
                              Argument::ARGUMENT_VALUE(userName.c_str()));
    }
    auto userEntry = usersList.find(userName);
    if (userEntry == usersList.end())
    {
        log<level::INFO>("User does not exist",
                         entry("USER_NAME=%s", userName.c_str()));
        elog<UserNameDoesNotExist>();
    }

    try
    {
        executeFile("/usr/sbin/userdel", "userdel", userName.c_str());
    }
    catch (...)
    {
        log<level::INFO>("User deletion failed",
                         entry("USER_NAME=%s", userName.c_str()));
        elog<InternalFailure>();
    }

    std::string priv = userEntry->second.get()->userPrivilege();
    std::vector<std::string> groupNames = userEntry->second.get()->userGroups();

    // Remove the users object before sending out the signal
    usersList.erase(userName);

    this->userUpdated(UserMgr::UserUpdate::Deleted, userName, groupNames, priv);

    log<level::INFO>("User deleted successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::updateGroupsAndPriv(const std::string &userName,
                                  const std::vector<std::string> &groupNames,
                                  const std::string &priv)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();

    // TODO: Need to implement this as C++ code
    if (userName.empty())
    {
        log<level::ERR>("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("userName"),
                              Argument::ARGUMENT_VALUE(userName.c_str()));
    }
    if (usersList.find(userName) == usersList.end())
    {
        log<level::INFO>("User does not exist",
                         entry("USER_NAME=%s", userName.c_str()));
        // TODO: Resolve elog-errors.hpp creation error and uncomment below line
        //        elog<UserNameDoesNotExist>();
        elog<InternalFailure>();
    }
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(priv.c_str()));
    }

    std::string addGroup;
    bool sshRequested = false;
    for (auto group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) !=
            groupsMgr.end())
        {
            if (group == "ssh")
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
                                  Argument::ARGUMENT_VALUE(group.c_str()));
        }
    }
    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    addGroup += "," + priv;
    try
    {
        executeFile("/usr/sbin/usermod", "usermod", userName.c_str(), "-G",
                    addGroup.c_str(), "-s",
                    (sshRequested ? "/bin/bash" : "/bin/nologin"));
    }
    catch (...)
    {
        log<level::ERR>("Unable to modify user privilege / groups");
        elog<InternalFailure>();
    }

    if (priv !=
        usersList[userName].get()->sdbusplus::xyz::openbmc_project::User::
            server::Users::userPrivilege())
    {
        this->userUpdated(UserMgr::UserUpdate::PrivilegeUpdated, userName,
                          groupNames, priv);
    }
    else
    {
        this->userUpdated(UserMgr::UserUpdate::GroupUpdated, userName,
                          groupNames, priv);
    }

    log<level::INFO>("User groups / privilege updated successfully",
                     entry("USER_NAME=%s", userName.c_str()));
    return;
}

void UserMgr::getUserList(std::vector<std::string> &userList)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    // Open passwd file for read only mode and list out all users
    std::ifstream passStream(PASSWD_FILE_NAME);
    if (!passStream.is_open())
    {
        log<level::ERR>("Error in opening passwd file",
                        entry("ERRNO=%s", errno));
        elog<InternalFailure>();
    }

    std::string lineStr;
    size_t userEPos = 0, uidSPos = 0, uidEPos = 0;
    int uid = 0;
    std::string userName;

    // TODO: Try to read whether user belongs to ssh group here itself ??

    // Pass through each and every line, for valid user names
    // /etc/passwd has the following format
    //  name:passwd:UID:GID:GECOS:home directory:login shell
    // Add all the users whose UID >=1000 & < 65534
    while (std::getline(passStream, lineStr))
    {
        if ((userEPos = lineStr.find(":")) == std::string::npos)
        {
            continue;
        }
        if ((uidSPos = lineStr.find(":", userEPos + 1)) == std::string::npos)
        {
            continue;
        }
        if ((uidEPos = lineStr.find(":", uidSPos + 1)) != std::string::npos)
        {
            std::string uidStr =
                lineStr.substr(uidSPos + 1, (uidEPos) - (uidSPos + 1));
            size_t end = 0;
            uid = std::stoi(uidStr, &end);
            if (end != uidStr.size())
            {
                continue;
            }
            if (uid >= 1000 && uid < 65534)
            {
                userName = lineStr.substr(0, userEPos);
                userList.emplace_back(userName);
            }
        }
    }
    if (!passStream.eof())
    {
        log<level::ERR>("Error in parsing passwd file",
                        entry("ERRNO=%s", errno));
        elog<InternalFailure>();
    }
}

void UserMgr::getGroupUsers(const std::string &groupName,
                            std::vector<std::string> &userList)
{
    // Should be more than enough to get the pwd structure.
    std::array<char, 4096> buffer{};
    struct group grp;
    struct group *grpPtr = &grp;
    struct group *resultPtr;

    int status = getgrnam_r(groupName.c_str(), grpPtr, buffer.data(),
                            buffer.max_size(), &resultPtr);

    if (!status && (grpPtr == resultPtr))
    {
        for (; *(grp.gr_mem) != NULL; ++(grp.gr_mem))
        {
            userList.emplace_back(*(grp.gr_mem));
        }
    }
    else
    {
        log<level::ERR>("Error in parsing group file",
                        entry("GROUP=%s", groupName.c_str()));
        // Don't throw error, just return empty userList - fallback
    }
}

void UserMgr::initUserObjects(void)
{
    // All user management lock has to be based on /etc/shadow
    phosphor::user::shadow::Lock lock();
    std::vector<std::string> userNameList;
    getUserList(userNameList);
    if (!userNameList.empty())
    {
        std::map<std::string, std::vector<std::string>> groupLists;
        for (auto &grp : groupsMgr)
        {
            std::vector<std::string> grpUsersList;
            getGroupUsers(grp, grpUsersList);
            groupLists.emplace(grp, grpUsersList);
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
            auto objPath = std::string(USERS_OBJECT_PATH) + "/" + user;
            usersList.emplace(
                user, std::move(std::make_unique<phosphor::user::Users>(
                          bus, objPath.c_str(), userGroups, userPriv, *this)));
            // NOTE: Don't send any signal here, as this is existing user update
        }
    }

    // TODO: Needs to be removed
    // Currently hard coded root user for the time being.
    auto objPath = std::string(USERS_OBJECT_PATH) + "/" + "root";
    usersList.emplace("root",
                      std::move(std::make_unique<phosphor::user::Users>(
                          bus, objPath.c_str(), UserMgrIface::listGroups(),
                          std::string("priv-admin"), *this)));
}

UserMgr::UserMgr(sdbusplus::bus::bus &bus, const char *path)
    : UserMgrIface(bus, path), bus(bus), path(path)
{
    UserMgrIface::listPrivileges(privMgr);
    UserMgrIface::listGroups(groupsMgr);
    initUserObjects();
}

// TODO: Code to call registered  D-Bus API based on the groups

} // namespace user
} // namespace phosphor
