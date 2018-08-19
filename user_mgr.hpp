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
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Manager/server.hpp>
#include <unordered_map>
#include "users.hpp"

namespace phosphor
{
namespace user
{

using UserMgrIface = sdbusplus::xyz::openbmc_project::User::server::Manager;
using UserSSHLists =
    std::pair<std::vector<std::string>, std::vector<std::string>>;
/** @class UserMgr
 *  @brief Responsible for managing user accounts over the D-Bus interface.
 */
class UserMgr : public UserMgrIface
{
  public:
    UserMgr() = delete;
    ~UserMgr() = default;
    UserMgr(const UserMgr &) = delete;
    UserMgr &operator=(const UserMgr &) = delete;
    UserMgr(UserMgr &&) = delete;
    UserMgr &operator=(UserMgr &&) = delete;

    /** @brief Constructs UserMgr object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     */
    UserMgr(sdbusplus::bus::bus &bus, const char *path);

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
    void updateGroupsAndPriv(const std::string &userName,
                             const std::vector<std::string> &groups,
                             const std::string &priv);

    /** @brief Update user enabled state.
     *  This method enables / disables user
     *
     *  @param[in] userName - user name, for which update is requested
     *  @param[in] enabled - enable / disable the user
     */
    void userEnable(const std::string &userName, bool enabled);

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus &bus;

    /** @brief object path */
    const std::string path;

    /** @brief privilege manager container */
    std::vector<std::string> privMgr = {"priv-admin", "priv-operator",
                                        "priv-user", "priv-callback"};

    /** @brief groups manager container */
    std::vector<std::string> groupsMgr = {"web", "redfish", "ipmi", "ssh"};

    /** @brief map container to hold users object */
    using UserName = std::string;
    std::unordered_map<UserName, std::unique_ptr<phosphor::user::Users>>
        usersList;

    /** @brief get users in group
     *  method to get group user list
     *
     *  @param[in] groupName - group name
     *
     *  @return userList  - list of users in the group.
     */
    std::vector<std::string> getUsersInGroup(const std::string &groupName);

    /** @brief get user & SSH users list
     *  method to get the users and ssh users list.
     *
     *@return - vector of User & SSH user lists
     */
    UserSSHLists getUserAndSshGrpList(void);

    /** @brief check for user presence
     *  method to check for user existence
     *
     *  @param[in] userName - name of the user
     *  @return -true if user exists and false if not.
     */
    bool isUserExist(const std::string &userName);

    /** @brief check user exists
     *  method to check whether user exist, and throw if not.
     *
     *  @param[in] userName - name of the user
     */
    void throwForUserDoesNotExist(const std::string &userName);

    /** @brief check user does not exist
     *  method to check whether does not exist, and throw if exists.
     *
     *  @param[in] userName - name of the user
     */
    void throwForUserExists(const std::string &userName);

    /** @brief check user name constraints
     *  method to check user name constraints and throw if failed.
     *
     *  @param[in] userName - name of the user
     *  @param[in] groupNames - user groups
     */
    void
        throwForUserNameConstraints(const std::string &userName,
                                    const std::vector<std::string> &groupNames);

    /** @brief check group user count
     *  method to check max group user count, and throw if limit reached
     *
     *  @param[in] groupNames - group name
     */
    void throwForMaxGrpUserCount(const std::vector<std::string> &groupNames);

    /** @brief check for valid privielge
     *  method to check valid privilege, and throw if invalid
     *
     *  @param[in] priv - privilege of the user
     */
    void throwForInvalidPrivilege(const std::string &priv);

    /** @brief check for valid groups
     *  method to check valid groups, and throw if invalid
     *
     *  @param[in] groupNames - user groups
     */
    void throwForInvalidGroups(const std::vector<std::string> &groupName);

    /** @brief get user enabled state
     *  method to get user enabled state.
     *
     *  @param[in] userName - name of the user
     *  @return - user enabled status (true/false)
     */
    bool isUserEnabled(const std::string &userName);

    /** @brief initialize the user manager objects
     *  method to initialize the user manager objects accordingly
     *
     */
    void initUserObjects(void);

    /** @brief get IPMI user count
     *  method to get IPMI user count
     *
     * @return - returns user count
     */
    size_t getIpmiUsersCount(void);
};

} // namespace user
} // namespace phosphor
