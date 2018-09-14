#include <shadow.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <regex>
#include <algorithm>
#include <numeric>
#include <boost/process/child.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "config.h"
#include "ldap_mapper_mgr.hpp"

namespace phosphor
{
namespace user
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

void LDAPMapperMgr::createPrivilegeMapper(std::string groupName,
                                          std::string privilege)
{
    // Check if the group name already exists.
    auto groupStatus = checkPrivilegeMapping(groupName);
    if (groupStatus == true)
    {
        log<level::ERR>("Group name already exists");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group Name"),
                              Argument::ARGUMENT_VALUE(groupName.c_str()));
    }

    // Check if the privilege is a valid one.
    auto privStatus = checkPrivilegeLevel(privilege);
    if (privStatus == false)
    {
        log<level::ERR>("Invalid privilege");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(privilege.c_str()));
    }

    // Add the users object before sending out the signal
    std::string mapperObject = std::string(mapperObjPath) + "/" + groupName;
    PrivilegeMapperList.emplace(
            groupName,
            std::move(std::make_unique<phosphor::user::LDAPMapperEntry>(
            bus, mapperObject.c_str(), privilege, *this)));

    log<level::INFO>("Privilege mapper created successfully",
                     entry("GROUP_NAME=%s", groupName.c_str()));
    return;
}

void LDAPMapperMgr::deletePrivilegeMapper(std::string groupName)
{
    //checkGroupExists(groupName);
    PrivilegeMapperList.erase(groupName);

    log<level::INFO>("Privilege mapper deleted successfully",
                     entry("GROUP_NAME=%s", groupName.c_str()));
    return;
}

bool LDAPMapperMgr::checkPrivilegeMapping(const std::string &groupName)
{
    if (groupName.empty())
    {
        log<level::ERR>("Group name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }
    if (PrivilegeMapperList.find(groupName) == PrivilegeMapperList.end())
    {
        return false;
    }
    return true;
}

bool LDAPMapperMgr::checkPrivilegeLevel(const std::string &privilege)
{
    if (privilege.empty())
    {
        log<level::ERR>("Privilege level is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege level"),
                              Argument::ARGUMENT_VALUE("Null"));
    }

    if (std::find(privMgr.begin(), privMgr.end(), privilege) == privMgr.end())
    {
        return false;
    }
    return true;
}

LDAPMapperMgr::LDAPMapperMgr(sdbusplus::bus::bus &bus, const char *path) :
        MapperMgrIface(bus, path), bus(bus), path(path)
{
}

} // namespace user
} // namespace phosphor
