#pragma once

#include <shadow.h>
#include <stdio.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cassert>
namespace phosphor
{
namespace user
{
namespace shadow
{

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using namespace phosphor::logging;

/** @class Lock
 *  @brief Responsible for locking and unlocking /etc/shadow
 */
class Lock
{
  public:
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
    Lock(Lock&&) = delete;
    Lock& operator=(Lock&&) = delete;

    /** @brief Default constructor that just locks the shadow file */
    Lock()
    {
        if (!lckpwdf())
        {
            lg2::error("Failed to lock shadow file");
            elog<InternalFailure>();
        }
    }
    ~Lock()
    {
        if (!ulckpwdf())
        {
            lg2::error("Failed to unlock shadow file");
            elog<InternalFailure>();
        }
    }
};

} // namespace shadow
} // namespace user
} // namespace phosphor
