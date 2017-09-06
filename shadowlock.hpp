#pragma once

#include <stdio.h>
#include <cassert>
namespace phosphor
{
namespace user
{
namespace shadow
{
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
            assert(lckpwdf());
        }
        ~Lock()
        {
            ulckpwdf();
        }
};

} // namespace shadow
} // namespace user
} // namespace phosphor
