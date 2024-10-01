#include "config.h"

#include "user_mgr.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

// D-Bus root for user manager
constexpr auto userManagerRoot = "/xyz/openbmc_project/user";

int main(int /*argc*/, char** /*argv*/)
{
    auto bus = sdbusplus::bus::new_default();
    sdbusplus::server::manager_t objManager(bus, userManagerRoot);

    phosphor::user::UserMgr userMgr(bus, userManagerRoot);
    // Claim the bus now
    bus.request_name(USER_MANAGER_BUSNAME);

    // Wait for client request
    bus.process_loop();
}
