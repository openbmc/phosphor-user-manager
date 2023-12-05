#include "config.h"

#include "user_mgr.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/source/signal.hpp>
#include <stdplus/signal.hpp>

#include <iostream>

using namespace sdeventplus;
using namespace sdeventplus::source;
using sdeventplus::source::Signal;

// D-Bus root for user manager
constexpr auto userManagerRoot = "/xyz/openbmc_project/user";

int main(int /*argc*/, char** /*argv*/)
{
    auto bus = sdbusplus::bus::new_default();
    sdbusplus::server::manager_t objManager(bus, userManagerRoot);

    phosphor::user::UserMgr userMgr(bus, userManagerRoot);

    // Claim the bus now
    bus.request_name(USER_MANAGER_BUSNAME);

    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    stdplus::signal::block(SIGUSR1);

    sdeventplus::source::Signal sigUsr1(
        event, SIGUSR1,
        [&userMgr](sdeventplus::source::Signal& /*signal*/,
                   const struct signalfd_siginfo*) {
            std::cout << "LDAP Received SIGUR1(10) Signal interrupt"
                      << std::endl;
            if (userMgr.isLdapEnabled())
            {
                userMgr.ldapDumpCollector();
            }
        });
    event.loop();
    // Wait for client request
    bus.process_loop();
}
