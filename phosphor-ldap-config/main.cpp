#include "config.h"
#include "ldap_configuration.hpp"
#include <experimental/filesystem>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

int main(int argc, char* argv[])
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    namespace fs = std::experimental::filesystem;

    if (!fs::exists(phosphor::ldap::defaultNslcdFile) ||
        !fs::exists(phosphor::ldap::nsSwitchFile) ||
        (!fs::exists(phosphor::ldap::LDAPNsSwitchFile) &&
         !fs::exists(phosphor::ldap::linuxNsSwitchFile)))
    {
        log<level::ERR>("Error starting LDAP Config App, configfile(s) are "
                        "missing, exiting!!!");
        elog<InternalFailure>();
    }
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus ObjectManager for the 'root' path of the LDAP config.
    sdbusplus::server::manager::manager objManager(bus, LDAP_CONFIG_ROOT);

    phosphor::ldap::ConfigMgr mgr(bus, LDAP_CONFIG_ROOT);

    bus.request_name(LDAP_CONFIG_BUSNAME);

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }

    return 0;
}
