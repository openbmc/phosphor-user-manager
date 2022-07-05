#include "config.h"

#include "ldap_config_mgr.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>

int main(int /*argc*/, char** /*argv*/)
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    std::filesystem::path configDir =
        std::filesystem::path(LDAP_CONFIG_FILE).parent_path();

    if (!std::filesystem::exists(configDir /
                                 phosphor::ldap::defaultNslcdFile) ||
        !std::filesystem::exists(configDir / phosphor::ldap::nsSwitchFile))
    {
        lg2::error("Failed to start phosphor-ldap-manager, configfile(s) are "
                   "missing");
        elog<InternalFailure>();
    }
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus ObjectManager for the 'root' path of the LDAP config.
    sdbusplus::server::manager_t objManager(bus, LDAP_CONFIG_ROOT);

    phosphor::ldap::ConfigMgr mgr(bus, LDAP_CONFIG_ROOT, LDAP_CONFIG_FILE,
                                  LDAP_CONF_PERSIST_PATH, TLS_CACERT_PATH,
                                  TLS_CERT_FILE);
    mgr.restore();

    bus.request_name(LDAP_CONFIG_BUSNAME);

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }

    return 0;
}
