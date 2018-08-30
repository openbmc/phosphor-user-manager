#include "config.h"
#include "ldap_configuration.hpp"
#include <sdbusplus/bus.hpp>

int main(int argc, char* argv[])
{
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus ObjectManager for the 'root' path of the LDAP config.
    sdbusplus::server::manager::manager objManager(bus, LDAP_CONFIG_DBUS_PATH);

    phosphor::ldap::ConfigMgr ldapConf(bus, LDAP_CONFIG_DBUS_PATH,
                                       LDAP_CONFIG_FILE);

    bus.request_name(LDAP_CONFIG_BUSNAME);

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }

    return 0;
}
