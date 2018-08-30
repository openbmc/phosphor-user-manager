#include "config.h"
#include "ldap_configuration.hpp"
#include <sdbusplus/bus.hpp>

int main(int argc, char* argv[])
{
    auto bus = sdbusplus::bus::new_default();

    phosphor::ldap::Configure ldapConf(bus, LDAP_CONFIG_ROOT, LDAP_CONFIG_FILE);

    bus.request_name(BUSNAME_LDAP_CONFIG);

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }

    return 0;
}
