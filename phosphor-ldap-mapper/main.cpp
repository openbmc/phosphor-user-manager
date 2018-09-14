#include <string>
#include "config.h"
#include "ldap_mapper_mgr.hpp"

// D-Bus root for LDAP privilege mapper
constexpr auto ldapManagerRoot = "/xyz/openbmc_project/user/ldap";

int main(int argc, char** argv)
{
    auto bus = sdbusplus::bus::new_default();
    sdbusplus::server::manager::manager objManager(bus, ldapManagerRoot);

    phosphor::user::LDAPMapperMgr mapperMgr(bus, ldapManagerRoot);

    // Claim the bus now
    bus.request_name(LDAP_MAPPER_MANAGER_BUSNAME);

    // Wait for client request
    while (true)
    {
        // Process D-Bus calls
        bus.process_discard();
        bus.wait();
    }
    return 0;
}
