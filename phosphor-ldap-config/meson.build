phosphor_ldap_conf_deps = [
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
]

phosphor_ldap_conf_lib = static_library(
    'phosphor_ldap_conf',
    [
        'utils.cpp',
        'ldap_config.cpp',
        'ldap_config_mgr.cpp',
        'ldap_mapper_entry.cpp',
        'ldap_mapper_serialize.cpp'
    ],
    include_directories: '..',
    dependencies: phosphor_ldap_conf_deps,
)

phosphor_ldap_conf_dep = declare_dependency(
    link_with: phosphor_ldap_conf_lib,
    dependencies: phosphor_ldap_conf_deps,
)

executable(
    'phosphor-ldap-conf',
    'main.cpp',
    include_directories: '..',
    dependencies: phosphor_ldap_conf_dep,
    link_args: ['-lldap'],
    install: true,
)
