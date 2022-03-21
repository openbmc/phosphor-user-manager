phosphor_ldap_mapper_deps = [
    cereal_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
]

phosphor_ldap_mapper_lib = static_library(
    'phosphor_ldap_mapper',
    [
        'ldap_mapper_mgr.cpp',
        'ldap_mapper_entry.cpp',
        'ldap_mapper_serialize.cpp'
    ],
    include_directories: '..',
    dependencies: phosphor_ldap_mapper_deps,
)

phosphor_ldap_mapper_dep = declare_dependency(
    link_with: phosphor_ldap_mapper_lib,
    dependencies: phosphor_ldap_mapper_deps,
)

executable(
    'phosphor-ldap-mapper',
    'main.cpp',
    include_directories: '..',
    dependencies: phosphor_ldap_mapper_dep,
    install: true,
)

