sources = [
    'main.cpp',
    'utils.cpp',
    'ldap_config.cpp',
    'ldap_config_mgr.cpp',
    'ldap_mapper_entry.cpp',
    'ldap_mapper_serialize.cpp'
]

config_exe = executable(
    'phosphor-ldap-config',
    sources,
    include_directories: ['..'],
    implicit_include_directories: true,
    dependencies: deps,
    install: true,
    install_dir: get_option('bindir'),
    link_args: ['-lstdc++fs', '-lldap'],
    cpp_args: ['-flto'])

