sources = [
    'main.cpp',
    'ldap_mapper_entry.cpp',
    'ldap_mapper_mgr.cpp',
    'ldap_mapper_serialize.cpp'
]

mapper_exe = executable(
    'phosphor-ldap-mapper',
    sources,
    include_directories: ['..'],
    implicit_include_directories: true,
    dependencies: deps,
    install: true,
    install_dir: get_option('bindir'),
    link_args: ['-lstdc++fs'],
    cpp_args: ['-flto'])
