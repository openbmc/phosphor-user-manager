project('phosphor-user-manager', ['cpp'],
    version: '0.1', meson_version: '>=0.49.0',
    default_options: [
    'warning_level=3',
    'default_library=shared',
    'werror=true',
    'cpp_std=c++17'
    ])

conf_data = configuration_data()
conf_data.set_quoted('USER_MANAGER_BUSNAME','xyz.openbmc_project.User.Manager')
conf_data.set_quoted('LDAP_MAPPER_MANAGER_BUSNAME','xyz.openbmc_project.LDAP.PrivilegeMapper')
conf_data.set_quoted('LDAP_MAPPER_PERSIST_PATH','/var/lib/phosphor-ldap-mapper/groups')
conf_data.set('CLASS_VERSION',1)
conf_data.set_quoted('DEFAULT_CRYPT_ALGO','1')
conf_data.set_quoted('LDAP_CONFIG_FILE','/etc/nslcd.conf')
conf_data.set_quoted('TLS_CACERT_FILE','/etc/ssl/certs/Root-CA.pem')
conf_data.set_quoted('TLS_CERT_FILE','/etc/nslcd/certs/cert.pem')
conf_data.set_quoted('LDAP_CONFIG_ROOT','/xyz/openbmc_project/user/ldap')
conf_data.set_quoted('LDAP_CONFIG_DBUS_OBJ_PATH','/xyz/openbmc_project/user/ldap/config')
conf_data.set_quoted('LDAP_CONFIG_BUSNAME','xyz.openbmc_project.Ldap.Config')
conf_data.set_quoted('LDAP_CONF_PERSIST_PATH','/var/lib/phosphor-ldap-conf')
conf_data.set_quoted('SYSTEMD_BUSNAME','org.freedesktop.systemd1')
conf_data.set_quoted('SYSTEMD_PATH','/org/freedesktop/systemd1')
conf_data.set_quoted('SYSTEMD_INTERFACE','org.freedesktop.systemd1.Manager')

configure_file(output: 'config.h',
    configuration: conf_data
)

lib_sdbusplus=dependency('sdbusplus')
lib_phosphor_dbus_interfaces=dependency('phosphor-dbus-interfaces')
lib_phosphor_logging=dependency('phosphor-logging')

deps = [
    lib_sdbusplus,
    lib_phosphor_dbus_interfaces,
    lib_phosphor_logging
    ]

manager_exe = executable(
    'phosphor-user-manager',
    'mainapp.cpp', 'user_mgr.cpp', 'users.cpp',
    implicit_include_directories: true,
    dependencies: deps,
    install: true,
    install_dir: get_option('bindir'),
    link_args: ['-lcrypt', '-lstdc++fs'],
    cpp_args: ['-DBOOST_ALL_NO_LIB', '-DBOOST_SYSTEM_NO_DEPRECATED', '-DBOOST_ERROR_CODE_HEADER_ONLY'])

subdir('phosphor-ldap-config')
subdir('phosphor-ldap-mapper')

if get_option('tests').enabled()
    subdir('test')
endif
