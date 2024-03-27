project('phosphor-user-manager',
        'cpp',
        version: '0.1', meson_version: '>=1.1.1',
        default_options: [
          'warning_level=3',
          'werror=true',
          'cpp_std=c++23',
          'buildtype=debugoptimized',
        ]
)

if get_option('root_user_mgmt').allowed()
    add_project_arguments('-DENABLE_ROOT_USER_MGMT', language:'cpp')
endif

conf_data = configuration_data()

conf_data.set_quoted('USER_MANAGER_BUSNAME', 'xyz.openbmc_project.User.Manager',
                      description : 'The DBus busname to own.')

conf_data.set_quoted('DEFAULT_CRYPT_ALGO', '1',
                      description : 'The default crypt algorithm if one not found in shadow.')

conf_data.set('MAX_SYSTEM_USERS', get_option('max_system_users'), description: 'Maximum allowed number of system users')

conf_data.set('CLASS_VERSION', 1,
                      description : 'Class version to register with Cereal.')

conf_data.set_quoted('LDAP_CONFIG_FILE', '/etc/nslcd.conf',
                      description : 'Path of LDAP configuration file.')

conf_data.set_quoted('TLS_CACERT_PATH', '/etc/ssl/certs/authority',
                      description : 'Path of LDAP server CA certificate.')

conf_data.set_quoted('TLS_CERT_FILE', '/etc/nslcd/certs/cert.pem',
                      description : 'Path of LDAP client certificate.')

conf_data.set_quoted('LDAP_CONFIG_ROOT', '/xyz/openbmc_project/user/ldap',
                      description : 'LDAP configuration root.')

conf_data.set_quoted('LDAP_CONFIG_DBUS_OBJ_PATH', '/xyz/openbmc_project/user/ldap/config',
                      description : 'D-Bus path of LDAP config object.')

conf_data.set_quoted('LDAP_CONFIG_BUSNAME', 'xyz.openbmc_project.Ldap.Config',
                      description : 'D-Bus busname of LDAP config service.')

conf_data.set_quoted('LDAP_CONF_PERSIST_PATH', '/var/lib/phosphor-ldap-conf',
                      description : 'path of directory having persisted LDAP configuration enabled property.')

conf_data.set_quoted('SYSTEMD_BUSNAME', 'org.freedesktop.systemd1',
                      description : 'systemd busname.')

conf_data.set_quoted('SYSTEMD_PATH', '/org/freedesktop/systemd1',
                      description :  'systemd path')

conf_data.set_quoted('SYSTEMD_INTERFACE', 'org.freedesktop.systemd1.Manager',
                      description : 'systemd interface.')

conf_header = configure_file(output: 'config.h',
    configuration: conf_data)

phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
sdbusplus_dep = dependency('sdbusplus')
phosphor_logging_dep = dependency('phosphor-logging')
systemd_dep = dependency('systemd')

cpp = meson.get_compiler('cpp')

# Get Cereal dependency.
cereal_dep = dependency('cereal', required: false)
has_cereal = cpp.has_header_symbol(
    'cereal/cereal.hpp',
    'cereal::specialize',
    dependencies: cereal_dep,
    required: false)
if not has_cereal
    cereal_opts = import('cmake').subproject_options()
    cereal_opts.add_cmake_defines({'BUILD_TESTS': 'OFF'})
    cereal_proj = import('cmake').subproject(
        'cereal',
        options: cereal_opts,
        required: false)
    assert(cereal_proj.found(), 'cereal is required')
    cereal_dep = cereal_proj.dependency('cereal')
endif

user_manager_src = [
    'mainapp.cpp',
    'user_mgr.cpp',
    'users.cpp'
]

user_manager_deps = [
     sdbusplus_dep,
     phosphor_logging_dep,
     phosphor_dbus_interfaces_dep
]

user_manager_lib = static_library(
    'phosphor-user-manager',
    [
        'user_mgr.cpp',
        'users.cpp',
    ],
    dependencies: user_manager_deps,
)

user_manager_dep = declare_dependency(
    link_with: user_manager_lib,
    dependencies: user_manager_deps
)

executable(
    'phosphor-user-manager',
    'mainapp.cpp',
    dependencies: user_manager_dep,
    link_args: ['-lcrypt' ],
    cpp_args: ['-DBOOST_ALL_NO_LIB', '-DBOOST_SYSTEM_NO_DEPRECATED', '-DBOOST_ERROR_CODE_HEADER_ONLY'],
    install: true,
)


systemd_system_unit_dir = systemd_dep.get_variable(
    'systemdsystemunitdir'
)

install_data(
    'phosphor-nslcd-cert-config.conf',
    install_dir: get_option('datadir') / 'dbus-1' / 'system.d',
)

install_data(
    'nslcd',
    install_dir: get_option('datadir') / 'phosphor-certificate-manager',
)

# Figure out how to use install_symlink to install symlink to a file of another
# recipe
#install_symlink(
#      'phosphor-certificate-manager@nslcd.service',
#      install_dir: systemd_system_unit_dir / 'multi-user.target.wants',
#      pointing_to: systemd_system_unit_dir / 'phosphor-certificate-manager@.service',
#  )
meson.add_install_script(
    'sh', '-c',
    'mkdir -p $(dirname $DESTDIR/@0@/@1@)'.format(systemd_system_unit_dir,
        'multi-user.target.wants/phosphor-certificate-manager@nslcd.service'),
)
meson.add_install_script(
    'sh', '-c',
    'ln -s @0@ $DESTDIR/@1@/@2@'.format('../phosphor-certificate-manager@.service',
        systemd_system_unit_dir,
        'multi-user.target.wants/phosphor-certificate-manager@nslcd.service'),
)

subdir('phosphor-ldap-config')

if get_option('tests').allowed()
  subdir('test')
endif
