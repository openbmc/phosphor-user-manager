gtest = dependency('gtest', main: true, disabler: true, required: true)
gmock = dependency('gmock', disabler: true, required: true)

deps += [gtest, gmock]

test_linker = [
    '-lgtest_main',
    '-lcrypt',
    '-lstdc++fs'
]

test('ldap_config_test',
    executable('ldap_config_test_exe',
        'ldap_config_test.cpp', 'utils_test.cpp',
        objects: config_exe.extract_all_objects(),
        include_directories: ['..'],
        implicit_include_directories: true,
        link_args: [test_linker, '-lldap', '-lgmock'],
        dependencies: deps
    ),
    workdir: meson.current_source_dir()
)

test('ldap_mapper_test',
    executable('ldap_mapper_test_exe',
        'ldap_mapper_test.cpp',
        objects: mapper_exe.extract_all_objects(),
        include_directories: ['..'],
        implicit_include_directories: true,
        link_args: test_linker,
        dependencies: deps
    ),
    workdir: meson.current_source_dir()
)

test('user_mgr_test',
    executable('user_mgr_test_exe',
        'user_mgr_test.cpp',
        objects: manager_exe.extract_all_objects(),
        include_directories: ['..'],
        implicit_include_directories: true,
        link_args: [test_linker, '-lgmock'],
        dependencies: deps
    ),
    workdir: meson.current_source_dir()
)
