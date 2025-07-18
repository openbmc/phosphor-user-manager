gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
gmock_dep = dependency('gmock', disabler: true, required: false)
if not gtest_dep.found() or not gmock_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ],
        )
        gmock_dep = gtest_proj.dependency('gmock')
    else
        assert(
            not get_option('tests').allowed(),
            'Googletest is required if tests are enabled',
        )
    endif
endif

if ldap_dep.found()
    test(
        'ldap_config_test',
        executable(
            'ldap_config_test',
            ['ldap_config_test.cpp', 'utils_test.cpp'],
            include_directories: '..',
            dependencies: [
                gmock_dep,
                gtest_dep,
                ldap_dep,
                phosphor_ldap_conf_dep,
            ],
            link_args: ['-lldap'],
        ),
    )
endif

test(
    'user_mgr_test',
    executable(
        'user_mgr_test',
        'user_mgr_test.cpp',
        include_directories: '..',
        dependencies: [gtest_dep, gmock_dep, user_manager_dep],
    ),
)

test(
    'json_serializer_test',
    executable(
        'json_serializer_test',
        'json_serializer_test.cpp',
        include_directories: '..',
        dependencies: [gtest_dep, gmock_dep, user_manager_dep],
    ),
)


test(
    'execute_cmd_test',
    executable(
        'execute_cmd_test',
        'execute_cmd_test.cpp',
        include_directories: '..',
        dependencies: [gtest_dep, gmock_dep, phosphor_logging_dep],
    ),
)
