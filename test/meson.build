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
            ]
        )
        gmock_dep = gtest_proj.dependency('gmock')
    else
        assert(
            not get_option('tests').enabled(),
            'Googletest is required if tests are enabled'
        )
    endif
endif

test(
    'ldap_config_test',
    executable(
        'ldap_config_test',
        ['ldap_config_test.cpp',
         'utils_test.cpp'],
        include_directories: '..',
        dependencies: [
            gtest_dep,
            gmock_dep,
            phosphor_ldap_conf_dep,
        ],
        link_args: ['-lldap'],
    ),
)

test(
    'ldap_mapper_test',
    executable(
        'ldap_mapper_test',
        'ldap_mapper_test.cpp',
        include_directories: '..',
        dependencies: [
            gtest_dep,
            gmock_dep,
            phosphor_ldap_mapper_dep,
        ],
    ),
)

test(
    'user_mgr_test',
    executable(
        'user_mgr_test',
        'user_mgr_test.cpp',
        include_directories: '..',
        dependencies: [
            gtest_dep,
            gmock_dep,
            user_manager_dep,
        ],
    ),
)
