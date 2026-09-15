add_executable(integration_test
    integration_test.cpp
)

target_link_libraries(integration_test
    PRIVATE
    ${PROJECT_NAME}
)

# add_test(
#     NAME integration_test
#     COMMAND integration_test
# )
