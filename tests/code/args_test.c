#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../args.h"

// Test helper functions
static int test_count = 0;
static int test_passed = 0;

#define TEST_ASSERT(condition, message) \
    do { \
        test_count++; \
        if (condition) { \
            test_passed++; \
            printf("PASS: %s\n", message); \
        } else { \
            printf("FAIL: %s\n", message); \
        } \
    } while(0)

#define TEST_ASSERT_STR_EQ(actual, expected, message) \
    do { \
        test_count++; \
        if (strcmp(actual, expected) == 0) { \
            test_passed++; \
            printf("PASS: %s\n", message); \
        } else { \
            printf("FAIL: %s (expected '%s', got '%s')\n", message, expected, actual); \
        } \
    } while(0)

void test_nbd0_argument() {
    printf("\n=== Testing nbd-client nbd0 argument parsing ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "nbd0"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    // The key test: nbd0 should be recognized as a device
    TEST_ASSERT_STR_EQ(client.hostn, "nbd0", "nbd0 should be set as hostn");
    TEST_ASSERT_STR_EQ(client.dev, "nbd0", "nbd0 should also be set as dev (nbdtab logic)");
    TEST_ASSERT(!result.should_exit, "Should not exit for nbd0 argument");
    TEST_ASSERT(!result.check_conn, "Should not be check_conn");
    TEST_ASSERT(!result.need_disconnect, "Should not need disconnect");
    TEST_ASSERT(!result.list_exports, "Should not list exports");
    
    free_client_fields(&client);
}

void test_dev_nbd0_argument() {
    printf("\n=== Testing nbd-client /dev/nbd0 argument parsing ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "/dev/nbd0"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    // The key test: /dev/nbd0 should be recognized as a device
    TEST_ASSERT_STR_EQ(client.hostn, "/dev/nbd0", "/dev/nbd0 should be set as hostn");
    TEST_ASSERT_STR_EQ(client.dev, "/dev/nbd0", "/dev/nbd0 should also be set as dev (nbdtab logic)");
    TEST_ASSERT(!result.should_exit, "Should not exit for /dev/nbd0 argument");
    TEST_ASSERT(!result.check_conn, "Should not be check_conn");
    TEST_ASSERT(!result.need_disconnect, "Should not need disconnect");
    TEST_ASSERT(!result.list_exports, "Should not list exports");
    
    free_client_fields(&client);
}

void test_normal_connection() {
    printf("\n=== Testing normal connection arguments ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "localhost", "10809", "/dev/nbd0"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    TEST_ASSERT_STR_EQ(client.hostn, "localhost", "Host should be localhost");
    TEST_ASSERT_STR_EQ(client.port, "10809", "Port should be 10809");
    TEST_ASSERT_STR_EQ(client.dev, "/dev/nbd0", "Device should be /dev/nbd0");
    TEST_ASSERT(!result.should_exit, "Should not exit for normal connection");
    
    free_client_fields(&client);
}

void test_with_options() {
    printf("\n=== Testing arguments with options ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "-N", "export", "-b", "1024", "-timeout", "30", "localhost", "/dev/nbd0"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    TEST_ASSERT_STR_EQ(client.name, "export", "Export name should be set");
    TEST_ASSERT(client.bs == 1024, "Block size should be 1024");
    TEST_ASSERT(client.timeout == 30, "Timeout should be 30");
    TEST_ASSERT_STR_EQ(client.hostn, "localhost", "Host should be localhost");
    TEST_ASSERT_STR_EQ(client.dev, "/dev/nbd0", "Device should be /dev/nbd0");
    
    free_client_fields(&client);
}

void test_check_connection() {
    printf("\n=== Testing check connection option ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "-c", "/dev/nbd0"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    TEST_ASSERT(result.check_conn, "Should set check_conn flag");
    TEST_ASSERT_STR_EQ(result.check_device, "/dev/nbd0", "Check device should be /dev/nbd0");
    
    free_client_fields(&client);
}

void test_disconnect() {
    printf("\n=== Testing disconnect option ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "-d", "/dev/nbd0"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    TEST_ASSERT(result.need_disconnect, "Should set need_disconnect flag");
    TEST_ASSERT_STR_EQ(client.dev, "/dev/nbd0", "Device should be /dev/nbd0");
    
    free_client_fields(&client);
}

void test_list_exports() {
    printf("\n=== Testing list exports option ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "-l", "localhost"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    TEST_ASSERT(result.list_exports, "Should set list_exports flag");
    TEST_ASSERT_STR_EQ(client.hostn, "localhost", "Host should be localhost");
    TEST_ASSERT_STR_EQ(client.dev, "", "Device should be empty string for list");
    
    free_client_fields(&client);
}

void test_version() {
    printf("\n=== Testing version option ===\n");
    
    CLIENT client;
    init_client(&client);
    
    char *argv[] = {"nbd-client", "-V"};
    int argc = sizeof(argv) / sizeof(argv[0]);
    
    parse_result_t result = parse_nbd_client_args(argc, argv, &client);
    
    TEST_ASSERT(result.show_version, "Should set show_version flag");
    
    free_client_fields(&client);
}

void test_netlink_options() {
    printf("\n=== Testing HAVE_NETLINK conditional options ===\n");
    
    CLIENT client;
    init_client(&client);
    
    // Test -i (identifier) option - should work when HAVE_NETLINK is defined
    char *argv1[] = {"nbd-client", "-i", "test_id", "localhost", "/dev/nbd0"};
    int argc1 = sizeof(argv1) / sizeof(argv1[0]);
    
    parse_result_t result1 = parse_nbd_client_args(argc1, argv1, &client);
    
#ifdef HAVE_NETLINK
    TEST_ASSERT(!result1.should_exit, "Should not exit for -i option when HAVE_NETLINK");
    TEST_ASSERT_STR_EQ(result1.identifier, "test_id", "Identifier should be set");
#else
    TEST_ASSERT(result1.should_exit, "Should exit for -i option when HAVE_NETLINK is not defined");
    TEST_ASSERT(result1.exit_code == 1, "Should have exit code 1 when HAVE_NETLINK is not defined");
#endif
    
    free_client_fields(&client);
    
    // Test -L (nonetlink) option - should work when HAVE_NETLINK is defined
    init_client(&client);
    char *argv2[] = {"nbd-client", "-L", "-c", "/dev/nbd0"};
    int argc2 = sizeof(argv2) / sizeof(argv2[0]);
    
    parse_result_t result2 = parse_nbd_client_args(argc2, argv2, &client);
    
#ifdef HAVE_NETLINK
    TEST_ASSERT(!result2.should_exit, "Should not exit for -L option when HAVE_NETLINK");
    TEST_ASSERT(result2.nonetlink, "Nonetlink flag should be set");
#else
    TEST_ASSERT(result2.should_exit, "Should exit for -L option when HAVE_NETLINK is not defined");
    TEST_ASSERT(result2.exit_code == 1, "Should have exit code 1 when HAVE_NETLINK is not defined");
#endif
    
    free_client_fields(&client);
}

void test_error_cases() {
    printf("\n=== Testing error cases ===\n");
    
    CLIENT client;
    
    // Test invalid blocksize
    init_client(&client);
    char *argv1[] = {"nbd-client", "-b", "513", "localhost", "/dev/nbd0"};
    parse_result_t result1 = parse_nbd_client_args(sizeof(argv1)/sizeof(argv1[0]), argv1, &client);
    TEST_ASSERT(result1.should_exit, "Should exit for invalid blocksize");
    TEST_ASSERT(result1.exit_code == 1, "Should have exit code 1");
    free_client_fields(&client);
    
    // Test too many arguments
    init_client(&client);
    char *argv2[] = {"nbd-client", "localhost", "10809", "/dev/nbd0", "extra"};
    parse_result_t result2 = parse_nbd_client_args(sizeof(argv2)/sizeof(argv2[0]), argv2, &client);
    TEST_ASSERT(result2.should_exit, "Should exit for too many arguments");
    free_client_fields(&client);
    
    // Test no arguments
    init_client(&client);
    char *argv3[] = {"nbd-client"};
    parse_result_t result3 = parse_nbd_client_args(sizeof(argv3)/sizeof(argv3[0]), argv3, &client);
    TEST_ASSERT(result3.should_exit, "Should exit for no arguments");
    free_client_fields(&client);
}

int main() {
    printf("=== NBD Client Argument Parsing Tests ===\n");
    printf("Testing the refactored argument parsing functionality\n");
    
    // Run all tests
    test_nbd0_argument();
    test_dev_nbd0_argument();
    test_normal_connection();
    test_with_options();
    test_check_connection();
    test_disconnect();
    test_list_exports();
    test_version();
    test_netlink_options();
    test_error_cases();
    
    // Print summary
    printf("\n=== Test Summary ===\n");
    printf("Tests passed: %d/%d\n", test_passed, test_count);
    
    if (test_passed == test_count) {
        printf("All tests PASSED!\n");
        return 0;
    } else {
        printf("Some tests FAILED!\n");
        return 1;
    }
}
