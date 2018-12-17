#include <catch2/catch.hpp>

#include "../../src/config.h"
#include "../../src/exceptions.h"

#include "constants.h"


SCENARIO("test the command line parsing", "[cmdline]") {
    int argc = 0;

    GIVEN("an empty command line") {
        argc = 1;
        const char *argv[] = {"pcapfs"};
        REQUIRE_THROWS_AS(pcapfs::parseOptions(argc, argv), pcapfs::ArgumentError);
    }

    GIVEN("a command line without a mount point") {
        WHEN("the --no-mount option is not provided") {
            argc = 3;
            const char *argv[] = {"pcapfs", "-m", pcapfs::tests::TEST_PCAP_PATH};
            const auto opts = pcapfs::parseOptions(argc, argv);
            THEN("assertValidOptions should throw an ArgumentError") {
                REQUIRE_THROWS_AS(pcapfs::assertValidOptions(opts), pcapfs::ArgumentError);
            }
        }

        argc = 4;
        WHEN("the --no-mount option is provided") {
            const char *argv[] = {"pcapfs", "-m", "--no-mount", pcapfs::tests::TEST_PCAP_PATH};
            const auto opts = pcapfs::parseOptions(argc, argv);
            THEN("assertValidOptions should not throw") {
                REQUIRE_NOTHROW(pcapfs::assertValidOptions(opts));
            }
        }

        WHEN("the -n option is provided") {
            const char *argv[] = {"pcapfs", "-m", "-n", pcapfs::tests::TEST_PCAP_PATH};
            const auto opts = pcapfs::parseOptions(argc, argv);
            THEN("assertValidOptions should not throw") {
                REQUIRE_NOTHROW(pcapfs::assertValidOptions(opts));
            }
        }
    }

}
