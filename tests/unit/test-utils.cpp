
#include <catch2/catch.hpp>

#include "../../src/commontypes.h"
#include "../../src/utils.h"

using Catch::Equals;
using pcapfs::Bytes;


SCENARIO("test hexStringToBytes", "[utils]") {
    std::string input;

    GIVEN("an empty string") {
        input = "";
        THEN("the bytes vector should be empty") {
            REQUIRE(pcapfs::utils::hexStringToBytes(input).empty());
        }
    }

    GIVEN("an invalid input string") {

        WHEN("the input string is odd") {
            input = "a";
            THEN("the function should throw") {
                REQUIRE_THROWS(pcapfs::utils::hexStringToBytes(input));
            }
            input = "aab";
            THEN("the function should throw") {
                REQUIRE_THROWS(pcapfs::utils::hexStringToBytes(input));
            }
        }

        WHEN("the input string contains non-hex characters") {
            input = "x";
            THEN("the function should throw") {
                REQUIRE_THROWS(pcapfs::utils::hexStringToBytes(input));
            }
            input = "aaxb";
            THEN("the function should throw") {
                REQUIRE_THROWS(pcapfs::utils::hexStringToBytes(input));
            }
            input = "aabx";
            THEN("the function should throw") {
                REQUIRE_THROWS(pcapfs::utils::hexStringToBytes(input));
            }
            input = "aaxx";
            THEN("the function should throw") {
                REQUIRE_THROWS(pcapfs::utils::hexStringToBytes(input));
            }
        }

    }

    GIVEN("a valid input string") {
        input = "01";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{1}));
        }
        input = "f1";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{241}));
        }
        input = "0102";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{1, 2}));
        }
        input = "010203";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{1, 2, 3}));
        }
        input = "aabbcc";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{170, 187, 204}));
        }
        input = "aa01cc";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{170, 1, 204}));
        }
        input = "01aa02";
        THEN("the function should return the correct byte sequence") {
            REQUIRE_THAT(pcapfs::utils::hexStringToBytes(input), Equals(Bytes{1, 170, 2}));
        }
    }

}
