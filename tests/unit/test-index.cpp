
#include <catch2/catch.hpp>

#include "../../src/index.h"
#include "../../src/commontypes.h"
#include "constants.h"

using Catch::Equals;
using pcapfs::Index;
using pcapfs::Path;


SCENARIO("test header version checks", "[index]") {
    Path indexPath{pcapfs::tests::TEST_DATA_DIRECTORY};
    indexPath /= "indexes";

    GIVEN("an index with an older compatible version") {
        indexPath /= "empty-0.1.index";
        Index index;
        THEN("reading the index should throw no errors") {
            REQUIRE_NOTHROW(index.read(indexPath));
        }
    }

    GIVEN("an index with a newer incompatble version") {
        indexPath /= "empty-9999.1.index";
        Index index;
        THEN("reading the index should throw an error") {
            REQUIRE_THROWS(index.read(indexPath));
        }
    }

}
