#include <sstream>

#include <catch2/catch.hpp>

#include "../../src/commontypes.h"
#include "../../src/config.h"
#include "../../src/exceptions.h"

#include "constants.h"

using Catch::Equals;


template<class T>
class HasSameElements : public Catch::MatcherBase<T> {
public:
    explicit HasSameElements(const T expected) : expected(expected) {
        std::sort(this->expected.begin(), this->expected.end());
    }

    virtual bool match(const T &vec) const override {
        T v(vec);
        std::sort(v.begin(), v.end());
        return std::equal(vec.cbegin(), vec.cend(), expected.cbegin());
    }

    virtual std::string describe() const override {
        std::ostringstream oss;
        oss << "has the same elements as { ";
        for (unsigned int i = 0; i < expected.size(); ++i) {
            oss << expected[i];
            if (i < expected.size() - 1) {
                oss << ", ";
            }
        }
        oss << " }";
        return oss.str();
    }

private:
    T expected;
};


template<typename T>
inline HasSameElements<T> HasSameElementsAs(T expected) {
    return HasSameElements<T>(expected);
}


SCENARIO("test the command line parsing", "[cmdline]") {
    int argc = 0;
    const pcapfs::Path keysdir(pcapfs::tests::KEY_FILE_DIRECTORY);

    GIVEN("an empty command line") {
        argc = 1;
        const char *argv[] = {"pcapfs"};
        REQUIRE_THROWS_AS(pcapfs::parseOptions(argc, argv), pcapfs::ArgumentError);
    }


    GIVEN("a minimal command line") {
        argc = 3;
        const char *argv[] = {"pcapfs", pcapfs::tests::TEST_PCAP_PATH, "/some/mount/point"};
        const auto opts = pcapfs::parseOptions(argc, argv);
        THEN("assertValidOptions should not throw") {
            REQUIRE_NOTHROW(pcapfs::assertValidOptions(opts));
        }
        THEN("there should be no key files") {
            REQUIRE(opts.pcapfsOptions.keyFiles.empty());
        }
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


    GIVEN("a command line with key files") {

        WHEN("one key file is given") {
            argc = 5;
            const auto keyfile = keysdir / "single-xor.key";
            const char *argv[] = {"pcapfs", "-m", "-k", keyfile.string().c_str(), pcapfs::tests::TEST_PCAP_PATH};
            THEN("the config should contain one key file path") {
                const auto options = pcapfs::parseOptions(argc, argv);
                REQUIRE_THAT(options.pcapfsOptions.keyFiles, Equals(pcapfs::Paths{keyfile}));
            }
        }

        WHEN("two key files are given") {
            argc = 7;
            const auto xorKeyFile = keysdir / "single-xor.key";
            const auto sslKeyFile = keysdir / "single-ssl.key";
            const char *argv[] = {"pcapfs", "-m", "-k", xorKeyFile.string().c_str(), "-k", sslKeyFile.string().c_str(),
                                  pcapfs::tests::TEST_PCAP_PATH};
            THEN("the config should contain two key file paths") {
                const auto options = pcapfs::parseOptions(argc, argv);
                REQUIRE_THAT(options.pcapfsOptions.keyFiles,
                             HasSameElementsAs<pcapfs::Paths>(pcapfs::Paths{xorKeyFile, sslKeyFile}));
            }
        }

        WHEN("duplicate key files are given") {
            argc = 11;
            const auto xorKeyFile1 = keysdir / "single-xor.key";
            const auto xorKeyFile2 = keysdir / "single-xor.key";
            const auto sslKeyFile1 = keysdir / "single-ssl.key";
            const auto sslKeyFile2 = keysdir / "single-ssl.key";
            const char *argv[] = {"pcapfs", "-m", pcapfs::tests::TEST_PCAP_PATH,
                                  "-k", xorKeyFile1.string().c_str(),
                                  "-k", xorKeyFile2.string().c_str(),
                                  "-k", sslKeyFile1.string().c_str(),
                                  "-k", sslKeyFile2.string().c_str()};
            THEN("the config should contain only unique key file paths") {
                auto options = pcapfs::parseOptions(argc, argv);
                REQUIRE_THAT(options.pcapfsOptions.keyFiles,
                             HasSameElementsAs<pcapfs::Paths>(pcapfs::Paths{xorKeyFile1, sslKeyFile1}));
            }
        }

    }

}
