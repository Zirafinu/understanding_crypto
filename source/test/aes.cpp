#include <doctest/doctest.h>
#include <understanding_crypto/aes.hpp>

namespace std {
std::ostream &operator<<(std::ostream &os,
                         const std::array<uint32_t, 4> &value) {
    os << "[" << value[0] << "," << value[1] << "," << value[2] << ","
       << value[3] << "]";
    return os;
}
} // namespace std

namespace understanding_crypto::aes {

TEST_SUITE("examples") {
    TEST_CASE("encrypt message") { WARN("Not implemented"); }
    TEST_CASE("decrypt message") { WARN("Not implemented"); }
}

TEST_SUITE("encrypt") {
    TEST_CASE("substitute bytes") { WARN("Not implemented"); }
    TEST_CASE("row shift") {
        auto state = state_t{1, 2, 3, 4};

        auto expected = state_t{1, 0x200, 0x30000, 0x4000000};
        CHECK_EQ(AES<key128_t>::Encryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{1, 2, 3, 4};

        auto expected = state_t{3, 4, 9, 10};
        CHECK_EQ(AES<key128_t>::Encryption::mix_columns(state), expected);
    }
}

TEST_SUITE("decrypt") {
    TEST_CASE("substitute bytes") { WARN("Not implemented"); }
    TEST_CASE("row shift") {
        auto state = state_t{1, 0x200, 0x30000, 0x4000000};

        auto expected = state_t{1, 2, 3, 4};
        CHECK_EQ(AES<key128_t>::Decryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{3, 4, 9, 10};

        auto expected = state_t{1, 2, 3, 4};
        CHECK_EQ(AES<key128_t>::Decryption::mix_columns(state), expected);
    }
}

TEST_SUITE("common") {
    TEST_CASE("expand key") { WARN("Not implemented"); }
    TEST_CASE("transpose") { WARN("Not implemented"); }
    TEST_CASE("add round key") {
        auto state = state_t{1, 2, 3, 4};
        auto key = state_t{4, 3, 2, 1};

        auto expected = state_t{5, 1, 1, 5};
        CHECK_EQ(AES<key128_t>::Common::add_round_key(state, key), expected);
    }
}
} // namespace understanding_crypto::aes