#include <doctest/doctest.h>
#include <understanding_crypto/aes.hpp>

namespace understanding_crypto::aes {

TEST_SUITE("examples") {
    TEST_CASE("encrypt block") { WARN("Not implemented"); }
    TEST_CASE("decrypt block") { WARN("Not implemented"); }
}

TEST_SUITE("encrypt") {
    TEST_CASE("substitute bytes") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected =
            state_t{0x6363637c, 0x63636377, 0x6363637b, 0x636363f2};
        CHECK_EQ(AES<key128_t>::Encryption::substitute_bytes(state), expected);
    }
    TEST_CASE("row shift") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected = state_t{1, 0x200, 0x30000, 0x4000000};
        CHECK_EQ(AES<key128_t>::Encryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected = state_t{3, 4, 9, 10};
        CHECK_EQ(AES<key128_t>::Encryption::mix_columns(state), expected);
    }
}

TEST_SUITE("decrypt") {
    TEST_CASE("substitute bytes") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected =
            state_t{0x52525209, 0x5252526a, 0x525252d5, 0x52525230};
        CHECK_EQ(AES<key128_t>::Decryption::substitute_bytes(state), expected);
    }
    TEST_CASE("row shift") {
        auto state = state_t{1, 0x200, 0x30000, 0x4000000};

        constexpr auto expected = state_t{1, 2, 3, 4};
        CHECK_EQ(AES<key128_t>::Decryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{3, 4, 9, 10};

        constexpr auto expected = state_t{1, 2, 3, 4};
        CHECK_EQ(AES<key128_t>::Decryption::mix_columns(state), expected);
    }
}

TEST_SUITE("common") {
    TEST_CASE("expand key") { WARN("Not implemented"); }
    TEST_CASE("transpose") { WARN("Not implemented"); }
    TEST_CASE("add round key") {
        auto state = state_t{1, 2, 3, 4};
        constexpr auto key = state_t{4, 3, 2, 1};

        constexpr auto expected = state_t{5, 1, 1, 5};
        CHECK_EQ(AES<key128_t>::Common::add_round_key(state, key), expected);
    }
}
} // namespace understanding_crypto::aes

namespace std {
std::ostream &operator<<(std::ostream &os,
                         const std::array<uint32_t, 4> &value) {
    os << std::hex << "[" << value[0] << "," << value[1] << "," << value[2]
       << "," << value[3] << "]";
    return os;
}
} // namespace std
