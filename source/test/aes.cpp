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
        auto state = state_t{0x01020304, 0x02030405, 0x03040506, 0x04050607};

        constexpr auto expected =
            state_t{0x01020304, 0x03040502, 0x05060304, 0x07040506};
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
        auto state = state_t{0x01020304, 0x03040502, 0x05060304, 0x07040506};

        constexpr auto expected =
            state_t{0x01020304, 0x02030405, 0x03040506, 0x04050607};
        CHECK_EQ(AES<key128_t>::Decryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{3, 4, 9, 10};

        constexpr auto expected = state_t{1, 2, 3, 4};
        CHECK_EQ(AES<key128_t>::Decryption::mix_columns(state), expected);
    }
}

TEST_SUITE("common") {
    TEST_CASE("expand key 128 bits") {
        uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        key128_t key_s{key};
        const auto expanded = AES<key128_t>::Common::expand_key(key_s);

        auto expected_0 =
            state_t{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
        auto expected_1 =
            state_t{0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605};
        auto expected_10 =
            state_t{0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6};
        CHECK_EQ(expanded[0], expected_0);
        CHECK_EQ(expanded[1], expected_1);
        CHECK_EQ(expanded[10], expected_10);
    }
    TEST_CASE("expand key 192 bits") {
        uint8_t key[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                         0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                         0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
        key192_t key_s{key};
        const auto expanded = AES<key192_t>::Common::expand_key(key_s);

        auto expected_0 =
            state_t{0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5};
        auto expected_1 =
            state_t{0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5};
        auto expected_12 =
            state_t{0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202};
        CHECK_EQ(expanded[0], expected_0);
        CHECK_EQ(expanded[1], expected_1);
        CHECK_EQ(expanded[12], expected_12);
    }
    TEST_CASE("expand key 256 bits") {
        uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                         0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                         0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                         0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
        key256_t key_s{key};
        const auto expanded = AES<key256_t>::Common::expand_key(key_s);

        auto expected_0 =
            state_t{0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781};
        auto expected_1 =
            state_t{0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
        auto expected_14 =
            state_t{0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e};
        CHECK_EQ(expanded[0], expected_0);
        CHECK_EQ(expanded[1], expected_1);
        CHECK_EQ(expanded[14], expected_14);
    }
    TEST_CASE("transpose") {
        state_t state = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10};
        constexpr auto expected =
            state_t{0x0105090d, 0x02060a0e, 0x03070b0f, 0x04080c10};
        CHECK_EQ(AES<key128_t>::Common::transpose(state), expected);
    }
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
