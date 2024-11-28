#include <doctest/doctest.h>
#include <understanding_crypto/aes.hpp>

namespace understanding_crypto::aes {

TEST_SUITE("examples") {
    TEST_CASE("encrypt block") {
        uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        key128_t key_s{key};
        auto expanded = AES::Common::expand_key(key_s);
        state_t data = {0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734};
        AES::encrypt(data, expanded);

        constexpr state_t expected = {0x3925841d, 0x02dc09fb, 0xdc118597,
                                      0x196a0b32};
        CHECK_EQ(data, expected);
    }
    TEST_CASE("decrypt block") {
        uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        key128_t key_s{key};
        auto expanded = AES::Common::expand_key(key_s);
        state_t data = {0x3925841d, 0x02dc09fb, 0xdc118597, 0x196a0b32};
        AES::decrypt(data, expanded);

        constexpr state_t expected = {0x3243f6a8, 0x885a308d, 0x313198a2,
                                      0xe0370734};
        CHECK_EQ(data, expected);
    }
}

TEST_SUITE("encrypt") {
    TEST_CASE("substitute bytes") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected =
            state_t{0x6363637c, 0x63636377, 0x6363637b, 0x636363f2};
        CHECK_EQ(AES::Encryption::substitute_bytes(state), expected);
    }
    TEST_CASE("row shift") {
        auto state = state_t{0x01020304, 0x02030405, 0x03040506, 0x04050607};

        constexpr auto expected =
            state_t{0x01020304, 0x03040502, 0x05060304, 0x07040506};
        CHECK_EQ(AES::Encryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected = state_t{3, 4, 9, 10};
        CHECK_EQ(AES::Encryption::mix_columns(state), expected);
    }
}

TEST_SUITE("decrypt") {
    TEST_CASE("substitute bytes") {
        auto state = state_t{1, 2, 3, 4};

        constexpr auto expected =
            state_t{0x52525209, 0x5252526a, 0x525252d5, 0x52525230};
        CHECK_EQ(AES::Decryption::substitute_bytes(state), expected);
    }
    TEST_CASE("row shift") {
        auto state = state_t{0x01020304, 0x03040502, 0x05060304, 0x07040506};

        constexpr auto expected =
            state_t{0x01020304, 0x02030405, 0x03040506, 0x04050607};
        CHECK_EQ(AES::Decryption::row_shift(state), expected);
    }
    TEST_CASE("column mix") {
        auto state = state_t{3, 4, 9, 10};

        constexpr auto expected = state_t{1, 2, 3, 4};
        CHECK_EQ(AES::Decryption::mix_columns(state), expected);
    }
}

TEST_SUITE("common") {
    TEST_CASE("expand key 128 bits") {
        uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
        key128_t key_s{key};
        const auto expanded = AES::Common::expand_key(key_s);

        constexpr auto expected_0 =
            state_t{0x2b28ab09, 0x7eaef7cf, 0x15d2154f, 0x16a6883c};
        constexpr auto expected_1 =
            state_t{0xa088232a, 0xfa54a36c, 0xfe2c3976, 0x17b13905};
        constexpr auto expected_10 =
            state_t{0xd0c9e1b6, 0x14ee3f63, 0xf9250c0c, 0xa889c8a6};
        CHECK_EQ(expanded[0], expected_0);
        CHECK_EQ(expanded[1], expected_1);
        CHECK_EQ(expanded[10], expected_10);
    }
    TEST_CASE("expand key 192 bits") {
        uint8_t key[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                         0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                         0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
        key192_t key_s{key};
        const auto expanded = AES::Common::expand_key(key_s);

        constexpr auto expected_0 =
            state_t{0x8edac880, 0x730e1090, 0xb064f379, 0xf7522be5};
        constexpr auto expected_1 =
            state_t{0x6252fe24, 0xf82c0c02, 0xea6b91f5, 0xd27bf7a5};
        constexpr auto expected_12 =
            state_t{0xe9448e01, 0x8b8ccc00, 0xa0777222, 0x6f3c0402};
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
        const auto expanded = AES::Common::expand_key(key_s);

        constexpr auto expected_0 =
            state_t{0x60152b85, 0x3dca737d, 0xeb71ae77, 0x10bef081};
        constexpr auto expected_1 =
            state_t{0x1f3b2d09, 0x35619814, 0x2c0810df, 0x07d7a3f4};
        constexpr auto expected_14 =
            state_t{0xfee60470, 0x48186d6c, 0x908df363, 0xd10b441e};
        CHECK_EQ(expanded[0], expected_0);
        CHECK_EQ(expanded[1], expected_1);
        CHECK_EQ(expanded[14], expected_14);
    }
    TEST_CASE("transpose") {
        state_t state = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10};
        constexpr auto expected =
            state_t{0x0105090d, 0x02060a0e, 0x03070b0f, 0x04080c10};
        CHECK_EQ(AES::Common::transpose(state), expected);
    }
    TEST_CASE("add round key") {
        auto state = state_t{1, 2, 3, 4};
        constexpr auto key = state_t{4, 3, 2, 1};

        constexpr auto expected = state_t{5, 1, 1, 5};
        CHECK_EQ(AES::Common::add_round_key(state, key), expected);
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
