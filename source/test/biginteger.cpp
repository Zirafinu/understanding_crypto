#include <doctest/doctest.h>
#include <understanding_crypto/biginteger.hpp>

namespace understanding_crypto {

TEST_SUITE("examples") {}

TEST_SUITE("same size") {
    TEST_CASE("constructor") {
        const uint_t<24> a = 0x01020304U;
        const uint_t<sizeof(std::size_t) * 8> b = a;
        CHECK_EQ(a.internal_main[0], 0x020304U);
        CHECK_EQ(b.internal_main[0], 0x020304U);
        const uint_t<sizeof(std::size_t) * 8> c = 0x01020304U;
        const uint_t<24> d = c;
        CHECK_EQ(c.internal_main[0], 0x01020304U);
        CHECK_EQ(d.internal_main[0], 0x020304U);
    }
    TEST_CASE("addition") {
        uint_t<128> a = 0x01020304;
        a.internal_main[0] = ~std::size_t(0);
        a.internal_main[1] = 1;
        const uint_t<128> b = a + a;
        CHECK_EQ(b[0], ~size_t(1));
        CHECK_EQ(b[1], 3);
    }
    TEST_CASE("binary operations") {
        uint_t<128> a = 0x01020304U;
        uint_t<128> b = 0x04030201U;
        const uint_t<128> res_and = a & b;
        const uint_t<128> res_or = a | b;
        const uint_t<128> res_xor = a ^ b;
        CHECK_EQ(res_and[0], 0x00020200U);
        CHECK_EQ(res_or[0], 0x05030305U);
        CHECK_EQ(res_xor[0], 0x05010105U);
    }
}

TEST_SUITE("with integer types") {
    TEST_CASE("constructor") {
        // checked in other Suites
    }
    TEST_CASE("addition") {
        uint_t<128> a{};
        a.internal_main[0] = ~std::size_t(0);
        a.internal_main[1] = 1;
        const uint_t<128> b = a + ~std::size_t(0);
        CHECK_EQ(b[0], ~size_t(1));
        CHECK_EQ(b[1], 2);
    }
    TEST_CASE("subtraction") {
        uint_t<128> a{};
        a.internal_main[0] = 1;
        a.internal_main[1] = 1;
        const uint_t<128> b = a - 2;
        CHECK_EQ(b[0], ~size_t(0));
        CHECK_EQ(b[1], 0);
    }
    TEST_CASE("multiplication") {
        uint_t<128> a{};
        a.internal_main[0] = 0x1000'1000'1000'1000ULL;
        a.internal_main[1] = 0x1000'1000'1000'1000ULL;
        const uint_t<128> b = a * 0x1'0001ULL;
        CHECK_EQ(b[0], size_t(0x1000'1000'1000'1000ULL + 0x1000'1000'1000'0000ULL));
        CHECK_EQ(b[1], size_t(0x1000'1000'1000'1000ULL + 0x1000'1000'1000'1000ULL));

        uint_t<128> c{};
        c.internal_main[0] = ~size_t(0);
        c.internal_main[1] = ~size_t(0);
        const uint_t<128> d = c * ~size_t(0);
        CHECK_EQ(d[0], 0x0000'0000'0000'0001);
        CHECK_EQ(d[1], 0xffff'ffff'ffff'ffff);

        const auto e = uint_t<256>::from_multiplication_of(c, uint_t<64>(~size_t(0)));
        CHECK_EQ(e[0], 0x0000'0000'0000'0001);
        CHECK_EQ(e[1], 0xffff'ffff'ffff'ffff);
        CHECK_EQ(e[2], 0xffff'ffff'ffff'fffe);
        CHECK_EQ(e[3], 0x0000'0000'0000'0000);
    }
    TEST_CASE("binary operations") {
        uint_t<128> a = 0x01020304U;
        uint32_t b = 0x04030201U;
        const uint_t<128> res_and = a & b;
        const uint_t<128> res_or = a | b;
        const uint_t<128> res_xor = a ^ b;
        CHECK_EQ(res_and[0], 0x00020200U);
        CHECK_EQ(res_or[0], 0x05030305U);
        CHECK_EQ(res_xor[0], 0x05010105U);
    }
    TEST_CASE("compare") {
        const uint_t<128> a = 0x0102030405060708ULL;
        const uint_t<128> b = 0x1020304050607080ULL;
        CHECK_EQ(a < b, true);
        CHECK_EQ(b < a, false);
        CHECK_EQ(a < a, false);
        CHECK_EQ(a > b, false);
        CHECK_EQ(b > a, true);
        CHECK_EQ(a > a, false);
        CHECK_EQ(a <= b, true);
        CHECK_EQ(b <= a, false);
        CHECK_EQ(a <= a, true);
        CHECK_EQ(a >= b, false);
        CHECK_EQ(b >= a, true);
        CHECK_EQ(a >= a, true);
        CHECK_EQ(a == b, false);
        CHECK_EQ(a == a, true);
        CHECK_EQ(a != b, true);
        CHECK_EQ(a != a, false);
    }
}

} // namespace understanding_crypto
