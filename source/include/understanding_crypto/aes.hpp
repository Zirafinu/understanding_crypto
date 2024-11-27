#ifndef UNDERSTANDING_CRYPTO_AES_H
#define UNDERSTANDING_CRYPTO_AES_H
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <ranges>
#include <span>

namespace understanding_crypto::aes {
using key128_t = std::span<uint8_t, 16>;
using key192_t = std::span<uint8_t, 24>;
using key256_t = std::span<uint8_t, 32>;

using state_t = std::array<uint32_t, 4>;

template <typename KEY_T> class AES {
    consteval static int round_count() {
        if constexpr (std::is_same_v<KEY_T, key128_t>)
            return 10;
        else if constexpr (std::is_same_v<KEY_T, key192_t>)
            return 12;
        else if constexpr (std::is_same_v<KEY_T, key256_t>)
            return 14;
        else
            static_assert(std::is_same_v<KEY_T, key128_t>, "invalid key type");
    }

  public:
    using key_t = KEY_T;
    constexpr static auto ROUNDS = round_count();
    using expanded_keys_t = std::array<state_t, ROUNDS + 1>;

  public:
    struct Encryption {
        static state_t &row_shift(state_t &state) {
            for (auto i = 1U; i < state.size(); ++i) {
                state[i] = (state[i] << (8 * i)) | (state[i] >> (32 - 8 * 1));
            }
            return state;
        }

        static state_t &mix_columns(state_t &state) {
            state_t last_state = state;
            std::fill(state.begin(), state.end(), 0U);
            for (auto i = 0U; i < sizeof(state[0]); ++i) {
                state[0] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 2) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 3) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 1) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 1))
                            << (8 * i);
                state[1] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 1) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 2) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 3) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 1))
                            << (8 * i);
                state[2] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 1) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 1) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 2) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 3))
                            << (8 * i);
                state[3] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 3) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 1) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 1) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 2))
                            << (8 * i);
            }
            return state;
        }

        static uint32_t substitute_word(uint32_t word) {
            auto &bytes =
                *reinterpret_cast<std::array<uint8_t, sizeof(word)> *>(&word);
            for (auto &byte : bytes) {
                byte = sbox[byte];
            }
            return word;
        }

        static state_t &substitute_bytes(state_t &state) {
            for (auto &word : state) {
                word = substitute_word(word);
            }
            return state;
        }

        static constexpr std::array<uint8_t, 256> sbox = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16};
    };

    struct Decryption {
        static state_t &row_shift(state_t &state) {
            for (auto i = 1U; i < state.size(); ++i) {
                state[i] = (state[i] >> (8 * i)) | (state[i] << (32 - 8 * 1));
            }
            return state;
        }

        static state_t &mix_columns(state_t &state) {
            state_t last_state = state;
            std::fill(state.begin(), state.end(), 0U);
            for (auto i = 0U; i < sizeof(state[0]); ++i) {
                state[0] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 0xE) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 0xB) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 0xD) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 0x9))
                            << (8 * i);
                state[1] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 0x9) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 0xE) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 0xB) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 0xD))
                            << (8 * i);
                state[2] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 0xD) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 0x9) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 0xE) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 0xB))
                            << (8 * i);
                state[3] |= (GF_MULTIPLY(last_state[0] >> (8 * i), 0xB) ^
                             GF_MULTIPLY(last_state[1] >> (8 * i), 0xD) ^
                             GF_MULTIPLY(last_state[2] >> (8 * i), 0x9) ^
                             GF_MULTIPLY(last_state[3] >> (8 * i), 0xE))
                            << (8 * i);
            }
            return state;
        }

        static uint32_t substitute_word(uint32_t word) {
            auto &bytes =
                *reinterpret_cast<std::array<uint8_t, sizeof(word)> *>(&word);
            for (auto &byte : bytes) {
                byte = sbox[byte];
            }
            return word;
        }

        static state_t substitute_bytes(state_t &state) {
            for (auto &word : state) {
                word = substitute_word(word);
            }
            return state;
        }

        static constexpr std::array<uint8_t, 256> sbox{
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d};
    };

    struct Common {
        static state_t &add_round_key(state_t &state, const state_t &key) {
            for (const auto [word, key] : std::views::zip(state, key)) {
                word ^= key;
            }
            return state;
        }

        static expanded_keys_t expand_key(const key_t &key) {
            expanded_keys_t expanded{};
            auto &linear_view = *reinterpret_cast<
                std::array<uint32_t, (ROUNDS + 1) * sizeof(uint32_t)> *>(
                &expanded);
            constexpr auto N = key.size() / sizeof(uint32_t);

            for (auto i = 0U; i < key.size(); ++i) {
                linear_view[i / 4] <<= 8;
                linear_view[i / 4] |= key[i];
            }

            auto round_key = 0x01;
            for (auto i = N; i < linear_view.size(); ++i) {
                auto tmp = linear_view[i - 1];
                if ((i % N) == 0) {
                    tmp = Encryption::substitute_word((tmp >> 24) | (tmp << 8));
                    tmp ^= round_key << 24;
                    round_key = GF_MULTIPLY(round_key, 2);
                } else if ((N > 6) && ((i % N) == 4)) {
                    tmp = Encryption::substitute_word(tmp);
                }
                linear_view[i] = linear_view[i - N] ^ tmp;
            }
            return expanded;
        }

        static state_t &transpose(state_t &state) {
            auto copy = state;
            for (auto i = 0U; i < state.size(); ++i) {
                state[3 - i] = (((copy[0] >> (8 * i)) & 0xFF) << 24) |
                               (((copy[1] >> (8 * i)) & 0xFF) << 16) |
                               (((copy[2] >> (8 * i)) & 0xFF) << 8) |
                               (((copy[3] >> (8 * i)) & 0xFF) << 0);
            }
            return state;
        }
    };

  public:
    static uint8_t GF_MULTIPLY(uint8_t value, uint8_t factor) {
        uint_fast16_t compute = value;
        uint8_t result = (factor & 0x1) ? value : 0;
        while (factor > 1) {
            compute <<= 1;
            factor >>= 1;
            if (compute & 0x100) {
                compute ^= 0x1b;
            }
            if (factor & 1) {
                result ^= compute;
            }
        }
        return result;
    }
};
} // namespace understanding_crypto::aes

#endif
