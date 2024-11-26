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
using state_t = std::array<uint32_t, 4>;
template <typename KEY_T> class AES {
  public:
    using key_t = KEY_T;

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
    };

    struct Common {
        static state_t &add_round_key(state_t &state, const state_t &key) {
            for (const auto [word, key] : std::views::zip(state, key)) {
                word ^= key;
            }
            return state;
        }
    };

  public:
    static uint8_t GF_MULTIPLY(uint8_t value, uint8_t factor) {
        uint8_t result = (factor & 0x1) ? value : 0;
        while (factor > 1) {
            value <<= 1;
            factor >>= 1;
            if (value & 0x100) {
                value ^= 0x1b;
            }
            if (factor & 1) {
                result ^= value;
            }
        }
        return result;
    }
};
} // namespace understanding_crypto::aes

#endif
