#ifndef UNDERSTANDING_CRYPTO_BIG_INT_H
#define UNDERSTANDING_CRYPTO_BIG_INT_H
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace understanding_crypto {
template <std::size_t BITS> struct uint_t {
    enum class Compare_Operation { EQUALS, GREATER, LESS, GREATER_EQUAL, LESS_EQUAL };
    enum class Binary_Operation { AND, OR, XOR, ADDITION, SUBTRACTION };

    using value_t = size_t;
    using this_t = uint_t<BITS>;
    using half_value_t =
        std::conditional_t<sizeof(value_t) == sizeof(uint64_t), uint32_t,
                           std::conditional_t<sizeof(value_t) == sizeof(uint32_t), uint16_t, void>>;

    static constexpr auto bit_count = BITS;
    static constexpr auto bits_in_word = 8 * sizeof(value_t);
    static constexpr auto bit_count_last_word = bit_count & (bits_in_word - 1);
    static constexpr auto word_count = (bit_count + bits_in_word - 1) / (bits_in_word);

    std::array<value_t, word_count> internal_main;

    constexpr void trim() {
        if constexpr (bit_count_last_word > 0) {
            internal_main.back() &= (value_t(1) << bit_count_last_word) - 1;
        }
    }

  public:
    constexpr uint_t() = default;

    constexpr uint_t(std::integral auto rhs) {
        for (size_t j = 0; j < internal_main.size(); ++j) {
            internal_main[j] = rhs;
            rhs >>= std::min((sizeof(value_t) * 4), sizeof(decltype(rhs)) * 4);
            rhs >>= std::min((sizeof(value_t) * 4), sizeof(decltype(rhs)) * 4);
        }
        trim();
    }

    template <size_t bits> constexpr uint_t(uint_t<bits> const &rhs) {
        using other_t = uint_t<bits>;
        constexpr auto other_word_count = other_t::word_count;
        constexpr auto copy_main = std::min(word_count, other_word_count);

        for (size_t i = 0; i < copy_main; ++i) {
            internal_main[i] = rhs.internal_main[i];
        }
        for (size_t i = copy_main; i < word_count; ++i) {
            internal_main[i] = 0;
        }
        trim();
    }

    template <typename T> constexpr this_t &operator=(std::integral auto rhs) {
        for (size_t j = 0; j < internal_main.size(); ++j) {
            internal_main[j] = rhs;
            rhs >>= std::min((sizeof(value_t) * 4), sizeof(decltype(rhs)) * 4);
            rhs >>= std::min((sizeof(value_t) * 4), sizeof(decltype(rhs)) * 4);
        }
        trim();
        return *this;
    }

    template <size_t bits> constexpr this_t &operator=(uint_t<bits> const &rhs) {
        using other_t = uint_t<bits>;
        constexpr auto other_word_count = other_t::word_count;
        constexpr auto copy_main = std::min(word_count, other_word_count);

        for (size_t i = 0; i < copy_main; ++i) {
            internal_main[i] = rhs.internal_main[i];
        }
        for (size_t i = copy_main; i < word_count; ++i) {
            internal_main[i] = 0;
        }
        trim();
        return *this;
    }

    template <size_t lhs_bits, size_t rhs_bits>
    constexpr static this_t from_multiplication_of(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
        using lhs_t = uint_t<lhs_bits>;
        using rhs_t = uint_t<rhs_bits>;
        using res_t = this_t;
        res_t res{};

        for (size_t i = 0; i < std::min(res_t::word_count, lhs_t::word_count); ++i) {
            for (size_t j = 0; ((j + i) < res_t::word_count) && (j < rhs_t::word_count); ++j) {
                auto low_word = half_value_t(lhs[i]) * value_t(half_value_t(rhs[j]));
                const auto mid_lhs_word = value_t(half_value_t(lhs[i])) * (rhs[j] >> (bits_in_word / 2));
                const auto mid_rhs_word = (lhs[i] >> (bits_in_word / 2)) * value_t(half_value_t(rhs[j]));

                const size_t mid_sum_low =
                    value_t(half_value_t(mid_lhs_word)) + value_t(half_value_t(mid_rhs_word));
                size_t carry = mid_sum_low >> (bits_in_word / 2);
                low_word += mid_sum_low << (bits_in_word / 2);
                carry += (low_word < (mid_sum_low << (bits_in_word / 2)));
                res[i + j] += low_word;
                carry += (res[i + j] < low_word);

                if ((i + j + 1) < res_t::word_count) {
                    const size_t mid_sum_high = value_t(mid_lhs_word >> (bits_in_word / 2)) +
                                                value_t(mid_rhs_word >> (bits_in_word / 2));
                    auto high_word = (lhs[i] >> (bits_in_word / 2)) * (rhs[j] >> (bits_in_word / 2));
                    high_word += carry;
                    carry = (high_word < carry);
                    high_word += mid_sum_high;
                    carry += high_word < mid_sum_high;
                    res[i + j + 1] += high_word;
                    carry += res[i + j + 1] < high_word;
                }
                for (size_t k = i + j + 2; carry && (k < res_t::word_count); ++k) {
                    res[k] += carry;
                    carry = (res[k] < carry);
                }
            }
        }

        res.trim();
        return res;
    }

    template <Compare_Operation operation, size_t lhs_bits, size_t rhs_bits>
    constexpr static auto compare(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
        using lhs_t = uint_t<lhs_bits>;
        using rhs_t = uint_t<rhs_bits>;
        constexpr size_t min_index = std::min(lhs_t::word_count, rhs_t::word_count);
        constexpr size_t max_index = std::max(lhs_t::word_count, rhs_t::word_count);

        constexpr auto apply = [](value_t lhs, value_t rhs) {
            if constexpr (operation == Compare_Operation::EQUALS) {
                return lhs == rhs;
            } else if constexpr (operation == Compare_Operation::GREATER) {
                return lhs > rhs;
            } else if constexpr (operation == Compare_Operation::LESS) {
                return lhs < rhs;
            } else if constexpr (operation == Compare_Operation::GREATER_EQUAL) {
                return lhs >= rhs;
            } else if constexpr (operation == Compare_Operation::LESS_EQUAL) {
                return lhs <= rhs;
            }
        };

        for (size_t i = max_index - 1; i > (min_index - 1); ++i) {
            if constexpr (max_index == lhs_t::word_count) {
                if (lhs[i] == 0)
                    continue;
                return apply(lhs[i], 0);
            } else {
                if (rhs[i] == 0)
                    continue;
                return apply(0, rhs[i]);
            }
        }

        for (size_t i = min_index - 1; i < min_index; --i) {
            if (lhs[i] == rhs[i])
                continue;
            return apply(lhs[i], rhs[i]);
        }
        if constexpr (operation == Compare_Operation::GREATER || operation == Compare_Operation::LESS) {
            return false;
        }
        return true;
    }

    template <Binary_Operation operation, size_t lhs_bits, size_t rhs_bits>
    constexpr static this_t from_binary_operation_on(uint_t<lhs_bits> const &lhs,
                                                     uint_t<rhs_bits> const &rhs) {
        using res_t = this_t;
        using lhs_t = uint_t<lhs_bits>;
        using rhs_t = uint_t<rhs_bits>;
        res_t res;

        constexpr size_t min_index =
            std::min(res_t::word_count, std::min(lhs_t::word_count, rhs_t::word_count));
        constexpr size_t longer_word_count = std::max(lhs_t::word_count, rhs_t::word_count);
        constexpr size_t compute_word_count = std::min(res_t::word_count, longer_word_count);

        size_t carry = 0;
        for (size_t i = 0U; i < min_index; ++i) {
            res[i] = lhs[i];
            if constexpr (operation == Binary_Operation::AND) {
                res[i] &= rhs[i];
            } else if constexpr (operation == Binary_Operation::OR) {
                res[i] |= rhs[i];
            } else if constexpr (operation == Binary_Operation::XOR) {
                res[i] ^= rhs[i];
            } else if constexpr (operation == Binary_Operation::ADDITION) {
                res[i] += carry;
                carry = res[i] < carry;
                res[i] += rhs[i];
                carry += res[i] < rhs[i];
            } else if constexpr (operation == Binary_Operation::SUBTRACTION) {
                res[i] -= carry;
                carry = res[i] > lhs[i];
                const auto tmp = res[i] - rhs[i];
                carry |= tmp > res[i];
                res[i] = tmp;
            }
        }

        if constexpr (operation == Binary_Operation::AND) {
            for (size_t i = min_index; i < res_t::word_count; ++i) {
                res[i] = 0;
            }
        } else if constexpr (operation == Binary_Operation::OR || operation == Binary_Operation::XOR ||
                             operation == Binary_Operation::ADDITION ||
                             operation == Binary_Operation::SUBTRACTION) {
            for (size_t i = min_index; i < compute_word_count; ++i) {
                if constexpr (longer_word_count == rhs_t::word_count) {
                    if constexpr (operation == Binary_Operation::SUBTRACTION) {
                        res[i] = value_t(0) - carry;
                        res[i] -= rhs[i];
                        carry |= bool(rhs[i]);
                    } else {
                        res[i] = rhs[i];
                    }
                } else {
                    if constexpr (operation == Binary_Operation::SUBTRACTION) {
                        res[i] = lhs[i] - carry;
                        carry = res[i] > lhs[i];
                    } else {
                        res[i] = lhs[i];
                    }
                }
                if constexpr (operation == Binary_Operation::ADDITION) {
                    res[i] += carry;
                    carry = res[i] < carry;
                }
            }

            if constexpr (operation == Binary_Operation::SUBTRACTION) {
                carry = 0 - carry;
            }

            for (size_t i = longer_word_count; i < res_t::word_count; ++i) {
                res[i] = carry;
                if constexpr (operation == Binary_Operation::ADDITION) {
                    carry = 0;
                }
            }
        }

        res.trim();
        return res;
    }

  public:
    constexpr auto &&operator[](this auto &&self, size_t word_index) {
        return self.internal_main[word_index];
    }
};

template <std::size_t lhs_bits> auto operator+(uint_t<lhs_bits> const &lhs, std::integral auto rhs) {
    using rhs_t = uint_t<sizeof(decltype(rhs)) * 8>;
    return lhs + rhs_t(rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator+(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template from_binary_operation_on<res_t::Binary_Operation::ADDITION>(lhs, rhs);
}

template <std::size_t lhs_bits> auto operator-(uint_t<lhs_bits> const &lhs, std::integral auto rhs) {
    using rhs_t = uint_t<sizeof(decltype(rhs)) * 8>;
    return lhs - rhs_t(rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator-(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template from_binary_operation_on<res_t::Binary_Operation::SUBTRACTION>(lhs, rhs);
}

template <std::size_t lhs_bits> auto operator*(uint_t<lhs_bits> const &lhs, std::integral auto rhs) {
    using rhs_t = uint_t<sizeof(decltype(rhs)) * 8>;
    return lhs * rhs_t(rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator*(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::from_multiplication_of(lhs, rhs);
}

template <std::size_t lhs_bits> auto operator&(uint_t<lhs_bits> const &lhs, std::integral auto rhs) {
    using rhs_t = uint_t<sizeof(decltype(rhs)) * 8>;
    return lhs & rhs_t(rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator&(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template from_binary_operation_on<res_t::Binary_Operation::AND>(lhs, rhs);
}

template <std::size_t lhs_bits> auto operator|(uint_t<lhs_bits> const &lhs, std::integral auto rhs) {
    using rhs_t = uint_t<sizeof(decltype(rhs)) * 8>;
    return lhs | rhs_t(rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator|(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template from_binary_operation_on<res_t::Binary_Operation::OR>(lhs, rhs);
}

template <std::size_t lhs_bits> auto operator^(uint_t<lhs_bits> const &lhs, std::integral auto rhs) {
    using rhs_t = uint_t<sizeof(decltype(rhs)) * 8>;
    return lhs ^ rhs_t(rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator^(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template from_binary_operation_on<res_t::Binary_Operation::XOR>(lhs, rhs);
}

template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator<(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template compare<res_t::Compare_Operation::LESS>(lhs, rhs);
}
template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator>(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template compare<res_t::Compare_Operation::GREATER>(lhs, rhs);
}
template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator<=(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template compare<res_t::Compare_Operation::LESS_EQUAL>(lhs, rhs);
}
template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator>=(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template compare<res_t::Compare_Operation::GREATER_EQUAL>(lhs, rhs);
}
template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator==(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return res_t::template compare<res_t::Compare_Operation::EQUALS>(lhs, rhs);
}
template <std::size_t lhs_bits, std::size_t rhs_bits>
auto operator!=(uint_t<lhs_bits> const &lhs, uint_t<rhs_bits> const &rhs) {
    using res_t = uint_t<std::max(lhs_bits, rhs_bits)>;
    return !res_t::template compare<res_t::Compare_Operation::EQUALS>(lhs, rhs);
}

} // namespace understanding_crypto

#endif
