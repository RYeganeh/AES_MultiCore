#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

// S-box from FIPS 197 Figure 7
static const std::array<uint8_t, 256> s_box = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round constants from Section 5.2
static const std::array<uint8_t, 10> rcon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// Type aliases for clarity
using State = std::array<std::array<uint8_t, 4>, 4>;
using Key192 = std::array<uint8_t, 24>;
using Block = std::array<uint8_t, 16>;
using RoundKeys = std::array<State, 13>;

class AES192 {
private:
    RoundKeys round_keys_;
    std::vector<std::string> round_outputs_;

    static void bytes_to_state(const Block& block, State& state) {
        // Convert 16-byte block to 4x4 state array (Section 3.4)
        for (size_t r = 0; r < 4; ++r) {
            for (size_t c = 0; c < 4; ++c) {
                state[r][c] = block[r + 4 * c];
            }
        }
    }

    static Block state_to_bytes(const State& state) {
        // Convert 4x4 state array to 16-byte block (Section 3.4)
        Block block{};
        for (size_t r = 0; r < 4; ++r) {
            for (size_t c = 0; c < 4; ++c) {
                block[r + 4 * c] = state[r][c];
            }
        }
        return block;
    }

    static void sub_bytes(State& state) {
        // Apply S-box to each byte of the state (Section 5.1.1)
        for (size_t r = 0; r < 4; ++r) {
            for (size_t c = 0; c < 4; ++c) {
                state[r][c] = s_box[state[r][c]];
            }
        }
    }

    static void shift_rows(State& state) {
        // Cyclically shift rows of the state (Section 5.1.2)
        for (size_t r = 1; r < 4; ++r) {
            std::array<uint8_t, 4> temp = state[r];
            for (size_t c = 0; c < 4; ++c) {
                state[r][c] = temp[(c + r) % 4];
            }
        }
    }

    static uint8_t xtime(uint8_t a) {
        // Multiply by x in GF(2^8) (Section 4.2.1)
        uint8_t b = (a << 1);
        if (a & 0x80) {
            b ^= 0x1b;
        }
        return b;
    }

    static void mix_columns(State& state) {
        // Mix columns transformation (Section 5.1.3)
        for (size_t c = 0; c < 4; ++c) {
            std::array<uint8_t, 4> col = {state[0][c], state[1][c], state[2][c], state[3][c]};
            state[0][c] = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
            state[1][c] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3];
            state[2][c] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]);
            state[3][c] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]);
        }
    }

    static void add_round_key(State& state, const State& round_key) {
        // XOR state with round key (Section 5.1.4)
        for (size_t r = 0; r < 4; ++r) {
            for (size_t c = 0; c < 4; ++c) {
                state[r][c] ^= round_key[r][c];
            }
        }
    }

    void key_expansion(const Key192& key) {
        // Expand 192-bit key into round keys (Section 5.2)
        const size_t Nk = 6, Nr = 12;
        std::array<uint8_t, 4 * (Nr + 1) * 4> w{};

        // Initial key
        for (size_t i = 0; i < Nk * 4; ++i) {
            w[i] = key[i];
        }

        // Key expansion
        for (size_t i = Nk; i < 4 * (Nr + 1); ++i) {
            std::array<uint8_t, 4> temp = {w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3]};
            if (i % Nk == 0) {
                // RotWord
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                // SubWord
                for (size_t j = 0; j < 4; ++j) {
                    temp[j] = s_box[temp[j]];
                }
                // XOR with Rcon
                temp[0] ^= rcon[i / Nk - 1];
            }
            for (size_t j = 0; j < 4; ++j) {
                w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
            }
        }

        // Convert to round key states
        for (size_t i = 0; i < Nr + 1; ++i) {
            for (size_t r = 0; r < 4; ++r) {
                for (size_t c = 0; c < 4; ++c) {
                    round_keys_[i][r][c] = w[i * 16 + r + 4 * c];
                }
            }
        }
    }

    void record_state(const std::string& label, const State& state) {
        // Record state as a hexadecimal string for output
        round_outputs_.push_back(label + " " + bytes_to_hex(state_to_bytes(state)));
    }

    void record_state(const std::string& label, const Block& block) {
        // Record block as a hexadecimal string for output
        round_outputs_.push_back(label + " " + bytes_to_hex(block));
    }

public:
    static std::string bytes_to_hex(const Block& bytes) {
        // Convert 16-byte array to hexadecimal string
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : bytes) {
            ss << std::setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    static std::string key_to_hex(const Key192& key) {
        // Convert 24-byte key to hexadecimal string
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : key) {
            ss << std::setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    AES192(const Key192& key) {
        key_expansion(key);
        round_outputs_.reserve(60); // Pre-allocate for round outputs
    }

    Block encrypt_with_output(const Block& plaintext) {
        // AES encryption with round-by-round output (Section 5.1)
        round_outputs_.clear();
        round_outputs_.push_back("CIPHER (ENCRYPT):\n");

        State state;
        bytes_to_state(plaintext, state);

        // Round 0
        record_state("round[ 0].input", plaintext);
        record_state("round[ 0].k_sch", state_to_bytes(round_keys_[0]));
        add_round_key(state, round_keys_[0]);
        record_state("round[ 1].start", state);

        // Rounds 1 to 11
        for (size_t round = 1; round < 12; ++round) {
            sub_bytes(state);
            std::stringstream ss;
            ss << "round[" << std::setw(2) << round << "].s_box";
            record_state(ss.str(), state);

            shift_rows(state);
            ss.str("");
            ss << "round[" << std::setw(2) << round << "].s_row";
            record_state(ss.str(), state);

            mix_columns(state);
            ss.str("");
            ss << "round[" << std::setw(2) << round << "].m_col";
            record_state(ss.str(), state);

            ss.str("");
            ss << "round[" << std::setw(2) << round << "].k_sch";
            record_state(ss.str(), state_to_bytes(round_keys_[round]));

            add_round_key(state, round_keys_[round]);
            ss.str("");
            ss << "round[" << std::setw(2) << round + 1 << "].start";
            record_state(ss.str(), state);
        }

        // Final round (12)
        sub_bytes(state);
        record_state("round[12].s_box", state);
        shift_rows(state);
        record_state("round[12].s_row", state);
        record_state("round[12].k_sch", state_to_bytes(round_keys_[12]));
        add_round_key(state, round_keys_[12]);
        record_state("round[12].output", state);

        return state_to_bytes(state);
    }

    const std::vector<std::string>& get_round_outputs() const {
        // Return recorded round outputs
        return round_outputs_;
    }
};

void test_aes() {
    // Test with provided example from FIPS 197 Appendix C.2
    Key192 key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    Block plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    Block expected_ciphertext = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};

    AES192 aes(key);

    std::cout << "PLAINTEXT: " << AES192::bytes_to_hex(plaintext) << "\n\n";
    std::cout << "KEY: " << AES192::key_to_hex(key) << "\n\n";
    Block ciphertext = aes.encrypt_with_output(plaintext);

    // Print round outputs
    for (const auto& output : aes.get_round_outputs()) {
        std::cout << output << '\n';
    }

    if (ciphertext == expected_ciphertext) {
        std::cout << "\nCiphertext matches expected: " << AES192::bytes_to_hex(ciphertext) << '\n';
    } else {
        std::cout << "\nEncryption failed: " << AES192::bytes_to_hex(ciphertext)
                  << " != " << AES192::bytes_to_hex(expected_ciphertext) << '\n';
    }
}

int main() {
    test_aes();
    return 0;
}
