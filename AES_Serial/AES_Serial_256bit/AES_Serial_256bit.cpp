#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

// S-box from FIPS 197 Figure 7
const std::array<uint8_t, 256> s_box = {
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
const std::array<uint8_t, 10> rcon = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// Type aliases for clarity
using State = std::array<std::array<uint8_t, 4>, 4>;
using Key256 = std::array<uint8_t, 32>;
using Block = std::array<uint8_t, 16>;
using RoundKeys = std::array<State, 15>;

void bytes_to_state(const Block& block, State& state) {
    // Convert 16-byte block to 4x4 state array (Section 3.4)
    for (size_t r = 0; r < 4; ++r) {
        for (size_t c = 0; c < 4; ++c) {
            state[r][c] = block[r + 4 * c];
        }
    }
}

Block state_to_bytes(const State& state) {
    // Convert 4x4 state array to 16-byte block (Section 3.4)
    Block block{};
    for (size_t r = 0; r < 4; ++r) {
        for (size_t c = 0; c < 4; ++c) {
            block[r + 4 * c] = state[r][c];
        }
    }
    return block;
}

std::string bytes_to_hex(const Block& bytes) {
    // Convert 16-byte array to hexadecimal string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::string key_to_hex(const Key256& key) {
    // Convert 32-byte key to hexadecimal string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : key) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

void sub_bytes(State& state) {
    // Apply S-box to each byte of the state (Section 5.1.1)
    for (size_t r = 0; r < 4; ++r) {
        for (size_t c = 0; c < 4; ++c) {
            state[r][c] = s_box[state[r][c]];
        }
    }
}

void shift_rows(State& state) {
    // Cyclically shift rows of the state (Section 5.1.2)
    for (size_t r = 1; r < 4; ++r) {
        std::array<uint8_t, 4> temp = state[r];
        for (size_t c = 0; c < 4; ++c) {
            state[r][c] = temp[(c + r) % 4];
        }
    }
}

uint8_t xtime(uint8_t a) {
    // Multiply by x in GF(2^8) (Section 4.2.1)
    uint8_t b = (a << 1);
    if (a & 0x80) {
        b ^= 0x1b;
    }
    return b;
}

void mix_columns(State& state) {
    // Mix columns transformation (Section 5.1.3)
    for (size_t c = 0; c < 4; ++c) {
        std::array<uint8_t, 4> col = {state[0][c], state[1][c], state[2][c], state[3][c]};
        state[0][c] = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
        state[1][c] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3];
        state[2][c] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]);
        state[3][c] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]);
    }
}

void add_round_key(State& state, const State& round_key) {
    // XOR state with round key (Section 5.1.4)
    for (size_t r = 0; r < 4; ++r) {
        for (size_t c = 0; c < 4; ++c) {
            state[r][c] ^= round_key[r][c];
        }
    }
}

RoundKeys key_expansion(const Key256& key) {
    // Expand 256-bit key into round keys (Section 5.2)
    const size_t Nk = 8, Nr = 14;
    RoundKeys round_keys{};
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
        } else if (i % Nk == 4) {
            // SubWord for AES-256
            for (size_t j = 0; j < 4; ++j) {
                temp[j] = s_box[temp[j]];
            }
        }
        for (size_t j = 0; j < 4; ++j) {
            w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
        }
    }

    // Convert to round key states
    for (size_t i = 0; i < Nr + 1; ++i) {
        for (size_t r = 0; r < 4; ++r) {
            for (size_t c = 0; c < 4; ++c) {
                round_keys[i][r][c] = w[i * 16 + r + 4 * c];
            }
        }
    }
    return round_keys;
}

Block cipher_with_output(const Block& plaintext, const Key256& key) {
    // AES encryption with round-by-round output (Section 5.1)
    std::cout << "CIPHER (ENCRYPT):\n\n";
    State state;
    bytes_to_state(plaintext, state);
    RoundKeys round_keys = key_expansion(key);

    // Round 0
    std::cout << "round[ 0].input  " << bytes_to_hex(plaintext) << '\n';
    std::cout << "round[ 0].k_sch  " << bytes_to_hex(state_to_bytes(round_keys[0])) << '\n';
    add_round_key(state, round_keys[0]);
    std::cout << "round[ 1].start  " << bytes_to_hex(state_to_bytes(state)) << '\n';

    // Rounds 1 to 13
    for (size_t round = 1; round < 14; ++round) {
        sub_bytes(state);
        std::cout << "round[" << std::setw(2) << round << "].s_box  " << bytes_to_hex(state_to_bytes(state)) << '\n';
        shift_rows(state);
        std::cout << "round[" << std::setw(2) << round << "].s_row  " << bytes_to_hex(state_to_bytes(state)) << '\n';
        mix_columns(state);
        std::cout << "round[" << std::setw(2) << round << "].m_col  " << bytes_to_hex(state_to_bytes(state)) << '\n';
        std::cout << "round[" << std::setw(2) << round << "].k_sch  " << bytes_to_hex(state_to_bytes(round_keys[round])) << '\n';
        add_round_key(state, round_keys[round]);
        std::cout << "round[" << std::setw(2) << round + 1 << "].start  " << bytes_to_hex(state_to_bytes(state)) << '\n';
    }

    // Final round (14)
    sub_bytes(state);
    std::cout << "round[14].s_box  " << bytes_to_hex(state_to_bytes(state)) << '\n';
    shift_rows(state);
    std::cout << "round[14].s_row  " << bytes_to_hex(state_to_bytes(state)) << '\n';
    std::cout << "round[14].k_sch  " << bytes_to_hex(state_to_bytes(round_keys[14])) << '\n';
    add_round_key(state, round_keys[14]);
    std::cout << "round[14].output " << bytes_to_hex(state_to_bytes(state)) << '\n';

    return state_to_bytes(state);
}

void test_aes() {
    // Test with provided example from FIPS 197 Appendix C.3
    Key256 key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    Block plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    Block expected_ciphertext = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

    std::cout << "PLAINTEXT: " << bytes_to_hex(plaintext) << "\n\n";
    std::cout << "KEY: " << key_to_hex(key) << "\n\n";
    Block ciphertext = cipher_with_output(plaintext, key);

    if (ciphertext == expected_ciphertext) {
        std::cout << "\nCiphertext matches expected: " << bytes_to_hex(ciphertext) << '\n';
    } else {
        std::cout << "\nEncryption failed: " << bytes_to_hex(ciphertext)
                  << " != " << bytes_to_hex(expected_ciphertext) << '\n';
    }
}

int main() {
    test_aes();
    return 0;
}
