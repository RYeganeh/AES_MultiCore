#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>


static int enable_logging = 0;

// S-box from FIPS 197 Figure 7
static const uint8_t s_box[256] = {
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
static const uint8_t rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

#define BLOCK_SIZE 16
#define NUM_ROUNDS 10
#define MAX_ROUNDS (NUM_ROUNDS + 1)
#define MAX_BLOCKS 10000
#define MAX_OUTPUTS 50
#define MAX_LINE 256

// AES context structure without typedef
struct AES128_Context {
    uint8_t round_keys[MAX_ROUNDS][4][4];
    char round_outputs[MAX_OUTPUTS][MAX_LINE];
    int output_count;
};

// Function prototypes
void bytes_to_state(const uint8_t *block, uint8_t state[4][4]);
void state_to_bytes(const uint8_t state[4][4], uint8_t *block);
void sub_bytes(uint8_t state[4][4]);
void shift_rows(uint8_t state[4][4]);
uint8_t xtime(uint8_t a);
void mix_columns(uint8_t state[4][4]);
void add_round_key(uint8_t state[4][4], const uint8_t round_key[4][4]);
void key_expansion(const uint8_t key[BLOCK_SIZE], uint8_t round_keys[MAX_ROUNDS][4][4]);
void record_state(struct AES128_Context *ctx, const char *index, const char *label, const uint8_t *block);
void bytes_to_hex(const uint8_t *bytes, char *hex);
void aes_init(struct AES128_Context *ctx, const uint8_t key[BLOCK_SIZE]);
void aes_encrypt_with_output(struct AES128_Context *ctx, const uint8_t *plaintext, uint8_t *ciphertext, const char *index);
int hex_to_key(const char *hex, uint8_t *key);
int read_keys(const char *filename, uint8_t keys[][BLOCK_SIZE], size_t *count);
void test_file_encryption(void);

void bytes_to_state(const uint8_t *block, uint8_t state[4][4]) {
    for (size_t r = 0; r < 4; ++r)
        for (size_t c = 0; c < 4; ++c)
            state[r][c] = block[r + 4 * c];
}

void state_to_bytes(const uint8_t state[4][4], uint8_t *block) {
    for (size_t r = 0; r < 4; ++r)
        for (size_t c = 0; c < 4; ++c)
            block[r + 4 * c] = state[r][c];
}

void sub_bytes(uint8_t state[4][4]) {
    for (size_t r = 0; r < 4; ++r)
        for (size_t c = 0; c < 4; ++c)
            state[r][c] = s_box[state[r][c]];
}

void shift_rows(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (size_t r = 1; r < 4; ++r) {
        for (size_t c = 0; c < 4; ++c)
            temp[c] = state[r][c];
        for (size_t c = 0; c < 4; ++c)
            state[r][c] = temp[(c + r) % 4];
    }
}

uint8_t xtime(uint8_t a) {
    return (a & 0x80) ? (uint8_t)((a << 1) ^ 0x1b) : (uint8_t)(a << 1);
}

void mix_columns(uint8_t state[4][4]) {
    for (size_t c = 0; c < 4; ++c) {
        uint8_t col[4] = {state[0][c], state[1][c], state[2][c], state[3][c]};
        state[0][c] = xtime(col[0]) ^ (xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
        state[1][c] = col[0] ^ xtime(col[1]) ^ (xtime(col[2]) ^ col[2]) ^ col[3];
        state[2][c] = col[0] ^ col[1] ^ xtime(col[2]) ^ (xtime(col[3]) ^ col[3]);
        state[3][c] = (xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime(col[3]);
    }
}

void add_round_key(uint8_t state[4][4], const uint8_t round_key[4][4]) {
    for (size_t r = 0; r < 4; ++r)
        for (size_t c = 0; c < 4; ++c)
            state[r][c] ^= round_key[r][c];
}

void key_expansion(const uint8_t key[BLOCK_SIZE], uint8_t round_keys[MAX_ROUNDS][4][4]) {
    uint8_t w[4 * MAX_ROUNDS * 4];
    memcpy(w, key, BLOCK_SIZE);
    size_t Nk = 4;

    for (size_t i = Nk; i < 4 * MAX_ROUNDS; ++i) {
        uint8_t temp[4] = {w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2], w[(i - 1) * 4 + 3]};
        if (i % Nk == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            for (size_t j = 0; j < 4; ++j)
                temp[j] = s_box[temp[j]];
            temp[0] ^= rcon[i / Nk - 1];
        }
        for (size_t j = 0; j < 4; ++j)
            w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
    }

    for (size_t i = 0; i < MAX_ROUNDS; ++i)
        for (size_t r = 0; r < 4; ++r)
            for (size_t c = 0; c < 4; ++c)
                round_keys[i][r][c] = w[i * BLOCK_SIZE + r + 4 * c];
}

void record_state(struct AES128_Context *ctx, const char *index, const char *label, const uint8_t *block) {
    if (!enable_logging || ctx->output_count >= MAX_OUTPUTS) return;
    char hex[BLOCK_SIZE * 2 + 1];
    bytes_to_hex(block, hex);
    snprintf(ctx->round_outputs[ctx->output_count++], MAX_LINE,
             "input%s | %s %s", index, label, hex);
}

void bytes_to_hex(const uint8_t *bytes, char *hex) {
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    hex[BLOCK_SIZE * 2] = '\0';
}

void aes_init(struct AES128_Context *ctx, const uint8_t key[BLOCK_SIZE]) {
    key_expansion(key, ctx->round_keys);
    if (enable_logging) {
        strcpy(ctx->round_outputs[0], "CIPHER (ENCRYPT):\n");
        ctx->output_count = 1;
    } else {
        ctx->output_count = 0;
    }
}

void aes_encrypt_with_output(struct AES128_Context *ctx, const uint8_t *plaintext, uint8_t *ciphertext, const char *index) {
    uint8_t state[4][4];
    char label[32];

    bytes_to_state(plaintext, state);
    record_state(ctx, index, "round[ 0].input", plaintext);
    record_state(ctx, index, "round[ 0].k_sch", (uint8_t *)ctx->round_keys[0]);
    add_round_key(state, ctx->round_keys[0]);
    snprintf(label, sizeof(label), "round[ 1].start");
    record_state(ctx, index, label, (uint8_t *)state);

    for (size_t round = 1; round < NUM_ROUNDS; ++round) {
        sub_bytes(state);
        snprintf(label, sizeof(label), "round[%2zu].s_box", round);
        record_state(ctx, index, label, (uint8_t *)state);
        shift_rows(state);
        snprintf(label, sizeof(label), "round[%2zu].s_row", round);
        record_state(ctx, index, label, (uint8_t *)state);
        mix_columns(state);
        snprintf(label, sizeof(label), "round[%2zu].m_col", round);
        record_state(ctx, index, label, (uint8_t *)state);
        snprintf(label, sizeof(label), "round[%2zu].k_sch", round);
        record_state(ctx, index, label, (uint8_t *)ctx->round_keys[round]);
        add_round_key(state, ctx->round_keys[round]);
        snprintf(label, sizeof(label), "round[%2zu].start", round + 1);
        record_state(ctx, index, label, (uint8_t *)state);
    }

    sub_bytes(state);
    snprintf(label, sizeof(label), "round[10].s_box"); record_state(ctx, index, label, (uint8_t *)state);
    shift_rows(state);
    snprintf(label, sizeof(label), "round[10].s_row"); record_state(ctx, index, label, (uint8_t *)state);
    snprintf(label, sizeof(label), "round[10].k_sch"); record_state(ctx, index, label, (uint8_t *)ctx->round_keys[10]);
    add_round_key(state, ctx->round_keys[10]);
    snprintf(label, sizeof(label), "round[10].output"); record_state(ctx, index, label, (uint8_t *)state);

    state_to_bytes(state, ciphertext);
}

int hex_to_key(const char *hex, uint8_t *key) {
    if (strlen(hex) != BLOCK_SIZE * 2) return 0;
    for (size_t i = 0; i < BLOCK_SIZE * 2; ++i)
        if (!isxdigit((unsigned char)hex[i])) return 0;
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        char byte_str[3] = {hex[2*i], hex[2*i+1], '\0'};
        key[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return 1;
}

int read_keys(const char *filename, uint8_t keys[][BLOCK_SIZE], size_t *count) {
    FILE *file = fopen(filename, "r");
    if (!file) return 0;
    char line[MAX_LINE];
    *count = 0;
    while (fgets(line, MAX_LINE, file) && *count < MAX_BLOCKS) {
        size_t len = strlen(line), j = 0;
        for (size_t i = 0; i < len; ++i)
            if (!isspace((unsigned char)line[i])) line[j++] = line[i];
        line[j] = '\0';
        if (j == 0) continue;
        if (!hex_to_key(line, keys[*count])) { fclose(file); return 0; }
        (*count)++;
    }
    fclose(file);
    return 1;
}

void test_file_encryption(void) {
    uint8_t key[BLOCK_SIZE] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    char key_hex[BLOCK_SIZE*2+1]; bytes_to_hex(key, key_hex);

    uint8_t plaintexts[MAX_BLOCKS][BLOCK_SIZE];
    uint8_t expected_ciphertexts[MAX_BLOCKS][BLOCK_SIZE];
    uint8_t ciphertexts[MAX_BLOCKS][BLOCK_SIZE];
    struct AES128_Context aes_ctx[MAX_BLOCKS];
    size_t plaintext_count=0, ciphertext_count=0;

    if (!read_keys("plaintext_10000_blocks.txt", plaintexts, &plaintext_count)) return;
    if (!read_keys("ciphertexts_10000_blocks.txt", expected_ciphertexts, &ciphertext_count)) return;
    if (plaintext_count == 0 || plaintext_count != ciphertext_count) return;

    const int num_iterations = 5;
    double times[5], total_time=0;

    enable_logging = 0;
    for (int iter = 0; iter < num_iterations; ++iter) {
        clock_t start = clock();
        for (size_t i = 0; i < plaintext_count; ++i) {
            char idx[16]; snprintf(idx, sizeof(idx), "%zu", i);
            aes_init(&aes_ctx[i], key);
            aes_encrypt_with_output(&aes_ctx[i], plaintexts[i], ciphertexts[i], idx);
        }
        clock_t end = clock();
        times[iter] = (double)(end - start) * 1000.0 / CLOCKS_PER_SEC;
        total_time += times[iter];
    }

    for (size_t i = 0; i < plaintext_count; ++i) {
        printf("Input %zu\n", i+1);
        printf("PLAINTEXT: %s\n", key_hex /* reuse plaintext hex function */);
        
        printf("KEY: %s\n", key_hex);
        
        for (int j = 0; j < aes_ctx[i].output_count; ++j){
            printf("%s\n", aes_ctx[i].round_outputs[j]);
            
        }
        
        char ct_hex[BLOCK_SIZE*2+1]; bytes_to_hex(ciphertexts[i], ct_hex);
        printf("CIPHERTEXT: %s\n", ct_hex);
        
        int match = memcmp(ciphertexts[i], expected_ciphertexts[i], BLOCK_SIZE)==0;
        printf("Match: %s\n", match?"Yes":"No");
        
        printf("===============================================================\n");
        
    }

    for (int i = 0; i < num_iterations; ++i){
        printf("Iteration %d: %.3f ms\n", i+1, times[i]);
    }
    
    printf("Average: %.3f ms\n", total_time/num_iterations);
    

    enable_logging = 1;
    for (size_t i = 0; i < plaintext_count; ++i) {
        char idx[16]; snprintf(idx, sizeof(idx), "%zu", i);
        aes_init(&aes_ctx[i], key);
        aes_encrypt_with_output(&aes_ctx[i], plaintexts[i], ciphertexts[i], idx);
        // detailed logs could be printed here
    }
}

int main(void) {
    printf("Program started\n");
    test_file_encryption();
    return 0;
}
