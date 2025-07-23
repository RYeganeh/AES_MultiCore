
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <cuda_runtime.h>

static int enable_logging = 0;

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

static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

#define BLOCK_SIZE 16
#define NUM_ROUNDS 10
#define MAX_ROUNDS (NUM_ROUNDS + 1)
#define MAX_BLOCKS 10000
#define MAX_OUTPUTS 50
#define MAX_LINE 256
#define NUM_STREAMS 16

struct AES128_Context {
    uint8_t round_keys[MAX_ROUNDS][4][4];
    char round_outputs[MAX_OUTPUTS][MAX_LINE];
    int output_count;
};

__constant__ uint8_t d_s_box[256];
__constant__ uint8_t d_round_keys[176];

void bytes_to_state(const uint8_t *block, uint8_t state[4][4]);
void state_to_bytes(const uint8_t state[4][4], uint8_t *block);
void sub_bytes(uint8_t state[4][4]);
void shift_rows(uint8_t state[4][4]);
uint8_t xtime(uint8_t a);
void mix_columns(uint8_t state[4][4]);
void add_round_key(uint8_t state[4][4], const uint8_t round_key[4][4]);
void key_expansion(const uint8_t key[BLOCK_SIZE], uint8_t round_keys[MAX_ROUNDS][4][4]);
void key_expansion_to_flat(const uint8_t* key, uint8_t* round_keys_flat);
void record_state(struct AES128_Context *ctx, const char *index, const char *label, const uint8_t *block);
void bytes_to_hex(const uint8_t *bytes, char *hex);
void aes_init(struct AES128_Context *ctx, const uint8_t key[BLOCK_SIZE]);
void aes_encrypt_with_output(struct AES128_Context *ctx, const uint8_t *plaintext, uint8_t *ciphertext, const char *index);
int hex_to_key(const char *hex, uint8_t *key);
int read_keys(const char *filename, uint8_t keys[][BLOCK_SIZE], size_t *count);
void test_file_encryption(void);

__device__ void bytes_to_state_device(const uint8_t *block, uint8_t state[4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = block[r + 4 * c];
}

__device__ void state_to_bytes_device(const uint8_t state[4][4], uint8_t *block) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            block[r + 4 * c] = state[r][c];
}

__device__ uint8_t xtime_device(uint8_t a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

__device__ void sub_bytes_device(uint8_t state[4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = d_s_box[state[r][c]];
}

__device__ void shift_rows_device(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int r = 1; r < 4; ++r) {
        for (int c = 0; c < 4; ++c)
            temp[c] = state[r][c];
        for (int c = 0; c < 4; ++c)
            state[r][c] = temp[(c + r) % 4];
    }
}

__device__ void mix_columns_device(uint8_t state[4][4]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t col[4] = {state[0][c], state[1][c], state[2][c], state[3][c]};
        state[0][c] = xtime_device(col[0]) ^ (xtime_device(col[1]) ^ col[1]) ^ col[2] ^ col[3];
        state[1][c] = col[0] ^ xtime_device(col[1]) ^ (xtime_device(col[2]) ^ col[2]) ^ col[3];
        state[2][c] = col[0] ^ col[1] ^ xtime_device(col[2]) ^ (xtime_device(col[3]) ^ col[3]);
        state[3][c] = (xtime_device(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ xtime_device(col[3]);
    }
}

__device__ void add_round_key_device(uint8_t state[4][4], const uint8_t *round_key) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] ^= round_key[r + 4 * c];
}

__global__ void aes_encrypt_kernel(const uint8_t* plaintexts, uint8_t* ciphertexts, int num_blocks) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    const int blocks_per_thread = 4;

    for (int b = 0; b < blocks_per_thread && (idx * blocks_per_thread + b) < num_blocks; ++b) {
        int block_idx = idx * blocks_per_thread + b;
        uint8_t state[4][4];
        bytes_to_state_device(&plaintexts[block_idx * 16], state);

        add_round_key_device(state, d_round_keys);
        for (int round = 1; round < NUM_ROUNDS; ++round) {
            sub_bytes_device(state);
            shift_rows_device(state);
            mix_columns_device(state);
            add_round_key_device(state, d_round_keys + round * 16);
        }
        sub_bytes_device(state);
        shift_rows_device(state);
        add_round_key_device(state, d_round_keys + NUM_ROUNDS * 16);

        state_to_bytes_device(state, &ciphertexts[block_idx * 16]);
    }
}

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

void key_expansion_to_flat(const uint8_t* key, uint8_t* round_keys_flat) {
    uint8_t round_keys[MAX_ROUNDS][4][4];
    key_expansion(key, round_keys);
    for (size_t i = 0; i < MAX_ROUNDS; ++i)
        for (size_t r = 0; r < 4; ++r)
            for (size_t c = 0; c < 4; ++c)
                round_keys_flat[i * 16 + r + 4 * c] = round_keys[i][r][c];
}

void record_state(struct AES128_Context *ctx, const char *index, const char *label, const uint8_t *block) {
    if (!enable_logging || ctx->output_count >= MAX_OUTPUTS) return;
    char hex[BLOCK_SIZE * 2 + 1];
    bytes_to_hex(block, hex);
    // snprintf(ctx->round_outputs[ctx->output_count++], MAX_LINE,
            //  "input%s | %s %s", index, label, hex);
}

void bytes_to_hex(const uint8_t *bytes, char *hex) {
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        // snprintf(hex + i * 2, 3, "%02x", bytes[i]);
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
    // snprintf(label, sizeof(label), "round[ 1].start");
    record_state(ctx, index, label, (uint8_t *)state);

    for (size_t round = 1; round < NUM_ROUNDS; ++round) {
        sub_bytes(state);
        // snprintf(label, sizeof(label), "round[%2zu].s_box", round);
        record_state(ctx, index, label, (uint8_t *)state);
        shift_rows(state);
        // snprintf(label, sizeof(label), "round[%2zu].s_row", round);
        record_state(ctx, index, label, (uint8_t *)state);
        mix_columns(state);
        // snprintf(label, sizeof(label), "round[%2zu].m_col", round);
        record_state(ctx, index, label, (uint8_t *)state);
        // snprintf(label, sizeof(label), "round[%2zu].k_sch", round);
        record_state(ctx, index, label, (uint8_t *)ctx->round_keys[round]);
        add_round_key(state, ctx->round_keys[round]);
        // snprintf(label, sizeof(label), "round[%2zu].start", round + 1);
        record_state(ctx, index, label, (uint8_t *)state);
    }

    sub_bytes(state);
    // snprintf(label, sizeof(label), "round[10].s_box");
    record_state(ctx, index, label, (uint8_t *)state);
    shift_rows(state);
    // snprintf(label, sizeof(label), "round[10].s_row");
    record_state(ctx, index, label, (uint8_t *)state);
    // snprintf(label, sizeof(label), "round[10].k_sch");
    record_state(ctx, index, label, (uint8_t *)ctx->round_keys[10]);
    add_round_key(state, ctx->round_keys[10]);
    // snprintf(label, sizeof(label), "round[10].output");
    record_state(ctx, index, label, (uint8_t *)state);

    state_to_bytes(state, ciphertext);
    
}

int hex_to_key(const char *hex, uint8_t *key) {
    if (strlen(hex) != BLOCK_SIZE * 2) {
        fprintf(stderr, "Error: Hex string length is %zu, expected %d\n", strlen(hex), BLOCK_SIZE * 2);
        return 0;
    }
    for (size_t i = 0; i < BLOCK_SIZE * 2; ++i) {
        if (!isxdigit((unsigned char)hex[i])) {
            fprintf(stderr, "Error: Invalid hex character at position %zu\n", i);
            return 0;
        }
    }
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        char byte_str[3] = {hex[2*i], hex[2*i+1], '\0'};
        key[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return 1;
}

int read_keys(const char *filename, uint8_t keys[][BLOCK_SIZE], size_t *count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return 0;
    }
    char line[MAX_LINE];
    *count = 0;
    size_t line_num = 0;
    while (fgets(line, MAX_LINE, file) && *count < MAX_BLOCKS) {
        line_num++;
        size_t len = strlen(line), j = 0;
        for (size_t i = 0; i < len; ++i)
            if (!isspace((unsigned char)line[i])) line[j++] = line[i];
        line[j] = '\0';
        if (j == 0) continue;
        //printf("Reading line %zu: %s\n", line_num, line);
        if (!hex_to_key(line, keys[*count])) {
            fprintf(stderr, "Error: Failed to parse hex string at line %zu\n", line_num);
            fclose(file);
            return 0;
        }
        (*count)++;
    }
    fclose(file);
    printf("Successfully read %zu keys from %s\n", *count, filename);
    return 1;
}

void cleanup_resources(cudaStream_t *streams, uint8_t *d_plaintexts[], uint8_t *d_ciphertexts[],
                      uint8_t (*plaintexts)[BLOCK_SIZE], uint8_t (*expected_ciphertexts)[BLOCK_SIZE],
                      uint8_t (*ciphertexts)[BLOCK_SIZE], struct AES128_Context *aes_ctx) {
    for (int i = 0; i < NUM_STREAMS; ++i) {
        if (d_plaintexts[i]) cudaFree(d_plaintexts[i]);
        if (d_ciphertexts[i]) cudaFree(d_ciphertexts[i]);
        if (streams[i]) cudaStreamDestroy(streams[i]);
    }
    free(plaintexts);
    free(expected_ciphertexts);
    free(ciphertexts);
    free(aes_ctx);
}


void test_file_encryption(void) {
    const int num_iterations = 5;
    float times[5] = {0};
    float total_time = 0;
    bool success = true;

    cudaStream_t streams[NUM_STREAMS];
    cudaEvent_t stream_done[NUM_STREAMS];
    uint8_t *d_all_plaintexts = NULL, *d_all_ciphertexts = NULL;
    uint8_t key[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    size_t plaintext_count = 0;
    size_t ciphertext_count = 0;
    cudaError_t err;

    uint8_t (*plaintexts)[BLOCK_SIZE];
    uint8_t (*expected_ciphertexts)[BLOCK_SIZE];
    uint8_t (*ciphertexts)[BLOCK_SIZE];
    cudaHostAlloc(&plaintexts, MAX_BLOCKS * BLOCK_SIZE * sizeof(uint8_t), cudaHostAllocDefault);
    cudaHostAlloc(&expected_ciphertexts, MAX_BLOCKS * BLOCK_SIZE * sizeof(uint8_t), cudaHostAllocDefault);
    cudaHostAlloc(&ciphertexts, MAX_BLOCKS * BLOCK_SIZE * sizeof(uint8_t), cudaHostAllocDefault);
    struct AES128_Context *aes_ctx = (struct AES128_Context *)malloc(MAX_BLOCKS * sizeof(struct AES128_Context));

    if (!plaintexts || !expected_ciphertexts || !ciphertexts || !aes_ctx) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }

    printf("Reading plaintexts from plaintext_10000_blocks.txt\n");
    if (!read_keys("plaintext_10000_blocks.txt", plaintexts, &plaintext_count)) {
        fprintf(stderr, "Error: Failed to read plaintexts\n");
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }
    printf("Reading ciphertexts from ciphertexts_10000_blocks.txt\n");
    if (!read_keys("ciphertexts_10000_blocks.txt", expected_ciphertexts, &ciphertext_count)) {
        fprintf(stderr, "Error: Failed to read ciphertexts\n");
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }
    if (plaintext_count == 0 || plaintext_count != ciphertext_count) {
        fprintf(stderr, "Error: Mismatch in number of plaintexts (%zu) and ciphertexts (%zu)\n",
                plaintext_count, ciphertext_count);
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }

    err = cudaSetDevice(0);
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA Error: Failed to set device: %s\n", cudaGetErrorString(err));
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }

    uint8_t round_keys_flat[176];
    key_expansion_to_flat(key, round_keys_flat);
    err = cudaMemcpyToSymbol(d_s_box, s_box, 256 * sizeof(uint8_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA Error: Failed to copy S-box: %s\n", cudaGetErrorString(err));
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }
    err = cudaMemcpyToSymbol(d_round_keys, round_keys_flat, 176 * sizeof(uint8_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA Error: Failed to copy round keys: %s\n", cudaGetErrorString(err));
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }

    err = cudaMalloc(&d_all_plaintexts, plaintext_count * BLOCK_SIZE * sizeof(uint8_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA Error: Failed to allocate d_all_plaintexts: %s\n", cudaGetErrorString(err));
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }
    err = cudaMalloc(&d_all_ciphertexts, plaintext_count * BLOCK_SIZE * sizeof(uint8_t));
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA Error: Failed to allocate d_all_ciphertexts: %s\n", cudaGetErrorString(err));
        cudaFree(d_all_plaintexts);
        cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
        return;
    }

    for (int i = 0; i < NUM_STREAMS; ++i) {
        err = cudaStreamCreate(&streams[i]);
        if (err != cudaSuccess) {
            fprintf(stderr, "CUDA Error: Failed to create stream %d: %s\n", i, cudaGetErrorString(err));
            cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
            return;
        }
        err = cudaEventCreate(&stream_done[i]);
        if (err != cudaSuccess) {
            fprintf(stderr, "CUDA Error: Failed to create event %d: %s\n", i, cudaGetErrorString(err));
            cleanup_resources(streams, NULL, NULL, plaintexts, expected_ciphertexts, ciphertexts, aes_ctx);
            return;
        }
    }

    size_t base_blocks = plaintext_count / NUM_STREAMS;
 size_t extra_blocks = plaintext_count % NUM_STREAMS;
    size_t stream_blocks[NUM_STREAMS];
    for (int i = 0; i < NUM_STREAMS; ++i) {
        stream_blocks[i] = base_blocks + (i < extra_blocks ? 1 : 0);
    }

    enable_logging = 0;
    for (int iter = 0; iter < num_iterations && success; ++iter) {
        cudaEvent_t start, stop;
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start, 0);

        size_t offset = 0;
        for (int i = 0; i < NUM_STREAMS && success; ++i) {
            if (stream_blocks[i] == 0) continue;

            if (offset + stream_blocks[i] * BLOCK_SIZE > plaintext_count * BLOCK_SIZE) {
                fprintf(stderr, "Error: Invalid offset for stream %d\n", i);
                success = false;
                break;
            }

            err = cudaMemcpyAsync(d_all_plaintexts + offset, (uint8_t *)plaintexts + offset,
                                 stream_blocks[i] * BLOCK_SIZE * sizeof(uint8_t),
                                 cudaMemcpyHostToDevice, streams[i]);
            if (err != cudaSuccess) {
                fprintf(stderr, "CUDA Error: Failed to copy plaintexts for stream %d: %s\n", i, cudaGetErrorString(err));
                success = false;
                break;
            }

            int threads_per_block = 256;
            int blocks = (stream_blocks[i] + threads_per_block - 1) / threads_per_block;
            aes_encrypt_kernel<<<blocks, threads_per_block, 0, streams[i]>>>(d_all_plaintexts + offset, d_all_ciphertexts + offset, stream_blocks[i]);
            err = cudaGetLastError();
            if (err != cudaSuccess) {
                fprintf(stderr, "CUDA Kernel Error in stream %d: %s\n", i, cudaGetErrorString(err));
                success = false;
                break;
            }

            err = cudaMemcpyAsync((uint8_t *)ciphertexts + offset, d_all_ciphertexts + offset,
                                 stream_blocks[i] * BLOCK_SIZE * sizeof(uint8_t),
                                 cudaMemcpyDeviceToHost, streams[i]);
            if (err != cudaSuccess) {
                fprintf(stderr, "CUDA Error: Failed to copy ciphertexts for stream %d: %s\n", i, cudaGetErrorString(err));
                success = false;
                break;
            }

            cudaEventRecord(stream_done[i], streams[i]);
            offset += stream_blocks[i] * BLOCK_SIZE;
        }

        for (int i = 0; i < NUM_STREAMS && success; ++i) {
            if (stream_blocks[i] > 0) {
                err = cudaEventSynchronize(stream_done[i]);
                if (err != cudaSuccess) {
                    fprintf(stderr, "CUDA Error: Failed to synchronize stream %d: %s\n", i, cudaGetErrorString(err));
                    success = false;
                }
            }
        }

        if (success) {
            cudaEventRecord(stop, 0);
            cudaEventSynchronize(stop);
            err = cudaEventElapsedTime(&times[iter], start, stop);
            if (err != cudaSuccess) {
                fprintf(stderr, "CUDA Error: Failed to measure elapsed time: %s\n", cudaGetErrorString(err));
                success = false;
            } else {
                total_time += times[iter];
            }
        }
        cudaEventDestroy(start);
        cudaEventDestroy(stop);
    }

    if (success) {
        for (int i = 0; i < num_iterations; ++i)
            printf("Iteration %d: %.3f ms\n", i + 1, times[i]);
        printf("Average: %.3f ms\n", total_time / num_iterations);
    }

    for (int i = 0; i < NUM_STREAMS; ++i) {
        if (stream_blocks[i] > 0) {
            cudaStreamDestroy(streams[i]);
            cudaEventDestroy(stream_done[i]);
        }
    }
    cudaFree(d_all_plaintexts);
    cudaFree(d_all_ciphertexts);
    cudaFreeHost(plaintexts);
    cudaFreeHost(expected_ciphertexts);
    cudaFreeHost(ciphertexts);
    free(aes_ctx);
}

int main(void) {
    test_file_encryption();
    return 0;
}
