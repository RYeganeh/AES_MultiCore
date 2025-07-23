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

// Kernel with shared memory
__global__ void aes_encrypt_kernel(const uint8_t* plaintexts, uint8_t* ciphertexts, int num_blocks, int blocks_per_thread) {
    extern __shared__ uint8_t shared_memory[];
    uint8_t* shared_s_box = shared_memory;
    uint8_t* shared_round_keys = shared_s_box + 256;
    uint8_t (*shared_state)[4][4] = (uint8_t (*)[4][4])(shared_round_keys + 176);

    if (threadIdx.x == 0) {
        for (int i = 0; i < 256; ++i)
            shared_s_box[i] = d_s_box[i];
        for (int i = 0; i < 176; ++i)
            shared_round_keys[i] = d_round_keys[i];
    }
    __syncthreads();

    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    for (int b = 0; b < blocks_per_thread && (idx * blocks_per_thread + b) < num_blocks; ++b) {
        int block_idx = idx * blocks_per_thread + b;
        bytes_to_state_device(&plaintexts[block_idx * 16], shared_state[threadIdx.x]);

        add_round_key_device(shared_state[threadIdx.x], shared_round_keys);
        for (int round = 1; round < NUM_ROUNDS; ++round) {
            sub_bytes_device(shared_state[threadIdx.x]);
            shift_rows_device(shared_state[threadIdx.x]);
            mix_columns_device(shared_state[threadIdx.x]);
            add_round_key_device(shared_state[threadIdx.x], shared_round_keys + round * 16);
        }
        sub_bytes_device(shared_state[threadIdx.x]);
        shift_rows_device(shared_state[threadIdx.x]);
        add_round_key_device(shared_state[threadIdx.x], shared_round_keys + NUM_ROUNDS * 16);

        state_to_bytes_device(shared_state[threadIdx.x], &ciphertexts[block_idx * 16]);
    }
}

// Kernel without shared memory
__global__ void aes_encrypt_kernel_no_shared(const uint8_t* plaintexts, uint8_t* ciphertexts, int num_blocks, int blocks_per_thread) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

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
        for (size_t c = 0; c < 4; ++
