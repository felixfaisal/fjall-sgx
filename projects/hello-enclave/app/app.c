/*
 * app.c — Untrusted host application
 *
 * This code runs OUTSIDE the enclave, in normal user space.
 * It is responsible for:
 *   1. Creating/loading the enclave
 *   2. Making ECALLs into the enclave
 *   3. Handling OCALLs from the enclave (I/O, filesystem, etc.)
 *   4. Destroying the enclave on exit
 *
 * TRUST MODEL:
 * - This code is UNTRUSTED — the OS, hypervisor, and even this app
 *   could be compromised. The enclave protects its data regardless.
 * - Data returned FROM the enclave via ECALL out-params is trusted.
 * - Data passed TO the enclave via ECALLs is validated inside the enclave.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "sgx_urts.h"      /* SGX untrusted runtime */
#include "enclave_u.h"      /* Generated ECALL/OCALL proxies (untrusted side) */

#define ENCLAVE_FILE "enclave.signed.so"

/* ============================================================
 * OCALL implementations
 * These are called BY the enclave when it needs untrusted services.
 * ============================================================ */

/* ocall_print: The enclave calls this to print messages */
void ocall_print(const char *str)
{
    printf("%s\n", str);
}

/* ocall_read_file: The enclave calls this to read files */
sgx_status_t ocall_read_file(const char *filename, uint8_t *buf, size_t buf_len, size_t *bytes_read)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        *bytes_read = 0;
        return SGX_ERROR_UNEXPECTED;
    }
    *bytes_read = fread(buf, 1, buf_len, f);
    fclose(f);
    return SGX_SUCCESS;
}

/* ocall_write_file: The enclave calls this to write files */
sgx_status_t ocall_write_file(const char *filename, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(filename, "wb");
    if (!f) return SGX_ERROR_UNEXPECTED;
    fwrite(buf, 1, len, f);
    fclose(f);
    return SGX_SUCCESS;
}

/* ============================================================
 * Helper: print SGX error codes
 * ============================================================ */
void print_sgx_error(const char *context, sgx_status_t ret)
{
    switch(ret) {
        case SGX_SUCCESS: break;
        case SGX_ERROR_INVALID_ENCLAVE:
            printf("[Error] %s: Invalid enclave image\n", context); break;
        case SGX_ERROR_OUT_OF_MEMORY:
            printf("[Error] %s: Out of memory\n", context); break;
        case SGX_ERROR_ENCLAVE_LOST:
            printf("[Error] %s: Enclave lost (power transition)\n", context); break;
        default:
            printf("[Error] %s: SGX error code 0x%04x\n", context, ret); break;
    }
}

/* ============================================================
 * Main — Orchestrates the enclave lifecycle
 * ============================================================ */
int main(int argc, char *argv[])
{
    sgx_enclave_id_t eid = 0;  /* Enclave ID, assigned by SGX runtime */
    sgx_status_t ret;
    sgx_status_t ecall_ret;
    int updated = 0;

    printf("=== SGX Simulation Demo ===\n\n");

    /* ---- Step 1: Create the enclave ---- */
    printf("[Host] Creating enclave from '%s'...\n", ENCLAVE_FILE);

    ret = sgx_create_enclave(
        ENCLAVE_FILE,   /* Path to signed enclave binary */
        SGX_DEBUG_FLAG,  /* Debug flag (1 = allow debugging) */
        NULL,            /* Launch token (deprecated, pass NULL) */
        &updated,        /* Whether launch token was updated */
        &eid,            /* Output: enclave ID */
        NULL             /* Misc attributes (optional) */
    );

    if (ret != SGX_SUCCESS) {
        print_sgx_error("sgx_create_enclave", ret);
        return 1;
    }
    printf("[Host] Enclave created successfully (eid=%lu)\n\n", eid);

    /* ---- Step 2: ECALL — Hello from enclave ---- */
    printf("[Host] --- Test 1: Simple ECALL ---\n");
    int result = 0;
    ret = ecall_hello(eid, &ecall_ret, &result);
    if (ret != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
        print_sgx_error("ecall_hello", ret != SGX_SUCCESS ? ret : ecall_ret);
        return 1;
    }
    printf("[Host] Enclave returned: %d\n\n", result);

    /* ---- Step 3: ECALL — Process a buffer ---- */
    printf("[Host] --- Test 2: Buffer Processing ---\n");
    const char *message = "Hello, SGX World!";
    size_t msg_len = strlen(message);
    uint8_t *encrypted = (uint8_t *)malloc(msg_len);
    uint8_t *decrypted = (uint8_t *)malloc(msg_len);

    printf("[Host] Original:  '%s'\n", message);

    /* Encrypt (XOR with 0xAA inside enclave) */
    ret = ecall_process_buffer(eid, &ecall_ret,
        (const uint8_t *)message, msg_len, encrypted);

    printf("[Host] Encrypted: ");
    for (size_t i = 0; i < msg_len; i++) printf("%02x ", encrypted[i]);
    printf("\n");

    /* Decrypt (XOR again) */
    ret = ecall_process_buffer(eid, &ecall_ret,
        encrypted, msg_len, decrypted);

    printf("[Host] Decrypted: '%.*s'\n\n", (int)msg_len, decrypted);

    free(encrypted);
    free(decrypted);

    /* ---- Step 4: ECALL — Seal and Unseal data ---- */
    printf("[Host] --- Test 3: Data Sealing ---\n");
    const char *secret = "My secret database encryption key!";
    size_t secret_len = strlen(secret) + 1;  /* Include null terminator */

    /* Allocate generous buffer for sealed data (it's larger due to metadata) */
    size_t sealed_buf_len = secret_len + 1024;
    uint8_t *sealed_buf = (uint8_t *)malloc(sealed_buf_len);
    size_t actual_sealed_len = 0;

    printf("[Host] Sealing: '%s'\n", secret);

    ret = ecall_seal_data(eid, &ecall_ret,
        (const uint8_t *)secret, secret_len,
        sealed_buf, sealed_buf_len, &actual_sealed_len);

    if (ret != SGX_SUCCESS || ecall_ret != SGX_SUCCESS) {
        print_sgx_error("ecall_seal_data", ret != SGX_SUCCESS ? ret : ecall_ret);
    } else {
        printf("[Host] Sealed data size: %zu bytes (vs %zu plaintext)\n",
               actual_sealed_len, secret_len);

        /* Now unseal it */
        uint8_t *unsealed_buf = (uint8_t *)malloc(secret_len);
        size_t actual_unsealed_len = 0;

        ret = ecall_unseal_data(eid, &ecall_ret,
            sealed_buf, actual_sealed_len,
            unsealed_buf, secret_len, &actual_unsealed_len);

        if (ret == SGX_SUCCESS && ecall_ret == SGX_SUCCESS) {
            printf("[Host] Unsealed: '%s'\n", (char *)unsealed_buf);
            printf("[Host] Seal/Unseal round-trip successful!\n");
        } else {
            print_sgx_error("ecall_unseal_data", ret != SGX_SUCCESS ? ret : ecall_ret);
        }

        free(unsealed_buf);
    }

    free(sealed_buf);

    /* ---- Step 5: Destroy the enclave ---- */
    printf("\n[Host] Destroying enclave...\n");
    sgx_destroy_enclave(eid);
    printf("[Host] Done.\n");

    return 0;
}
