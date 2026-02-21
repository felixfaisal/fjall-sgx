#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ecall_hello(int* result);
sgx_status_t ecall_process_buffer(const uint8_t* input, size_t len, uint8_t* output);
sgx_status_t ecall_seal_data(const uint8_t* plaintext, size_t len, uint8_t* sealed_data, size_t sealed_len, size_t* actual_sealed_len);
sgx_status_t ecall_unseal_data(const uint8_t* sealed_data, size_t sealed_len, uint8_t* plaintext, size_t plain_len, size_t* actual_plain_len);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_read_file(sgx_status_t* retval, const char* filename, uint8_t* buf, size_t buf_len, size_t* bytes_read);
sgx_status_t SGX_CDECL ocall_write_file(sgx_status_t* retval, const char* filename, const uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
