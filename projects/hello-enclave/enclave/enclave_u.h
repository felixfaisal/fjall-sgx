#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_READ_FILE_DEFINED__
#define OCALL_READ_FILE_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read_file, (const char* filename, uint8_t* buf, size_t buf_len, size_t* bytes_read));
#endif
#ifndef OCALL_WRITE_FILE_DEFINED__
#define OCALL_WRITE_FILE_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_file, (const char* filename, const uint8_t* buf, size_t len));
#endif

sgx_status_t ecall_hello(sgx_enclave_id_t eid, sgx_status_t* retval, int* result);
sgx_status_t ecall_process_buffer(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* input, size_t len, uint8_t* output);
sgx_status_t ecall_seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t len, uint8_t* sealed_data, size_t sealed_len, size_t* actual_sealed_len);
sgx_status_t ecall_unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_data, size_t sealed_len, uint8_t* plaintext, size_t plain_len, size_t* actual_plain_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
