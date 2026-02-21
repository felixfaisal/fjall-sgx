#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_hello_t {
	sgx_status_t ms_retval;
	int* ms_result;
} ms_ecall_hello_t;

typedef struct ms_ecall_process_buffer_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_input;
	size_t ms_len;
	uint8_t* ms_output;
} ms_ecall_process_buffer_t;

typedef struct ms_ecall_seal_data_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_plaintext;
	size_t ms_len;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_len;
	size_t* ms_actual_sealed_len;
} ms_ecall_seal_data_t;

typedef struct ms_ecall_unseal_data_t {
	sgx_status_t ms_retval;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_len;
	uint8_t* ms_plaintext;
	size_t ms_plain_len;
	size_t* ms_actual_plain_len;
} ms_ecall_unseal_data_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_read_file_t {
	sgx_status_t ms_retval;
	const char* ms_filename;
	uint8_t* ms_buf;
	size_t ms_buf_len;
	size_t* ms_bytes_read;
} ms_ocall_read_file_t;

typedef struct ms_ocall_write_file_t {
	sgx_status_t ms_retval;
	const char* ms_filename;
	const uint8_t* ms_buf;
	size_t ms_len;
} ms_ocall_write_file_t;

static sgx_status_t SGX_CDECL enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_read_file(void* pms)
{
	ms_ocall_read_file_t* ms = SGX_CAST(ms_ocall_read_file_t*, pms);
	ms->ms_retval = ocall_read_file(ms->ms_filename, ms->ms_buf, ms->ms_buf_len, ms->ms_bytes_read);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_write_file(void* pms)
{
	ms_ocall_write_file_t* ms = SGX_CAST(ms_ocall_write_file_t*, pms);
	ms->ms_retval = ocall_write_file(ms->ms_filename, ms->ms_buf, ms->ms_len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_enclave = {
	3,
	{
		(void*)enclave_ocall_print,
		(void*)enclave_ocall_read_file,
		(void*)enclave_ocall_write_file,
	}
};
sgx_status_t ecall_hello(sgx_enclave_id_t eid, sgx_status_t* retval, int* result)
{
	sgx_status_t status;
	ms_ecall_hello_t ms;
	ms.ms_result = result;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_process_buffer(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* input, size_t len, uint8_t* output)
{
	sgx_status_t status;
	ms_ecall_process_buffer_t ms;
	ms.ms_input = input;
	ms.ms_len = len;
	ms.ms_output = output;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_seal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* plaintext, size_t len, uint8_t* sealed_data, size_t sealed_len, size_t* actual_sealed_len)
{
	sgx_status_t status;
	ms_ecall_seal_data_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_len = len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_len = sealed_len;
	ms.ms_actual_sealed_len = actual_sealed_len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_unseal_data(sgx_enclave_id_t eid, sgx_status_t* retval, const uint8_t* sealed_data, size_t sealed_len, uint8_t* plaintext, size_t plain_len, size_t* actual_plain_len)
{
	sgx_status_t status;
	ms_ecall_unseal_data_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_len = sealed_len;
	ms.ms_plaintext = plaintext;
	ms.ms_plain_len = plain_len;
	ms.ms_actual_plain_len = actual_plain_len;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

