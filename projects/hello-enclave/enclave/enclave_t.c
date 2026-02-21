#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_hello(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_hello_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_hello_t* ms = SGX_CAST(ms_ecall_hello_t*, pms);
	ms_ecall_hello_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_hello_t), ms, sizeof(ms_ecall_hello_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(int);
	int* _in_result = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (int*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	_in_retval = ecall_hello(_in_result);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_process_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_process_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_process_buffer_t* ms = SGX_CAST(ms_ecall_process_buffer_t*, pms);
	ms_ecall_process_buffer_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_process_buffer_t), ms, sizeof(ms_ecall_process_buffer_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_input = __in_ms.ms_input;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_input = _tmp_len;
	uint8_t* _in_input = NULL;
	uint8_t* _tmp_output = __in_ms.ms_output;
	size_t _len_output = _tmp_len;
	uint8_t* _in_output = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_input, _len_input);
	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_input != NULL && _len_input != 0) {
		if ( _len_input % sizeof(*_tmp_input) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_input = (uint8_t*)malloc(_len_input);
		if (_in_input == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input, _len_input, _tmp_input, _len_input)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_output != NULL && _len_output != 0) {
		if ( _len_output % sizeof(*_tmp_output) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_output = (uint8_t*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}
	_in_retval = ecall_process_buffer((const uint8_t*)_in_input, _tmp_len, _in_output);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_output) {
		if (memcpy_verw_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_input) free(_in_input);
	if (_in_output) free(_in_output);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_seal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_seal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_seal_data_t* ms = SGX_CAST(ms_ecall_seal_data_t*, pms);
	ms_ecall_seal_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_seal_data_t), ms, sizeof(ms_ecall_seal_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_plaintext = __in_ms.ms_plaintext;
	size_t _tmp_len = __in_ms.ms_len;
	size_t _len_plaintext = _tmp_len;
	uint8_t* _in_plaintext = NULL;
	uint8_t* _tmp_sealed_data = __in_ms.ms_sealed_data;
	size_t _tmp_sealed_len = __in_ms.ms_sealed_len;
	size_t _len_sealed_data = _tmp_sealed_len;
	uint8_t* _in_sealed_data = NULL;
	size_t* _tmp_actual_sealed_len = __in_ms.ms_actual_sealed_len;
	size_t _len_actual_sealed_len = sizeof(size_t);
	size_t* _in_actual_sealed_len = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_actual_sealed_len, _len_actual_sealed_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plaintext, _len_plaintext, _tmp_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_data = (uint8_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	if (_tmp_actual_sealed_len != NULL && _len_actual_sealed_len != 0) {
		if ( _len_actual_sealed_len % sizeof(*_tmp_actual_sealed_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_actual_sealed_len = (size_t*)malloc(_len_actual_sealed_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_actual_sealed_len, 0, _len_actual_sealed_len);
	}
	_in_retval = ecall_seal_data((const uint8_t*)_in_plaintext, _tmp_len, _in_sealed_data, _tmp_sealed_len, _in_actual_sealed_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed_data) {
		if (memcpy_verw_s(_tmp_sealed_data, _len_sealed_data, _in_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_actual_sealed_len) {
		if (memcpy_verw_s(_tmp_actual_sealed_len, _len_actual_sealed_len, _in_actual_sealed_len, _len_actual_sealed_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_actual_sealed_len) free(_in_actual_sealed_len);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_data_t* ms = SGX_CAST(ms_ecall_unseal_data_t*, pms);
	ms_ecall_unseal_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_unseal_data_t), ms, sizeof(ms_ecall_unseal_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed_data = __in_ms.ms_sealed_data;
	size_t _tmp_sealed_len = __in_ms.ms_sealed_len;
	size_t _len_sealed_data = _tmp_sealed_len;
	uint8_t* _in_sealed_data = NULL;
	uint8_t* _tmp_plaintext = __in_ms.ms_plaintext;
	size_t _tmp_plain_len = __in_ms.ms_plain_len;
	size_t _len_plaintext = _tmp_plain_len;
	uint8_t* _in_plaintext = NULL;
	size_t* _tmp_actual_plain_len = __in_ms.ms_actual_plain_len;
	size_t _len_actual_plain_len = sizeof(size_t);
	size_t* _in_actual_plain_len = NULL;
	sgx_status_t _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_actual_plain_len, _len_actual_plain_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ( _len_sealed_data % sizeof(*_tmp_sealed_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed_data = (uint8_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data, _len_sealed_data, _tmp_sealed_data, _len_sealed_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ( _len_plaintext % sizeof(*_tmp_plaintext) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}
	if (_tmp_actual_plain_len != NULL && _len_actual_plain_len != 0) {
		if ( _len_actual_plain_len % sizeof(*_tmp_actual_plain_len) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_actual_plain_len = (size_t*)malloc(_len_actual_plain_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_actual_plain_len, 0, _len_actual_plain_len);
	}
	_in_retval = ecall_unseal_data((const uint8_t*)_in_sealed_data, _tmp_sealed_len, _in_plaintext, _tmp_plain_len, _in_actual_plain_len);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_plaintext) {
		if (memcpy_verw_s(_tmp_plaintext, _len_plaintext, _in_plaintext, _len_plaintext)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_actual_plain_len) {
		if (memcpy_verw_s(_tmp_actual_plain_len, _len_actual_plain_len, _in_actual_plain_len, _len_actual_plain_len)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_plaintext) free(_in_plaintext);
	if (_in_actual_plain_len) free(_in_actual_plain_len);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_hello, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_process_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_seal_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_data, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][4];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_read_file(sgx_status_t* retval, const char* filename, uint8_t* buf, size_t buf_len, size_t* bytes_read)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_buf = buf_len;
	size_t _len_bytes_read = sizeof(size_t);

	ms_ocall_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_read_file_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_bytes_read = NULL;

	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(bytes_read, _len_bytes_read);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bytes_read != NULL) ? _len_bytes_read : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_read_file_t));
	ocalloc_size -= sizeof(ms_ocall_read_file_t);

	if (filename != NULL) {
		if (memcpy_verw_s(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(uint8_t*), &__tmp, sizeof(uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_buf_len, sizeof(ms->ms_buf_len), &buf_len, sizeof(buf_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (bytes_read != NULL) {
		if (memcpy_verw_s(&ms->ms_bytes_read, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_bytes_read = __tmp;
		if (_len_bytes_read % sizeof(*bytes_read) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_bytes_read, 0, _len_bytes_read);
		__tmp = (void *)((size_t)__tmp + _len_bytes_read);
		ocalloc_size -= _len_bytes_read;
	} else {
		ms->ms_bytes_read = NULL;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (bytes_read) {
			if (memcpy_s((void*)bytes_read, _len_bytes_read, __tmp_bytes_read, _len_bytes_read)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_file(sgx_status_t* retval, const char* filename, const uint8_t* buf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_buf = len;

	ms_ocall_write_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_file_t));
	ocalloc_size -= sizeof(ms_ocall_write_file_t);

	if (filename != NULL) {
		if (memcpy_verw_s(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const uint8_t*), &__tmp, sizeof(const uint8_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

