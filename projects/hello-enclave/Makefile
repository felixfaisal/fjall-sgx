# Makefile for SGX Hello Enclave (Simulation Mode)
#
# Build targets:
#   make SGX_MODE=SIM        — Build for simulation (no SGX hardware needed)
#   make SGX_MODE=HW         — Build for real SGX hardware
#   make clean               — Remove build artifacts
#
# How the build works:
#   1. sgx_edger8r processes enclave.edl → generates enclave_t.c/h (trusted)
#      and enclave_u.c/h (untrusted) proxy functions
#   2. Enclave code (enclave.c + enclave_t.c) → compiled and linked into enclave.so
#   3. sgx_sign signs enclave.so → enclave.signed.so (with simulated key in SIM mode)
#   4. Host app (app.c + enclave_u.c) → compiled and linked into app

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM

ifeq ($(SGX_MODE), SIM)
    # Simulation mode: use _sim libraries (no real SGX)
    Urts_Library_Name := sgx_urts_sim
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
    CFlags_Sim := -DSGX_SIM
else
    # Hardware mode: use real SGX libraries
    Urts_Library_Name := sgx_urts
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
    CFlags_Sim :=
endif

SGX_COMMON_FLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

# ---- Untrusted (Host) App Settings ----
App_C_Flags := $(SGX_COMMON_FLAGS) -fPIC -Wno-attributes \
    -I$(SGX_SDK)/include \
    -Ienclave \
    $(CFlags_Sim)

App_Link_Flags := -L$(SGX_LIBRARY_PATH) \
    -l$(Urts_Library_Name) \
    -lpthread

# ---- Trusted (Enclave) Settings ----
Enclave_C_Flags := $(SGX_COMMON_FLAGS) -nostdinc -fvisibility=hidden \
    -fpie -ffunction-sections -fdata-sections \
    -I$(SGX_SDK)/include \
    -I$(SGX_SDK)/include/tlibc \
    -Ienclave

Enclave_Link_Flags := \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
    -Wl,--start-group \
        -lsgx_tstdc -lsgx_tcrypto -l$(Service_Library_Name) \
    -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=enclave/enclave.lds

# ---- Build Rules ----

.PHONY: all clean

all: hello_enclave

# Step 1: Generate edge routines from EDL
enclave/enclave_t.c enclave/enclave_t.h: enclave/enclave.edl
	@echo "GEN  => Edge routines (trusted side)"
	$(SGX_EDGER8R) --trusted enclave/enclave.edl \
		--search-path $(SGX_SDK)/include \
		--trusted-dir enclave

enclave/enclave_u.c enclave/enclave_u.h: enclave/enclave.edl
	@echo "GEN  => Edge routines (untrusted side)"
	$(SGX_EDGER8R) --untrusted enclave/enclave.edl \
		--search-path $(SGX_SDK)/include \
		--untrusted-dir enclave

# Step 2: Compile trusted objects
enclave/enclave_t.o: enclave/enclave_t.c
	@echo "CC   => $@"
	gcc $(Enclave_C_Flags) -c $< -o $@

enclave/enclave.o: enclave/enclave.c enclave/enclave_t.h
	@echo "CC   => $@"
	gcc $(Enclave_C_Flags) -c $< -o $@

# Step 3: Link enclave shared object
enclave.so: enclave/enclave.o enclave/enclave_t.o
	@echo "LINK => $@"
	gcc $^ -o $@ $(Enclave_Link_Flags)

# Step 4: Sign the enclave
enclave.signed.so: enclave.so enclave/enclave.config.xml
	@echo "SIGN => $@"
	$(SGX_ENCLAVE_SIGNER) sign \
		-key enclave/enclave_private.pem \
		-enclave enclave.so \
		-out $@ \
		-config enclave/enclave.config.xml

# Step 5: Compile untrusted objects
enclave/enclave_u.o: enclave/enclave_u.c
	@echo "CC   => $@"
	gcc $(App_C_Flags) -c $< -o $@

app/app.o: app/app.c enclave/enclave_u.h
	@echo "CC   => $@"
	gcc $(App_C_Flags) -c $< -o $@

# Step 6: Link the host application
hello_enclave: app/app.o enclave/enclave_u.o enclave.signed.so
	@echo "LINK => $@"
	gcc app/app.o enclave/enclave_u.o -o $@ $(App_Link_Flags)
	@echo ""
	@echo "Build complete! Run with: ./app"

# Generate signing key (one-time)
enclave/enclave_private.pem:
	@echo "GEN  => RSA signing key"
	openssl genrsa -out $@ -3 3072

# Linker version script for enclave
enclave/enclave.lds:
	@echo "GEN  => Linker script"
	@echo "enclave.so {" > $@
	@echo "    global:" >> $@
	@echo "        g_global_data_sim;" >> $@
	@echo "        g_global_data;" >> $@
	@echo "        enclave_entry;" >> $@
	@echo "        g_peak_heap_used;" >> $@
	@echo "        g_peak_rsrv_mem_committed;" >> $@
	@echo "    local:" >> $@
	@echo "        *;" >> $@
	@echo "};" >> $@

clean:
	rm -f hello_enclave enclave.so enclave.signed.so
	rm -f app/app.o
	rm -f enclave/enclave.o enclave/enclave_t.o enclave/enclave_u.o
	rm -f enclave/enclave_t.c enclave/enclave_t.h
	rm -f enclave/enclave_u.c enclave/enclave_u.h
	rm -f enclave/enclave.lds enclave/enclave_private.pem
