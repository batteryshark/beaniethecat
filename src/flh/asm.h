#pragma once

void flh_sanitize_original_bytes(void* original_address,void* sanitized_code_address, unsigned int code_size);
unsigned int flh_calculate_aligned_stub_size(void* target_address, unsigned int hotpatch_length);