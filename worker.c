//
// Created by dev on 9/16/26.
//

#include "worker.h"

static int g_is_64_bit = 0;

/* flags breakdown:
 * since all internal functions rely on parsing arch-specific structures we need to know what arch we're working on
 * so call this to tell the library the architecture you are working with
 * it should be safe to call multiple times to edit the arch in use on the fly
 */

int set_libcoff_options(int _is_64_bit) {
    g_is_64_bit = _is_64_bit;
    return 0;
}

static inline int is_machine_64bit(const uint16_t machine_type) {
    for (int i = 0; i < MACHINE_64BIT_COUNT; i++) {
        if (MACHINE_64BIT_TYPES[i] == machine_type) {
            return 1;
        }
    }
    return 0;
}

static int detect_architecture(void* image) {
    if (!image) return 0;

    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)image;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    uint32_t* pe_sig_ptr = (uint32_t*)((uint8_t*)image + dos_header->e_lfanew);
    if (*pe_sig_ptr != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    const IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)(pe_sig_ptr + 1);

    return is_machine_64bit(file_header->Machine);
}
