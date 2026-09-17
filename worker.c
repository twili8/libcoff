//
// Created by dev on 9/16/26.
//

#include "worker.h"

int set_libcoff_options() {
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
static inline uint16_t get_machine_type(const void* image) {
    if (!image) return 0;

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    const uint32_t* pe_sig = (const uint32_t*)((const uint8_t*)image + dos->e_lfanew);
    if (*pe_sig != IMAGE_NT_SIGNATURE) return 0;

    const IMAGE_FILE_HEADER* fh = (const IMAGE_FILE_HEADER*)(pe_sig + 1);
    return fh->Machine;
}

static void* get_nt_headers(const void* image) {
    if (!image) return 0;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (void*)((uint8_t*)image + dos->e_lfanew);
}

int is_image_valid(const void* image) {
    if (!image) return 0;

    const uint16_t machine = get_machine_type(image);
    if (machine == 0) return 0;

    void* nt = get_nt_headers(image);
    if (!nt) return 0;

    return *(const uint32_t*)nt == IMAGE_NT_SIGNATURE;
}

int is_image_have_entry_point(const void* image) {
    const uint16_t machine = get_machine_type(image);
    if (machine == 0) return 0;

    void* nt = get_nt_headers(image);
    if (!nt) return 0;

    if (is_machine_64bit(machine)) {
        return ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.AddressOfEntryPoint != 0;
    } else {
        return ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.AddressOfEntryPoint != 0;
    }
}

struct image_section {
    struct image_section* next;
    uint32_t virtual_address;
    uint32_t size;
};

static int helper_image_find_sections_32(const void* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    return 0;
}

static int helper_image_find_sections_64(const void* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    return 0;
}

int image_find_sections(const void* image,
    int find_x,
    int find_w,
    int find_r,
    int find_ro) {
    if (!is_image_valid(image)) return 0;

    if (is_machine_64bit(machine)) {
        return helper_image_find_sections_64(image, find_x, find_w, find_r, find_ro);
    } else {
        return helper_image_find_sections_32(image, find_x, find_w, find_r, find_ro);
    }

    return 0;
}


int image_how_many_sections(const void* image) {
    return 0;
}
