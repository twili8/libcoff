//
// Created by dev on 9/16/26.
//

#include "worker.h"
//
// Created by dev on 9/16/26.
//

#include "worker.h"

int is_image_valid_pe(void* image, __ssize_t image_len) {
    PIMAGE_NT_HEADERS64 i = (PIMAGE_NT_HEADERS64)image;
}