#pragma once

struct device_t {
    uint32_t unk1;
    uint32_t unk2;
    uint32_t unk3;
    uint32_t unk4;
    size_t (*read)(struct device_t *dev, uint64_t dev_addr, void *dst, uint32_t size, uint32_t part);
};

//struct device_t* (*get_device)() = (void*)0x81E14681;
struct device_t* (*get_device)() = (void*)0x81E354F1;
//void (*cache_clean)(void *addr, size_t sz) = (void*)0x81E1AE60;
void (*cache_clean)(void *addr, size_t sz) = (void*)0x81E3BCD0;
//void (*cache_clean)(void *addr, size_t sz) = (void*)0x81E1AE34;

#define PAYLOAD_DST 0x8AB00000
#define PAYLOAD_SRC 0x200000
#define PAYLOAD_SIZE 0x200000

#define BOOT0_PART 1
#define USER_PART 8
