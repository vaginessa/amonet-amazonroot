#include <inttypes.h>

#include "libc.h"

#include "common.h"

#define RELOAD_LK 1

void low_uart_put(int ch) {
    volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
    volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

    while ( !((*uart_reg0) & 0x20) )
    {}

    *uart_reg1 = ch;
}

void _putchar(char character)
{
    if (character == '\n')
        low_uart_put('\r');
    low_uart_put(character);
}

//int (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) = (void *)0x4BD1E839;
int (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) = (void *)0x81E141F5;

uint64_t g_boot, g_recovery, g_lk;

void hex_dump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("\n");
                // printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                // printf("|  %s \n", ascii);
                printf("\n");
            }
        }
    }
}


int read_func(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) {
    printf("read_func hook\n");
    int ret = 0;
    //hex_dump((void *)0x81E6E998, 0x1000);
    //return original_read(dev, block_off, dst, sz, part);
    if (block_off == g_boot * 0x200 || block_off == g_recovery * 0x200) {
        //hex_dump((void *)0x81E6E998, 0x1000);
        printf("demangle boot image - from 0x%08X\n", __builtin_return_address(0));
        if (sz < 0x400) {
            ret = original_read(dev, block_off + 0x400, dst, sz, part);
        } else {
            void *second_copy = (char*)dst + 0x400;
            ret = original_read(dev, block_off, dst, sz, part);
            memcpy(dst, second_copy, 0x400);
            memset(second_copy, 0, 0x400);
        }
    } else {
        printf("read_func original_read\n");
        ret = original_read(dev, block_off, dst, sz, part);
    }
    if(__builtin_return_address(0) == (void*)0x81E02D13){
      //void (*my_ret)() = (void*)0x81E02D63;
      //void (*my_ret)() = (void*)0x81E02DA7;
      //my_ret();

//      asm volatile (
//          "b 0x81E02D36\n"
//          : );
    }
    return ret;
}

static void parse_gpt() {
    uint8_t raw[0x800] = { 0 };
    struct device_t *dev = get_device();
    dev->read(dev, 0x400, raw, sizeof(raw), USER_PART);
    for (int i = 0; i < sizeof(raw) / 0x80; ++i) {
        uint8_t *ptr = &raw[i * 0x80];
        uint8_t *name = ptr + 0x38;
        uint32_t start;
        memcpy(&start, ptr + 0x20, 4);
        if (memcmp(name, "b\x00o\x00o\x00t\x00\x00\x00", 10) == 0) {
            printf("found boot at 0x%08X\n", start);
            g_boot = start;
        } else if (memcmp(name, "r\x00\x65\x00\x63\x00o\x00v\x00\x65\x00r\x00y\x00\x00\x00", 18) == 0) {
            printf("found recovery at 0x%08X\n", start);
            g_recovery = start;
        } else if (memcmp(name, "U\x00\x42\x00O\x00O\x00T\x00\x00\x00", 12) == 0) {
            printf("found lk at 0x%08X\n", start);
            g_lk = start;
        }
    }
}

int main() {
    int ret = 0;
    printf("This is LK-payload by xyz. Copyright 2019\n");

    //uint32_t **argptr = (void*)0x4BD00020;
    uint32_t **argptr = (void*)0x81E00020;
    uint32_t *arg = *argptr;
    //arg[0x53] = 4; // force 64-bit linux kernel

    int fastboot = 0;

    /*
    [300] [LK/LCM] lcm_init enter, build type: PVT, vendor type: FITI_KD
    [300] [LK/LCM] lcm_init No LCM connected. Just Return
    [340] DSI_WaitForNotBusy:Error:DSI_INTSTA is 0...
    */

    parse_gpt();

    if (!g_boot || !g_recovery || !g_lk) {
        printf("failed to find boot, recovery or lk\n");
        while (1) {}
    }

    //int (*app)() = (void*)0x4BD27109;
    int (*app)() = (void*)0x81E3D8E5; //loading
    //int (*app)() = (void*)0x81E3D4AD;
    //int (*app)() = (void*)0x81E1C2F0;
    //int (*app)() = (void*)0x81E0074C;
    //int (*app)() = (void*)0x81E39B7D;
    //int (*app2)() = (void*)0x81E1C2F1; //loading

    /*unsigned char overwritten[80] = {
        0xE9, 0x0A, 0xD0, 0x4B, 0x7D, 0x0E, 0xD0, 0x4B, 0x01, 0x09, 0xD0, 0x4B, 0x31, 0x0B, 0xD0, 0x4B,
        0x9D, 0x0C, 0xD0, 0x4B, 0x00, 0x84, 0xD5, 0x4B, 0x05, 0x0A, 0xD0, 0x4B, 0x71, 0x0A, 0xD0, 0x4B,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2D, 0x1B, 0xD0, 0x4B,
        0xF9, 0x1C, 0xD0, 0x4B, 0xA9, 0x1A, 0xD0, 0x4B, 0x95, 0x1D, 0xD0, 0x4B, 0x19, 0x1A, 0xD0, 0x4B,
        0xED, 0x1B, 0xD0, 0x4B, 0xA5, 0x19, 0xD0, 0x4B, 0x81, 0x1C, 0xD0, 0x4B, 0x00, 0x00, 0x00, 0x00 
    };*/
    unsigned char overwritten[] = {
        0xB1, 0xD5, 0xE1, 0x81, 0x6D, 0xD7, 0xE1, 0x81, 0xA1, 0xD3, 0xE1, 0x81, 0xFD, 0xD5, 0xE1, 0x81,
        0x69, 0xD7, 0xE1, 0x81, 0x98, 0xC1, 0xE6, 0x81, 0xBD, 0xD4, 0xE1, 0x81, 0x31, 0xD5, 0xE1, 0x81,
        0xD5, 0xD0, 0xE1, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    memcpy((void*)0x81E6E998, overwritten, sizeof(overwritten));

    //void *lk_dst = (void*)0x4BD00000;
    void *lk_tmp = (void*)0x89B00000;
    void *lk_dst = (void*)0x81E00000;
    #define LK_SIZE (0x800 * 0x200)

    struct device_t *dev = get_device();

    if(RELOAD_LK) {
      ret = dev->read(dev, g_lk * 0x200 + 0x200, lk_tmp, LK_SIZE, USER_PART);
      printf("read lk: 0x%08X\n", ret);
    }

    uint8_t tmp[0x10] = { 0 };
    dev->read(dev, g_boot * 0x200 + 0x400, tmp, 0x10, USER_PART);
    if (strcmp(tmp, "FASTBOOT_PLEASE") == 0) {
        printf("well since you're asking so nicely...\n");
        fastboot = 1;
    }

    if (RELOAD_LK){
      printf("Disable interrupts\n");
      asm volatile ("cpsid if");

      printf("Copy lk\n");
      cache_clean(lk_tmp, LK_SIZE);
      memcpy(lk_dst, lk_tmp, LK_SIZE);

      uint32_t *argfix = (void*)0x81E00020;
      *argfix = 0x82053C08;
    }

    uint16_t *patch;


    // force fastboot mode
    if (fastboot) {
        patch = (void*)0x81E3D914;
        *patch = 0xE003;
    }
    
    /*
    // enable all commands
    patch = (void*)0x4BD0D838;
    *patch++ = 0x2000; // movs r0, #0
    *patch = 0x4770;   // bx lr
    */

    /*
    // device is unlocked
    patch = (void*)0x81E3CE7C;
    *patch++ = 0x2001; // movs r0, #1
    *patch = 0x4770;   // bx lr
    
    // skip verification
    patch = (void*)0x81E39962;
    while(patch < (uint16_t*)0x81E39980){
      *patch++ = 0xBF00;
    }

    // engineering device
    patch = (void*)0x81E00240;
    *patch = 0x2000;
    */

    uint32_t *patch32;
    patch32 = (void*)0x81E02D2E;
    *patch32 = 0xE3B00000; // mov r0, #0
    patch32 = (void*)0x81E02DBC;
    *patch32 = 0xE3B00000; // mov r0, #0


    // amzn_verify_unlock
    //patch = (void*)0x81E3CCD8;
    //*patch++ = 0x2001; // movs r0, #1
    //*patch = 0x4770;   // bx lr

    // hook bootimg read function
    original_read = (void*)dev->read;
    //patch32 = (void*)0x81E67124;
    if(RELOAD_LK) {
      patch32 = (void*)0x81E63124;
    }
    else {
      patch32 = (void*)&dev->read;
    }
    *patch32 = (uint32_t)read_func;

    /*
    patch32 = (void*)0x4BD681B8;
    *patch32 = 1; // // force 64-bit linux kernel
    */
    
    printf("Clean lk\n");
    cache_clean(lk_dst, LK_SIZE);

    if(RELOAD_LK) {
      printf("About to jump to LK\n");

      asm volatile (
          "mov r4, %0\n" 
          "mov r3, %1\n"
          "blx r3\n"
          : : "r" (arg), "r" (lk_dst) : "r3", "r4");

      printf("Failure\n");
    }
    else {
      app();
    }

    while (1) {

    }
}
