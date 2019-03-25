#include <inttypes.h>

#include "libc.h"

#include "common.h"

//#define RELOAD_LK

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

int (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, uint32_t part) = (void *)0x81E33E69;
int (*original_write)(struct device_t *dev, void *src, uint64_t block_off, size_t sz, uint32_t part) = (void *)0x81E351E5;

uint64_t g_boot, g_recovery, g_lk, g_misc;

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
    if (block_off == g_boot * 0x200 || block_off == g_recovery * 0x200) {
        //hex_dump((void *)0x81E68000, 0x100);
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
        ret = original_read(dev, block_off, dst, sz, part);
    }
    return ret;
}

#if 0
int write_func(struct device_t *dev, void *src, uint64_t block_off, size_t sz, int part) {
    printf("write_func hook\n");
    return original_write(dev, src, block_off, sz, part);
}
#endif

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
        } else if (memcmp(name, "M\x00I\x00S\x00\x43\x00\x00\x00", 10) == 0) {
            printf("found misc at 0x%08X\n", start);
            g_misc = start;
        }
    }
}

int main() {
    int ret = 0;
    printf("This is LK-payload by xyz. Copyright 2019\n");
    printf("Ported to Fire 7 by k4y0z, Copyright 2019\n");

    int fastboot = 0;

    parse_gpt();

    if (!g_boot || !g_recovery || !g_lk) {
        printf("failed to find boot, recovery or lk\n");
        printf("falling back to fastboot mode\n");
        fastboot = 1;
    }

    int (*app)() = (void*)0x81e3cb31;

    /*
     * 71 12 E0 81 39 14 E0 81  49 10 E0 81 C1 12 E0 81  
     * 35 14 E0 81 00 44 E6 81  65 11 E0 81 E5 11 E0 81
    */
    unsigned char overwritten[] = {
        0x71, 0x12, 0xE0, 0x81, 0x39, 0x14, 0xE0, 0x81, 0x49, 0x10, 0xE0, 0x81, 0xC1, 0x12, 0xE0, 0x81,
        0x35, 0x14, 0xE0, 0x81, 0x00, 0x44, 0xE6, 0x81, 0x65, 0x11, 0xE0, 0x81, 0xE5, 0x11, 0xE0, 0x81,
    };

    void *lk_dst = (void*)0x81E00000;
    #define LK_SIZE (0x800 * 0x200)

    struct device_t *dev = get_device();

    memcpy((void*)0x81E68000, overwritten, sizeof(overwritten));

    uint8_t bootloader_msg[0x10] = { 0 };

    //uint8_t tmp[0x10] = { 0 };
    //dev->read(dev, g_boot * 0x200 + 0x400, tmp, 0x10, USER_PART);
    uint8_t *tmp = (void*)0x81E683B0;

    if(g_misc) {
      // Read amonet-flag from MISC partition
      //dev->read(dev, g_misc * 0x200 + 0x4000, bootloader_msg, 0x10, USER_PART);
      dev->read(dev, g_misc * 0x200, bootloader_msg, 0x10, USER_PART);
      printf("bootloader_msg: %s\n", bootloader_msg);

      // temp flag on MISC
      if(strncmp(bootloader_msg, "boot-amonet", 11) == 0) {
        fastboot = 1;
        // reset flag
        memset(bootloader_msg, 0, 0x10);
        dev->write(dev, bootloader_msg, g_misc * 0x200, 0x10, USER_PART);
      }

      // perm flag on MISC
      else if(strncmp(bootloader_msg, "FASTBOOT_PLEASE", 15) == 0) {
        // only reset flag in recovery-boot
        if(*g_boot_mode == 2) {
          memset(bootloader_msg, 0, 0x10);
          dev->write(dev, bootloader_msg, g_misc * 0x200, 0x10, USER_PART);
        }
        else {
          fastboot = 1;
        }
      }
    }

    // microloader
    else if (strncmp(tmp, "FASTBOOT_PLEASE", 15) == 0 ) {
      fastboot = 1;
    }
    // factory and factory advanced boot
    else if(*g_boot_mode == 4){
      fastboot = 1;
    }
    // Use advanced factory boot to boot into recovery (tank has no buttons)
    else if(*g_boot_mode == 6){
      *g_boot_mode = 2;
    }

#ifdef RELOAD_LK
      printf("Disable interrupts\n");
      asm volatile ("cpsid if");
#endif

    uint16_t *patch;

    // force fastboot mode
    if (fastboot) {
        printf("well since you're asking so nicely...\n");

        patch = (void*)0x81E3CB60;
        *patch = 0xE003;

        video_printf("=> HACKED FASTBOOT mode: (%d) - xyz, k4y0z, NW\n", *g_boot_mode);
    }
    else if(*g_boot_mode == 2) {
        video_printf("=> RECOVERY mode...");
    }
    
    // device is unlocked
    patch = (void*)0x81e20a1c;
    *patch++ = 0x2001; // movs r0, #1
    *patch = 0x4770;   // bx lr

    // This enables adb-root-shell
    // amzn_verify_limited_unlock (to set androidboot.unlocked_kernel=true)
    patch = (void*)0x81e20c3c;
    *patch++ = 0x2000; // movs r0, #0
    *patch = 0x4770;   // bx lr

#if 0
    // skip verification
    patch = (void*)0x81E1D39A;
    while(patch < (uint16_t*)0x81E1D3C8){
      *patch++ = 0xBF00;
    }
#endif


    // Force uart enable
    char* disable_uart = (char*)0x81e55f28;
    strcpy(disable_uart, "printk.disable_uart=0");
    char* disable_uart2 = (char*)0x81e55e10;
    strcpy(disable_uart2, " printk.disable_uart=0");

    uint32_t *patch32;

    // hook bootimg read function
    if(!fastboot){
      original_read = (void*)dev->read;

      patch32 = (void*)0x81e6200c;
      *patch32 = (uint32_t)read_func;

      patch32 = (void*)&dev->read;
      *patch32 = (uint32_t)read_func;
    }

#if 0
    // hook write-function
    original_write = (void*)dev->write;
    patch32 = (void*)&dev->write;
    *patch32 = (uint32_t)write_func;
#endif

    printf("Clean lk\n");
    cache_clean(lk_dst, LK_SIZE);

#ifdef RELOAD_LK
    printf("About to jump to LK\n");

    uint32_t **argptr = (void*)0x81E00020;
    uint32_t *arg = *argptr;

    asm volatile (
        "mov r4, %0\n" 
        "mov r3, %1\n"
        "blx r3\n"
        : : "r" (arg), "r" (lk_dst) : "r3", "r4");

    printf("Failure\n");
#else
    app();
#endif

    while (1) {

    }
}
