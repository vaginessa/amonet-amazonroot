#include <inttypes.h>

#include "libc.h"

#include "common.h"

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

int (*original_read)(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) = (void*)0x4BD1E839;

uint64_t g_boot, g_recovery, g_lk, g_misc;

int read_func(struct device_t *dev, uint64_t block_off, void *dst, size_t sz, int part) {
    printf("read_func hook\n");
    int ret = 0;
    if (block_off == g_boot * 0x200 || block_off == g_recovery * 0x200) {
        // hex_dump(0x4BD5C000, 0x1000);
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
        } else if (memcmp(name, "l\x00k\x00\x00\x00", 6) == 0) {
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

    uint32_t **argptr = (void*)0x4BD00020;
    uint32_t *arg = *argptr;
    arg[0x53] = 4; // force 64-bit linux kernel

    int fastboot = 0;

    /*
    [300] [LK/LCM] lcm_init enter, build type: PVT, vendor type: FITI_KD
    [300] [LK/LCM] lcm_init No LCM connected. Just Return
    [340] DSI_WaitForNotBusy:Error:DSI_INTSTA is 0...
    */

    parse_gpt();

    if (!g_boot || !g_recovery || !g_lk) {
        printf("failed to find boot, recovery or lk\n");
        printf("falling back to fastboot mode\n");
        fastboot = 1;
    }

    int (*app)() = (void*)0x4BD27109;

    unsigned char overwritten[80] = {
        0xE9, 0x0A, 0xD0, 0x4B, 0x7D, 0x0E, 0xD0, 0x4B, 0x01, 0x09, 0xD0, 0x4B, 0x31, 0x0B, 0xD0, 0x4B,
        0x9D, 0x0C, 0xD0, 0x4B, 0x00, 0x84, 0xD5, 0x4B, 0x05, 0x0A, 0xD0, 0x4B, 0x71, 0x0A, 0xD0, 0x4B,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2D, 0x1B, 0xD0, 0x4B,
        0xF9, 0x1C, 0xD0, 0x4B, 0xA9, 0x1A, 0xD0, 0x4B, 0x95, 0x1D, 0xD0, 0x4B, 0x19, 0x1A, 0xD0, 0x4B,
        0xED, 0x1B, 0xD0, 0x4B, 0xA5, 0x19, 0xD0, 0x4B, 0x81, 0x1C, 0xD0, 0x4B, 0x00, 0x00, 0x00, 0x00 
    };
    memcpy((void*)0x4BD5C000, overwritten, sizeof(overwritten));

    uint8_t bootloader_msg[0x10] = { 0 };
    void *lk_dst = (void*)0x4BD00000;
    #define LK_SIZE (0x800 * 0x200)

    struct device_t *dev = get_device();

    //uint8_t tmp[0x10] = { 0 };
    //dev->read(dev, g_boot * 0x200 + 0x400, tmp, 0x10, USER_PART);
    uint8_t *tmp = (void*)0x4BD5C3B0;

    // microloader
    if (strncmp(tmp, "FASTBOOT_PLEASE", 15) == 0 ) {
      fastboot = 1;
    }

    // factory and factory advanced boot
    else if(*g_boot_mode == 4 ) {
      fastboot = 1;
    }

    // use advanced factory mode to boot recovery
    else if(*g_boot_mode == 6) {
      *g_boot_mode = 2;
    }

    else if(g_misc) {
      // Read amonet-flag from MISC partition
      dev->read(dev, g_misc * 0x200, bootloader_msg, 0x10, USER_PART);
      //dev->read(dev, g_misc * 0x200 + 0x4000, bootloader_msg, 0x10, USER_PART);
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

    uint16_t *patch;

    // force fastboot mode
    if (fastboot) {
        printf("well since you're asking so nicely...\n");

        patch = (void*)0x4BD2717C;
        *patch = 0;
        patch = (void*)0x4BD27182;
        *patch = 0;

        video_printf("=> HACKED FASTBOOT mode: (%d) - xyz, k4y0z\n", *g_boot_mode);
    }
    else if(*g_boot_mode == 2) {
        video_printf("=> RECOVERY mode...");
    }

    // enable all commands
    patch = (void*)0x4BD0D838;
    *patch++ = 0x2000; // movs r0, #0
    *patch = 0x4770;   // bx lr

    // device is unlocked
    patch = (void*)0x4BD01E84;
    *patch++ = 0x2001; // movs r0, #1
    *patch = 0x4770;   // bx lr

    // Force uart enable
    char* disable_uart = (char*)0x4BD4BC37;
    strcpy(disable_uart, "printk.disable_uart=0");

    // hook bootimg read function
    uint32_t *patch32;
    patch32 = (void*)&dev->read;
    *patch32 = (uint32_t)read_func;

    patch32 = (void*)0x4BD681B8;
    *patch32 = 1; // // force 64-bit linux kernel

    printf("Clean lk\n");
    cache_clean(lk_dst, LK_SIZE);

    app();

    while (1) {

    }
}
