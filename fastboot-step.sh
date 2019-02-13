#!/bin/bash

set -e

fastboot flash boot bin/boot.img
fastboot flash recovery bin/twrp.img
fastboot oem reboot-recovery

echo ""
echo ""
echo "Your device should now reboot into TWRP"
echo ""
