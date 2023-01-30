# ENV vars prepended above via board specific files
STATUS_LED_PATH="${STATUS_LED_PATH:-/sys/class/leds/nanopi:blue:status}"
MUSB_UDC="${MUSB_UDC:-musb-hdrc.1.auto}"

echo 4M > /sys/devices/virtual/block/zram0/disksize
mkfs.vfat -n lioness /dev/zram0
mount /dev/zram0 /mnt/
mkdir /mnt/LOST.DIR # avoid Android creating one automatically
cp /app/setup.html /mnt/
#dmesg > /mnt/log.txt
umount /mnt/

mount -t configfs configfs /sys/kernel/config
mkdir -p /sys/kernel/config/usb_gadget/confs/strings/0x409 \
	/sys/kernel/config/usb_gadget/confs/functions/mass_storage.usb0 \
	/sys/kernel/config/usb_gadget/confs/configs/c.1/strings/0x409
cd /sys/kernel/config/usb_gadget/confs
echo 0x1d6b > idVendor # Linux Foundation
echo 0x0104 > idProduct # Multifunction Composite Gadget
echo 0x0090 > bcdDevice # v0.9.0

echo "openSUSE" > strings/0x409/manufacturer 
echo "lioness config" > strings/0x409/product 
# (hopefully) unique board SID used as serial number
hexdump -n 16 -e '16 "%02x"' /sys/bus/nvmem/devices/sunxi-sid0/nvmem \
	> strings/0x409/serialnumber

echo 1 > functions/mass_storage.usb0/stall                                     
echo 0 > functions/mass_storage.usb0/lun.0/cdrom                               
echo 0 > functions/mass_storage.usb0/lun.0/ro                                  
echo 0 > functions/mass_storage.usb0/lun.0/nofua                               
echo 1 > functions/mass_storage.usb0/lun.0/removable
echo /dev/zram0 > functions/mass_storage.usb0/lun.0/file

echo "Config 1: mass-storage" > configs/c.1/strings/0x409/configuration
echo 500 > configs/c.1/MaxPower
ln -s functions/mass_storage.usb0 configs/c.1/
echo $MUSB_UDC > UDC

echo heartbeat > "$STATUS_LED_PATH"/trigger
