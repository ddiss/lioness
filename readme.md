**Warning**: this project is experimental, work-in-progress and completely
unsupported.

## Lioness

The aim of the Lioness project is to provide a system image for a linux-powered
USB security key, which can run on commonly available hardware, such as the
[NanoPi NEO2](https://linux-sunxi.org/FriendlyARM_NanoPi_NEO2).
The image should be minimal in size and use mainline kernel + u-boot sources,
powered by the [Buildroot](https://buildroot.org) build system.


### Getting started

Build a NanoPi NEO2 image by running:
```
git clone --recurse-submodules <this-repo-uri> lioness
mkdir lioness/out
cd lioness/out
make O=$PWD -C ../buildroot defconfig BR2_DEFCONFIG=../board-nanopi-neo2/buildroot_config BR2_EXTERNAL=../buildroot-external/
make
```

This should generate an SD card image under `images/sdcard.img`, which can be
written via:
```
dd if=images/sdcard.img of=<sd-card-device> bs=1M
```

The SD card can then be placed in a NanoPi NEO2 and booted. The image will boot
to expose a USB mass-storage device, which contains a static file-backed
configuration website. Upon configuration, the website allows the user to save
the settings to a file. With the `/usr/bin/lioness` binary running on the
board (it's not started by default), the configuration file will be
automatically detected and validated, when saved to `lioness.txt`.


### Work in progress

Functionality to initialized and unlock the dm-crypt storage area has not yet
been finilized. In addition to that, there is a long list of desired features:
- store salt in GPT uuid(?)
- mkfs.btrfs dm-crypt area
- mkfs.exfat file-on-btrfs
- on open: handle snapshots (reflink file)
- expose file-on-btrfs via USB
- FIDO2 / webauthn using softfido or an alternative
- OS image update from static website
- test, test, test!
- support for other boards


### Debugging

By default, the image provides boot logs via UART. A dhcp client starts on boot
alongside an ssh server which can be accessed with root/root credentials.


### Thanks

Thanks to SUSE for allowing me to work on this project as part of
[Hack Week 22](https://hackweek.opensuse.org/22/projects/usb-security-key-running-embedded-linux).
Thanks for FriendlyArm for providing some NanoPi hardware free of charge.
