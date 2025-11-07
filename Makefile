obj-m += btmtk_usb_mt6639.o

curpwd := $(shell pwd)
kver := $(shell uname -r)

all:
	$(MAKE) -C /lib/modules/${kver}/build M=${curpwd} modules

clean:
	$(MAKE) -C /lib/modules/${kver}/build M=${curpwd} clean
