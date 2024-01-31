TREE_TOP = ${HOME}/magicleap
KERNEL_TOP = ${TREE_TOP}/kernel

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
KDIR := ${KERNEL_TOP}
CC := $(CROSS_COMPILE)gcc

HCSM_MODULE_ODIR := $(KERNEL_TOP)/modules/hcsm/arm

all:
	# Make sure to clean before we copy over the contents.
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	if [ ! -d $(HCSM_MODULE_ODIR) ]; then mkdir -p $(HCSM_MODULE_ODIR); fi
	cp -R * $(HCSM_MODULE_ODIR)
	$(MAKE) -C $(KDIR) M=$(HCSM_MODULE_ODIR) CC="${CC}" modules

.PHONY: clean
clean:
	if [ -d $(HCSM_MODULE_ODIR) ]; then\
		$(MAKE) -C $(KDIR) M=$(HCSM_MODULE_ODIR) clean;\
	fi
