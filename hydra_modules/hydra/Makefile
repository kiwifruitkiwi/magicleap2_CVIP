TREE_TOP = ${HOME}/magicleap
KERNEL_TOP = ${TREE_TOP}/kernel

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
KDIR := ${KERNEL_TOP}
CC := $(CROSS_COMPILE)gcc

HYDRA_MODULE_ODIR := $(KERNEL_TOP)/modules/hydra/arm/kernel

all:
	# Make sure to clean before we copy over the contents.
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	if [ ! -d $(HYDRA_MODULE_ODIR) ]; then mkdir -p $(HYDRA_MODULE_ODIR); fi
	cp -R * $(HYDRA_MODULE_ODIR)
	$(MAKE) -C $(KDIR) M=$(HYDRA_MODULE_ODIR) CC="${CC}" modules

.PHONY: clean
clean:
	if [ -d $(HYDRA_MODULE_ODIR) ]; then\
		$(MAKE) -C $(KDIR) M=$(HYDRA_MODULE_ODIR) clean;\
	fi
