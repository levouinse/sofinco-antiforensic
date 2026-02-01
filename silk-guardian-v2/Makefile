# SOFINCO v6.0 - Silk Guardian v2 - Makefile

obj-m += silk_v2.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	@echo "Building Silk Guardian v2.0..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo "✅ Build complete: silk_v2.ko"

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@echo "✅ Clean complete"

install:
	@echo "Installing Silk Guardian v2.0..."
	sudo insmod silk_v2.ko
	@echo "✅ Module loaded"
	@dmesg | tail -20

uninstall:
	@echo "Uninstalling Silk Guardian v2.0..."
	sudo rmmod silk_v2
	@echo "✅ Module unloaded"

status:
	@echo "Silk Guardian v2.0 Status:"
	@lsmod | grep silk_v2 || echo "Module not loaded"
	@echo ""
	@echo "Kernel logs:"
	@dmesg | grep silk | tail -10

test:
	@echo "Testing Silk Guardian v2.0..."
	@echo "1. Loading module..."
	sudo insmod silk_v2.ko
	@sleep 1
	@echo "2. Checking if loaded..."
	@lsmod | grep silk_v2 && echo "✅ Module loaded" || echo "❌ Module not loaded"
	@echo "3. Checking kernel logs..."
	@dmesg | grep silk | tail -5
	@echo "4. Unloading module..."
	sudo rmmod silk_v2
	@echo "✅ Test complete"

.PHONY: all clean install uninstall status test
