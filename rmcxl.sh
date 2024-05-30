#!/bin/bash

sudo rmmod cdatfix
sudo rmmod cxl_port
sudo rmmod cxl_acpi
sudo rmmod cxl_mem
sudo rmmod cxl_pci
sudo rmmod cxl_core

sudo modprobe cxl_port
sudo modprobe cxl_acpi
sudo modprobe cxl_mem

# cdatfix should be before cxl_pci
# but after cxl_core is loaded (by other modules)
# otherwise the required function symbol is not defined
sudo modprobe cdatfix
sudo modprobe cxl_pci

