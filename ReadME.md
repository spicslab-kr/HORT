# Artifact: HORT: Fast and Secure TEE-Assisted Homomorphic Encryption in the Cloud

This repository contains the source code and artifact for our research on securing execution environments using **AMD Secure Encrypted Virtualization (SEV)**. 
---

## 1. Overview

This artifact is designed to reproduce the security mitigations discussed in our paper. It provides a containerized environment to ensure consistent code instrumentation and binary hardening, followed by a runtime environment to execute these binaries under hardware-backed SEV protection.

**The workflow consists of:**

1. **Host Setup**: Preparing hardware and software dependencies.
2. **Docker-based Hardening**: Applying `Coeff`, `Slot`, and `LWE` mitigations in a unified build flow.
3. **SEV Deployment**: Verifying hardware encryption and executing the protected workload.

---

## 2. System Requirements

To successfully reproduce the results, the following environment is required:

### Hardware

* **CPU**: AMD EPYC™ processor (Generations supporting SEV, SEV-ES, or SEV-SNP).
* **Memory**: Minimum 16GB RAM.

### Software & Kernel

* **OS**: Ubuntu 20.04 LTS or later (Linux Kernel 5.4+ recommended).
* **Kernel Configuration**: Must be booted with `sev=on` and `CONFIG_KVM_AMD_SEV=y`.
* **Container Runtime**: Docker Engine.

---

## 3. Step-by-Step Instructions

### Step 1: Environment Configuration (Host)

The `setup.sh` script prepares the host environment, installs required dependencies (including Docker and build tools), and applies the **Constantine** and **Cipherfix** patches required for the mitigation pipeline.

```bash
# Grant execution permission
chmod +x setup.sh

# Run the setup script (requires sudo)
sudo ./setup.sh

```

### Step 2: Apply Mitigations & Build Hardened Binaries

The mitigation pipeline runs inside Docker to ensure reproducibility. This step applies mitigations to following srcs(**Coeff**, **Slot**, and **LWE**) and generates the final hardened binaries.

```bash
# Grant execution permission
chmod +x mitigation_docker.sh

# Build the Docker image and execute the mitigation pipeline
# You can optionally pass N as an argument, e.g., ./mitigation_docker.sh 16384
./mitigation_docker.sh

```

*The resulting binaries will be output to the host's `./build` directory.*

### Step 3: SEV Hardware Activation

SEV activation requires host-level configuration (BIOS settings and kernel parameters) followed by a reboot. Once the host is configured, verify that SEV is active:

```bash
# Check if SEV is active in the kernel logs
dmesg | grep -i sev

```

**Expected Output:** Look for "SEV enabled" or "SEV-ES enabled" in the logs.

To enable SEV hardware support follow the steps in the official  guidelines from AMD(https://github.com/AMDESE/AMDSEV/tree/snp-latest#prepare-host)

#### 1. Install build dependencies (tested on Ubuntu 22.04)

```bash
sudo apt update
sudo apt install build-essential ninja-build python-is-python3 \
flex bison libncurses-dev gawk openssl libssl-dev dkms \
libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm

sed -i '/deb-src/s/^# //' /etc/apt/sources.list && apt update

apt build-dep ovmf qemu-system-x86 linux
```
#### 2. Run ./build.sh ovmf, ./build.sh qemu to build OVMF and QEMU. All packages are only installed locally in ./local-installation/.
``` bash
./build.sh ovmf
./build.sh qemu
```

#### 3. Create the config file /etc/modprobe.d/kvm.conf with content below to enable sev support
``` bash
vim /etc/modprobe.d/kvm.conf
```
``` bash
# Enable SEV Support
options kvm_amd sev-snp=1 sev=1 sev-es=1

# Pagetracking code for SEV-Step does not work if this option is set
# Context: there seems to be a transition in the page table management code.
# Our patch is for the old version that is phased out if this flag is set
options kvm tdp_mmu=0     
```
#### 4. Create and run an SEV VM
1. Create a disk for the VM with `./local-installation/usr/local/bin/qemu-img create -f qcow2 <VM_DISK.qcow2> 20G`
2. Start VM with `sudo ./launch-qemu.sh -hda <VM_DISK.qcow2> -cdrom <Ubuntu 22.10 iso> -vnc :1` where `<Ubuntu 22.10 iso>` is the path to the regular Ubuntu installation iso. While you can use other Distros, their SEV support might vary.
3. Connect to the VM via a VNC viewer on port `5901` and perform a standard installation.
4. Once the installation is done, terminate qemu with `ctrl a+x` or use `sudo kill $(pidof qemu-system-x86)`
5. Start the VM again and connect with VNC. Install the OpenSSH server and configure it to autostart.
6. Use `sudo ./launch-qemu.sh -hda <VM_DISK.qcow2> -sev-es` to start the VM with SEV-ES protection. You may need option `-mem <size>` to support bigger guest memory size in MB for benchmark.
7. Configure a static IP inside the VM. First, you run below command in Local
``` bash
sudo ip addr add 192.168.100.1/24 dev tap0
sudo ip link set tap0 up
```

Then, make 01-hostonly.yaml file in  `/etc/netplan/` inside the SEV VM. Below is the example code.
``` yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: no
      addresses: [192.168.100.2/24]
      gateway4: 192.168.100.1
      nameservers:
        addresses: [1.1.1.1, 8.8.8.8]
```
-  Then apply the configuration
- This makes the VM always use the same IP on that interface.
``` bash
sudo netplan apply
``` 

#### 5. Make cipherfix docker inside the VM for setting up the environment.

``` bash
sudo snap install docker

sudo docker run -it --name reenc [ghcr.io/uzl-its/cipherfix-examples-full:latest](http://ghcr.io/uzl-its/cipherfix-examples-full:latest)
```

### Step 4: Execution & Monitoring

The framework requires two components running concurrently: the hardened workload and the SEV controller for runtime monitoring.

**Terminal 1: (Local) Execute the Benchmarks after build**

```bash
# Navigate to the build directory and run the benchmark
# inside openfhe_development dir
mkdir build && cd build
cmake ..
make

# run benchmarks. its path is <openfhe_development>/build/bin/example/pke/ (e.g. <openfhe_development>/build/bin/example/pke/kmeans)

```

**Terminal 2: (SEV) Execute the SEV Controller**

```bash
# Run the controller to monitor and enforce security policies
# Controller appropriately executes re-encryption modules. It is implemented with hardcoded paths; modify them if needed.
# Usage: ./reenc_controller {PORT} {EXECUTION_LIMIT} {PATH}
./reenc_controller 8080 10000000 .

```

---



## 4. Artifact Package Inventory

| File / Directory | Description |
| --- | --- |
| `setup.sh` | Host-side dependency and environment setup script. |
| `mitigation_docker.sh` | All-in-one script for the mitigation and build pipeline. |
| `src_engine/` | Source code for the FHE engine. |
| `mitigation_scripts/` | Automation scripts for the hardening process. |
| `*.patch` | Constantine and Cipherfix mitigation patches. |
| `controller.c` | Source for the SEV runtime monitoring controller. |
| `cipherfix_interface.*` | Interface files for the Cipherfix mitigation. |

---
