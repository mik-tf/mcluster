# Guide: Deploy Ubuntu 24.04 Server with QEMU (4GB RAM)

This guide will help you set up Ubuntu Server 24.04 VMs using QEMU with 4GB RAM each, then access them to run commands.

## Prerequisites
- Linux host system with QEMU installed
- At least 8GB free RAM (for two VMs)
- 20GB+ free disk space

## Step 1: Download Ubuntu Server 24.04.2 ISO

```bash
mkdir -p /code/qemu_images
cd /code/qemu_images
wget https://ubuntu.com/download/server/thank-you?version=24.04.2&architecture=amd64&lts=true
```

## Step 2: Create Disk Images

```bash
# Create 10GB disk images for both VMs
qemu-img create -f qcow2 control-node.qcow2 10G
qemu-img create -f qcow2 managed-node.qcow2 10G
```

## Step 3: Install Ubuntu Server on Control Node VM

```bash
qemu-system-x86_64 \
  -hda control-node.qcow2 \
  -cdrom ubuntu-24.04.2-live-server-amd64.iso \
  -boot d \
  -m 4G \
  -enable-kvm \
  -smp 2 \
  -net nic \
  -net user,hostfwd=tcp::2222-:22
```

During installation:
1. Follow the Ubuntu Server installation prompts
2. Create a username/password you'll remember
3. Install OpenSSH server when prompted
4. Complete the installation and allow it to reboot
5. Shut down the VM after initial setup

## Step 4: Install Ubuntu Server on Managed Node VM

```bash
qemu-system-x86_64 \
  -hda managed-node.qcow2 \
  -cdrom ubuntu-24.04.2-live-server-amd64.iso \
  -boot d \
  -m 4G \
  -enable-kvm \
  -smp 2 \
  -net nic \
  -net user,hostfwd=tcp::2223-:22
```

Follow the same installation steps as with the control node.

## Step 5: Boot the VMs (Post-Installation)

### Start Control Node:
```bash
qemu-system-x86_64 \
  -hda control-node.qcow2 \
  -m 4G \
  -enable-kvm \
  -smp 2 \
  -net nic \
  -net user,hostfwd=tcp::2222-:22
```

### Start Managed Node:
```bash
qemu-system-x86_64 \
  -hda managed-node.qcow2 \
  -m 4G \
  -enable-kvm \
  -smp 2 \
  -net nic \
  -net user,hostfwd=tcp::2223-:22
```

## Step 6: Access the VMs

### Method 1: Direct Console Access
You can interact directly with the VM through the QEMU window that appears.

### Method 2: SSH Access (Recommended)
For control node:
```bash
ssh -p 2222 yourusername@localhost
```

For managed node:
```bash
ssh -p 2223 yourusername@localhost
```

## Step 7: Run Commands in the VM

Once connected to a VM, you can run any Ubuntu commands:

```bash
# Update package lists
sudo apt update

# Upgrade packages
sudo apt upgrade -y

# Check system info
uname -a

# Check disk space
df -h

# Check memory usage
free -m
```

## Additional Options

### Headless Mode (No GUI)
Add `-nographic` to the QEMU command to run without a window:

```bash
qemu-system-x86_64 -hda control-node.qcow2 -m 4G -enable-kvm -nographic -net nic -net user,hostfwd=tcp::2222-:22
```

To exit from the QEMU monitor in headless mode, press `Ctrl+a` then `x`.

### VNC Access
```bash
qemu-system-x86_64 -hda control-node.qcow2 -m 4G -enable-kvm -display none -vnc :0
```

Then connect with a VNC viewer to `localhost:5900`.

## Troubleshooting

- If KVM acceleration doesn't work, you might need to enable virtualization in BIOS/UEFI
- If port forwarding fails, try different ports (e.g., 2200, 2201)
- If you can't SSH, ensure the SSH server was installed during Ubuntu setup

Now you have two Ubuntu Server 24.04 VMs running with 4GB RAM each, accessible either through the console or SSH.