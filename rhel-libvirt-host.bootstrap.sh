#!/bin/bash

## Uncomment for step debugging
#set -e

########################################################################################################################
##
## Libvirt Host Bootstrap Script
##
## This script will set up a physical host to be used as a lab environment to simulate a disconnected OpenShift Assisted
## Installer Service environment and create a Mirror VM to sit inbetween the isolated and public subnets.
##
## If deploying the Mirror VM to another infrastructure platform then this script can be skipped - all that's needed by
## the end of this script is a RHEL 8.5 VM that can act as the Mirror VM.  If you're sneakernetting the content then
## the architecture will required to RHEL 8.5 hosts to act as the Mirror VMs on either side of the demarc.
##
## Prerequisites:
##
## - The hypervisor host must be running RHEL 8.4+ and already subscribed to RHSM/Satellite
## - The hypervisor host must have a working network connection to the internet with at least one bridged physical interface
## - The hypervisor host must be configured with SELinux disabled (this can be corrected with a different work directory)
##
## Execution Steps:
##
## - Take in variables, generate a hashed password for the root user
## - Define some functions
## - Preflight checks, verify that the host can run virtualized workloads
## - Update the system and install the required packages, enable services
## - Create a working directory
## - Create two Libvirt Networks, one bridged to the physical hosts' network and one isolated from other networks
## - Create a VM via Kickstart for the Mirror VM with two NICs, one in each network
## - Wait for the VM to shutdown, start it, and wait for it to be ready for SSH connections
## - [Optional] Create a GUI Bastion VM in the disconnected environment with VNC access from the Libvirt host
##
########################################################################################################################

########################################################################################################################
## Set needed variables

# WORK_DIR is the path to a directory where some generated assets can be stored on the physical host
WORK_DIR="/mnt/remoteWork/offline-ai"

# RHEL_85_ISO_PATH is the path to the RHEL 8.5 ISO on the physical host - this is the ISO that will be used to install the Mirror VM
RHEL_85_ISO_PATH="/mnt/nfs-isos/rhel8.5.iso"

# BRIDGE_IFACE is the name of your physically bridged interface (pre-network setup, create a bridge0 from your eth0)
BRIDGE_IFACE="bridge0"

## Mirror VM Variables
MIRROR_VM_HOSTNAME="mirror-vm"

# MIRROR_VM_ROOT_PW_HASH is the password hash for the root user - ideally replace aSecurePassword
MIRROR_VM_ROOT_PW_HASH=$(python3 -c "import crypt;print(crypt.crypt('aSecurePassword', crypt.mksalt(crypt.METHOD_SHA512)))")

# MIRROR_VM_BRIDGE_IFACE_IP is the IP address of the NIC on the Mirror VM that is in the connected network
MIRROR_VM_BRIDGE_IFACE_IP="192.168.42.7"
MIRROR_VM_BRIDGE_IFACE_GATEWAY="192.168.42.1"
MIRROR_VM_BRIDGE_IFACE_NETMASK="255.255.255.0"
MIRROR_VM_BRIDGE_IFACE_DNS="192.168.42.9"

# The following defines the virtual internal network that is used for the disconnected network
ISOLATED_NETWORK_SUBNET="192.168.50.0"
ISOLATED_NETWORK_CIDR="${ISOLATED_NETWORK_SUBNET}/24"
ISOLATED_NETWORK_GATEWAY="192.168.50.1"
ISOLATED_NETWORK_NETMASK="255.255.255.0"
ISOLATED_NETWORK_START_RANGE="192.168.50.100"
ISOLATED_NETWORK_END_RANGE="192.168.50.254"

# MIRROR_VM_ISOLATED_NETWORK_IFACE_IP is the IP address of the NIC on the Mirror VM that is in the disconnected isolated network
MIRROR_VM_ISOLATED_NETWORK_IFACE_IP="192.168.50.7"

## GUI Bastion VM Variables
DEPLOY_GUI_BASTION="true"
GUI_BASTION_HOSTNAME="bastion"

# GUI_BASTION_ISOLATED_NETWORK_IFACE_IP is the IP address of the NIC on the GUI Bastion VM that is in the disconnected isolated network
GUI_BASTION_ISOLATED_NETWORK_IFACE_IP="192.168.50.6"

# GUI_BASTION_ROOT_PW_HASH is the password hash for the root user on the GUI Bastion VM - ideally replace aSecurePassword
GUI_BASTION_ROOT_PW_HASH=$(python3 -c "import crypt;print(crypt.crypt('aSecurePassword', crypt.mksalt(crypt.METHOD_SHA512)))")

LOG_FILE="${WORK_DIR}/rhel-libvirt-host.bootstrap.$(date '+%s').log"

########################################################################################################################
## Global Functions
function checkForProgramAndInstallOrExit() {
    command -v $1 > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf '%-72s %-7s\n' $1 "PASSED!";
    else
        printf '%-72s %-7s\n' $1 "NOT FOUND!";
        echo "Attempting to install $1 via $2..."
        sudo yum install -y $2
        if [[ $? -eq 0 ]]; then
            printf '%-72s %-7s\n' $1 "PASSED!";
        else
            printf '%-72s %-7s\n' $1 "FAILED!";
            exit 1
        fi
    fi
}

########################################################################################################################
## Preflight

mkdir -p $(dirname $LOG_FILE)

echo -e "\n===== Running Preflight..." 2>&1 | tee -a $LOG_FILE

## Create a working directory
echo "  Creating working directory..." 2>&1 | tee -a $LOG_FILE
mkdir -p $WORK_DIR/libvirt/vms

## Check if you have virtualization enabled - if nothing is returned then virtualization is disabled
VIRT_TEST=$(cat /proc/cpuinfo | egrep "vmx|svm" | wc -l)
if [[ $VIRT_TEST -eq 0 ]]; then
  echo "  Virtualization is not enabled on this host.  Please enable it and try again." 2>&1 | tee -a $LOG_FILE
  exit 1
else
  echo "  Virtualization is enabled on this host..." 2>&1 | tee -a $LOG_FILE
fi

## Update base system
echo "  Updating base system packages..." 2>&1 | tee -a $LOG_FILE
dnf update -y &>> $LOG_FILE

## Install libvirt
#dnf install @virt -y
echo "  Checking for Libvirt..." 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit virsh "@virt" &>> $LOG_FILE

## Install Python
#dnf install python3 -y
echo "  Checking for Python..." 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit python3 python3 &>> $LOG_FILE

## Install supporting tools [optional]
echo "  Checking for Tools..." 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit socat socat &>> $LOG_FILE
checkForProgramAndInstallOrExit virt-top virt-top &>> $LOG_FILE
checkForProgramAndInstallOrExit guestfish libguestfs-tools &>> $LOG_FILE

dnf install libvirt-devel cockpit-machines -y &>> $LOG_FILE

## Enable Cockpit [optional]
echo "  Enabling Services..." 2>&1 | tee -a $LOG_FILE
systemctl enable --now cockpit.socket &>> $LOG_FILE

## Enable Libvirt
systemctl enable --now libvirtd &>> $LOG_FILE

echo -e "\n===== Preflight Complete!\n" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Libvirt Networking

## Get the current Libvirt networks
LIBVIRT_NETWORKS=$(virsh net-list --all --name)

if [[ ! "${LIBVIRT_NETWORKS[*]}" =~ "isolatedNet" ]]; then
  ## Create disconnected network - make sure the subnet isn't overlapping in your actual networks, and limit the DHCP range to use static IPs outside the range
  echo "===== Creating Isolated Libvirt Network..." 2>&1 | tee -a $LOG_FILE
  cat > $WORK_DIR/libvirt/disconnected-network.xml << EOF
<network>
  <name>isolatedNet</name>
  <bridge name="virbr50"/>
  <ip address="$ISOLATED_NETWORK_GATEWAY" netmask="$ISOLATED_NETWORK_NETMASK">
    <dhcp>
      <range start="$ISOLATED_NETWORK_START_RANGE" end="$ISOLATED_NETWORK_END_RANGE"/>
    </dhcp>
  </ip>
</network>
EOF
  virsh net-define $WORK_DIR/libvirt/disconnected-network.xml &>> $LOG_FILE
  virsh net-start isolatedNet &>> $LOG_FILE
  virsh net-autostart isolatedNet &>> $LOG_FILE
else
  echo "===== Isolated Libvirt Network already exists..." 2>&1 | tee -a $LOG_FILE
fi

if [[ ! "${LIBVIRT_NETWORKS[*]}" =~ "lanBridge" ]]; then
  ## Create bridged network
  echo "===== Creating Bridged Libvirt Network..." 2>&1 | tee -a $LOG_FILE
  cat > $WORK_DIR/libvirt/bridged-network.xml << EOF
<network>
  <name>lanBridge</name>
  <forward mode="bridge"/>
  <bridge name="$BRIDGE_IFACE"/>
</network>
EOF
  virsh net-define $WORK_DIR/libvirt/bridged-network.xml &>> $LOG_FILE
  virsh net-start lanBridge &>> $LOG_FILE
  virsh net-autostart lanBridge &>> $LOG_FILE
else
  echo "===== Bridged Libvirt Network already exists..." 2>&1 | tee -a $LOG_FILE
fi

########################################################################################################################
## Create the Mirror VM

## Get the current Libvirt VMSs
LIBVIRT_DOMAINS=$(virsh list --all --name)

if [[ ! "${LIBVIRT_DOMAINS[*]}" =~ "$MIRROR_VM_HOSTNAME" ]]; then
  ## Create a Kickstart File
  echo "===== Creating a Kickstart file for the Mirror VM..." 2>&1 | tee -a $LOG_FILE
  cat > $WORK_DIR/libvirt/kickstart.$MIRROR_VM_HOSTNAME.cfg << EOF
lang en_US
keyboard us
timezone America/New_York --isUtc
network --device=enp1s0 --bootproto=static --ip=$MIRROR_VM_BRIDGE_IFACE_IP --netmask=$MIRROR_VM_BRIDGE_IFACE_NETMASK --gateway=$MIRROR_VM_BRIDGE_IFACE_GATEWAY --nameserver=$MIRROR_VM_BRIDGE_IFACE_DNS
network --device=enp2s0 --bootproto=static --ip=$MIRROR_VM_ISOLATED_NETWORK_IFACE_IP --netmask=$ISOLATED_NETWORK_NETMASK --gateway=$ISOLATED_NETWORK_GATEWAY --nameserver=$MIRROR_VM_ISOLATED_NETWORK_IFACE_IP
network --hostname=$MIRROR_VM_HOSTNAME

rootpw $MIRROR_VM_ROOT_PW_HASH --iscrypted
#platform x86_64
reboot --eject
eula --agreed
text --non-interactive
cdrom
bootloader --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart --type=lvm --nohome
auth --passalgo=sha512 --useshadow
selinux --permissive
firewall --disabled
skipx
firstboot --disable

%packages
@^minimal-environment
kexec-tools
curl
jq
cockpit
cockpit-podman
podman
skopeo
nano
nfs-utils
bash-completion
bind-utils
httpd-tools
tar
tmux
%end

services --enabled="sshd"
services --enabled="cockpit.socket"
EOF

  ## Create the Mirror VM
  echo "===== Creating the Mirror VM..." 2>&1 | tee -a $LOG_FILE
  virt-install --name=$MIRROR_VM_HOSTNAME \
  --vcpus "sockets=1,cores=2,threads=1" --memory="8192" \
  --disk "size=1024,path=$WORK_DIR/libvirt/vms/$MIRROR_VM_HOSTNAME.qcow2,cache=none,format=qcow2" \
  --location $RHEL_85_ISO_PATH \
  --network network=lanBridge,model=virtio \
  --network network=isolatedNet,model=virtio \
  --console pty,target_type=serial \
  --os-type linux --os-variant=rhel8.5 \
  --controller type=scsi,model=virtio-scsi \
  --hvm --virt-type kvm --features kvm_hidden=on \
  --graphics vnc,listen=0.0.0.0,tlsport=,defaultMode='insecure' \
  --memballoon none --cpu host-passthrough --autostart --noautoconsole --events on_reboot=restart \
  --initrd-inject $WORK_DIR/libvirt/kickstart.$MIRROR_VM_HOSTNAME.cfg \
  --extra-args "inst.ks=file://kickstart.$MIRROR_VM_HOSTNAME.cfg console=tty0 console=ttyS0,115200n8" &>> $LOG_FILE

else
  echo "===== Mirror VM already exists..." 2>&1 | tee -a $LOG_FILE
fi

########################################################################################################################
## Create the GUI Bastion VM
if [ "$DEPLOY_GUI_BASTION" == "true" ]; then

  ## Get the current Libvirt VMSs
  LIBVIRT_DOMAINS=$(virsh list --all --name)

  if [[ ! "${LIBVIRT_DOMAINS[*]}" =~ "$GUI_BASTION_HOSTNAME" ]]; then
    ## Create a Kickstart File
    echo "===== Creating a Kickstart file for the GUI Bastion VM..." 2>&1 | tee -a $LOG_FILE
    cat > $WORK_DIR/libvirt/kickstart.$GUI_BASTION_HOSTNAME.cfg << EOF
lang en_US
keyboard us
timezone America/New_York --isUtc
network --device=enp1s0 --bootproto=static --ip=$GUI_BASTION_ISOLATED_NETWORK_IFACE_IP --netmask=$ISOLATED_NETWORK_NETMASK --gateway=$ISOLATED_NETWORK_GATEWAY --nameserver=$MIRROR_VM_ISOLATED_NETWORK_IFACE_IP
network --hostname=$GUI_BASTION_HOSTNAME

rootpw $GUI_BASTION_ROOT_PW_HASH --iscrypted
#platform x86_64
reboot --eject
eula --agreed
text --non-interactive
cdrom
bootloader --append="rhgb quiet crashkernel=auto"
zerombr
clearpart --all --initlabel
autopart --type=lvm --nohome
auth --passalgo=sha512 --useshadow
selinux --permissive
firewall --disabled
firstboot --disable

%packages
@^graphical-server-environment
kexec-tools
curl
jq
cockpit
nano
bash-completion
bind-utils
tar
tmux
firefox
%end

services --enabled="sshd"
services --enabled="cockpit.socket"
EOF

  ## Create the GUI Bastion VM
  echo "===== Creating the GUI Bastion VM..." 2>&1 | tee -a $LOG_FILE
  virt-install --name=$GUI_BASTION_HOSTNAME \
  --vcpus "sockets=1,cores=2,threads=1" --memory="8192" \
  --disk "size=30,path=$WORK_DIR/libvirt/vms/$GUI_BASTION_HOSTNAME.qcow2,cache=none,format=qcow2" \
  --location $RHEL_85_ISO_PATH \
  --network network=isolatedNet,model=virtio \
  --console pty,target_type=serial \
  --os-type linux --os-variant=rhel8.5 \
  --controller type=scsi,model=virtio-scsi \
  --hvm --virt-type kvm --features kvm_hidden=on \
  --graphics vnc,listen=0.0.0.0,tlsport=,defaultMode='insecure' \
  --memballoon none --cpu host-passthrough --autostart --noautoconsole --events on_reboot=restart \
  --initrd-inject $WORK_DIR/libvirt/kickstart.$GUI_BASTION_HOSTNAME.cfg \
  --extra-args "inst.ks=file://kickstart.$GUI_BASTION_HOSTNAME.cfg console=tty0 console=ttyS0,115200n8" &>> $LOG_FILE
  
  else
    echo "===== Mirror VM already exists..." 2>&1 | tee -a $LOG_FILE
  fi
fi

########################################################################################################################
## Wait for the Mirror VM

## virt-install kinda fakes the reboot when it stays connected to the VM console, so we need to wait for the VM to be shutdown when using --noautoconsole
if [ -z "$( socat -T2 stdout tcp:${MIRROR_VM_BRIDGE_IFACE_IP}:22,connect-timeout=2,readbytes=1 2>/dev/null )" ]; then
  echo -e "\n===== Waiting for Mirror VM to install and shutdown..." 2>&1 | tee -a $LOG_FILE
  LOOP_ON="true"
  while [ "$LOOP_ON" == "true" ]; do
    STOPPED_VMS=$(virsh list --state-shutoff --name)
    if [[ ! "${STOPPED_VMS[*]}" =~ "$MIRROR_VM_HOSTNAME" ]]; then
      echo "  Mirror VM has not installed and shutdown yet! Waiting 30s..." 2>&1 | tee -a $LOG_FILE
      sleep 30
    else
      echo "  Mirror VM has installed and shutdown!" 2>&1 | tee -a $LOG_FILE
      echo "  Starting Mirror VM..." 2>&1 | tee -a $LOG_FILE
      virsh start $MIRROR_VM_HOSTNAME &>> $LOG_FILE
      LOOP_ON="false"
    fi
  done
fi

echo "===== Waiting for Mirror VM to boot and be accessible..." 2>&1 | tee -a $LOG_FILE
while [ -z "$( socat -T2 stdout tcp:${MIRROR_VM_BRIDGE_IFACE_IP}:22,connect-timeout=2,readbytes=1 2>/dev/null )" ]; do
  echo "  Mirror VM is not accessible yet! Waiting 10s..." 2>&1 | tee -a $LOG_FILE
  sleep 10
done

echo -e "\n===== Mirror VM is online!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Wait for the GUI Bastion VM
if [ "$DEPLOY_GUI_BASTION" == "true" ]; then

  ## virt-install kinda fakes the reboot when it stays connected to the VM console, so we need to wait for the VM to be shutdown when using --noautoconsole
  if [ -z "$( socat -T2 stdout tcp:${GUI_BASTION_ISOLATED_NETWORK_IFACE_IP}:22,connect-timeout=2,readbytes=1 2>/dev/null )" ]; then
    echo -e "\n===== Waiting for GUI Bastion VM to install and shutdown..." 2>&1 | tee -a $LOG_FILE
    LOOP_ON="true"
    while [ "$LOOP_ON" == "true" ]; do
      STOPPED_VMS=$(virsh list --state-shutoff --name)
      if [[ ! "${STOPPED_VMS[*]}" =~ "$GUI_BASTION_HOSTNAME" ]]; then
        echo "  GUI Bastion VM has not installed and shutdown yet! Waiting 30s..." 2>&1 | tee -a $LOG_FILE
        sleep 30
      else
        echo "  GUI Bastion VM has installed and shutdown!" 2>&1 | tee -a $LOG_FILE
        echo "  Starting GUI Bastion VM..." 2>&1 | tee -a $LOG_FILE
        virsh start $GUI_BASTION_HOSTNAME &>> $LOG_FILE
        LOOP_ON="false"
      fi
    done
  fi

  echo "===== Waiting for GUI Bastion VM to boot and be accessible..." 2>&1 | tee -a $LOG_FILE
  while [ -z "$( socat -T2 stdout tcp:${GUI_BASTION_ISOLATED_NETWORK_IFACE_IP}:22,connect-timeout=2,readbytes=1 2>/dev/null )" ]; do
    echo "  GUI Bastion VM is not accessible yet! Waiting 10s..." 2>&1 | tee -a $LOG_FILE
    sleep 10
  done

  echo -e "\n===== GUI Bastion VM is online!" 2>&1 | tee -a $LOG_FILE
fi

echo -e "\n===== RHEL Libvirt Lab bootstrapping complete!" 2>&1 | tee -a $LOG_FILE