#!/bin/bash

# Uncomment for debugging
#set -e

MIRROR_VM_HOSTNAME="mirror-vm"

REGISTER_TO_RHSM="true"
UPDATE_SYSTEM="true"
INSTALL_ANSIBLE="true"
CONFIGURE_UNPRIVILEGED_PORT="true"
EXTEND_ROOT_FS="true"
REBOOT_AFTER_SETUP="false"

## If there is a NIC you want to create a bridge for set the following to true
CONFIGURE_NETWORKING="true"
# MIRROR_VM_ISOLATED_BRIDGE_IFACE is the name of your bridged interface (pre-network setup, create a bridge0 from your eth1 in the isolated network)
MIRROR_VM_ISOLATED_BRIDGE_IFACE="bridge0"
# MIRROR_VM_ISOLATED_BRIDGE_DEVICE is the name of the physical interface that is bridged
MIRROR_VM_ISOLATED_BRIDGE_DEVICE="enp2s0"

ISOLATED_NETWORK_DOMAIN="isolated.local"

LOG_FILE="/var/log/mirror-vm.preflight-$(date '+%s').log"

########################################################################################################################
##
## Mirror VM Preflight Script
##
## This script will setup a RHEL 8 host with a hostname, registration to RHSM, base update, some packages, and a reboot
##
########################################################################################################################

mkdir -p $(dirname $LOG_FILE)

## Set the Hostname
if [ ! -z "$MIRROR_VM_HOSTNAME" ]; then
  echo "===== Setting Hostname..." 2>&1 | tee -a $LOG_FILE
  hostnamectl set-hostname $MIRROR_VM_HOSTNAME &>> $LOG_FILE
fi

## Register to RHSM
if [ "$REGISTER_TO_RHSM" == "true" ]; then
  echo "===== Registering to RHSM..." 2>&1 | tee -a $LOG_FILE
  subscription-manager register
  subscription-manager auto-attach

  ## Enable Repos
  echo "===== Enabling repos..." 2>&1 | tee -a $LOG_FILE
  subscription-manager repos --enable codeready-builder-for-rhel-8-x86_64-rpms &>> $LOG_FILE
fi

## Do a base update
if [ "$UPDATE_SYSTEM" == "true" ]; then
  echo "===== Performing system update..." 2>&1 | tee -a $LOG_FILE
  dnf update -y &>> $LOG_FILE
fi

if [ "$CONFIGURE_UNPRIVILEGED_PORT" == "true" ]; then
  echo "===== Setting lower unprivileged ports..." 2>&1 | tee -a $LOG_FILE
  echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start
fi

## Extend the root partition
if [ "$EXTEND_ROOT_FS" == "true" ]; then
  echo "===== Extending root logical volume and partition..." 2>&1 | tee -a $LOG_FILE
  ## Find the name of the root LV
  ROOT_LV=$(lvs --noheadings -o lv_path | grep 'root' | sed -e 's/^[[:space:]]*//')
  lvextend -l +100%FREE $ROOT_LV &>> $LOG_FILE
  xfs_growfs $ROOT_LV &>> $LOG_FILE
fi

## Create a bridge attached to the NIC in the isolated network to allow Containers/Pods to pull IPs from the Isolated network space
if [ "$CONFIGURE_NETWORKING" == "true" ]; then
  #BRIDGE_DEVICE_CIDR=$(ip a show dev enp1s0 | grep 'inet ' | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2)
  #BRIDGE_DEVICE_IP=$(echo "$BRIDGE_DEVICE_CIDR" | cut -d '/' -f 1)
  #BRIDGE_DEVICE_CIDR_SUBNET=$(echo "$BRIDGE_DEVICE_CIDR" | cut -d '/' -f 2)
  #BRIDGE_DEVICE_INFO=$(cat /etc/sysconfig/network-scripts/ifcfg-enp1s0)
  #BRIDGE_DEVICE_LIST=$(nmcli device status | grep "$MIRROR_VM_ISOLATED_BRIDGE_IFACE")

  if [ -z "$(nmcli device status | grep "$MIRROR_VM_ISOLATED_BRIDGE_IFACE")" ]; then
    echo "===== Creating bridge device..." 2>&1 | tee -a $LOG_FILE
    source /etc/sysconfig/network-scripts/ifcfg-${MIRROR_VM_ISOLATED_BRIDGE_DEVICE}
    # Create the bridge
    nmcli con add type bridge con-name $MIRROR_VM_ISOLATED_BRIDGE_IFACE ifname $MIRROR_VM_ISOLATED_BRIDGE_IFACE &>> $LOG_FILE
    # Configure the bridge
    nmcli con mod $MIRROR_VM_ISOLATED_BRIDGE_IFACE ipv4.dns $DNS1 ipv4.gateway $GATEWAY ipv4.addresses "${IPADDR}/${PREFIX}" ipv4.dns-search "$ISOLATED_NETWORK_DOMAIN" ipv4.method manual connection.autoconnect yes connection.autoconnect-slaves yes &>> $LOG_FILE
    # Add the physical device
    nmcli con add type bridge-slave ifname $MIRROR_VM_ISOLATED_BRIDGE_DEVICE master $MIRROR_VM_ISOLATED_BRIDGE_IFACE &>> $LOG_FILE
    # Bring the connection up
    nmcli con up $MIRROR_VM_ISOLATED_BRIDGE_IFACE &>> $LOG_FILE
    # Delete the old one
    nmcli con delete $MIRROR_VM_ISOLATED_BRIDGE_DEVICE &>> $LOG_FILE
  fi

  ## Set up mutli-DNS resolution: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/using-different-dns-servers-for-different-domains_configuring-and-managing-networking
  ## Check for dns=systemd-resolved
  if [ -z "$(grep 'dns=systemd-resolved' /etc/NetworkManager/NetworkManager.conf)" ]; then
    echo "===== Setting DNS Resolution..." 2>&1 | tee -a $LOG_FILE
    NM_MAIN_CONF_LINE_NO=$(grep -n "\[main\]" /etc/NetworkManager/NetworkManager.conf | grep -Eo '^[^:]+')
    NM_MAIN_AFTER_CONF_LINE_NO=$(( $NM_MAIN_CONF_LINE_NO + 1))

    NM_CONFIG_HEAD=$(head -n $NM_MAIN_CONF_LINE_NO /etc/NetworkManager/NetworkManager.conf)
    NM_CONFIG_TAIL=$(tail -n +$NM_MAIN_AFTER_CONF_LINE_NO /etc/NetworkManager/NetworkManager.conf)
    
    cp /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf.bak-$(date '+%s')

    echo "$NM_CONFIG_HEAD" > /etc/NetworkManager/NetworkManager.conf
    echo 'dns=systemd-resolved' >> /etc/NetworkManager/NetworkManager.conf
    echo "$NM_CONFIG_TAIL" >> /etc/NetworkManager/NetworkManager.conf

    ## Start and enable the systemd-resolved service
    systemctl --now enable systemd-resolved &>> $LOG_FILE

    systemctl reload NetworkManager &>> $LOG_FILE
  fi
fi

## Optional: Install needed packages for Python3 and Ansible
if [ "$INSTALL_ANSIBLE" == "true" ]; then
  echo "===== Installing Python3 and Ansible..." 2>&1 | tee -a $LOG_FILE
  dnf install -y "@Development Tools" cmake expect cargo rust python3-devel python3-pip python3-setuptools openssl-devel git &>> $LOG_FILE
  python3 -m pip install --upgrade pip setuptools wheel &>> $LOG_FILE
  python3 -m pip install ansible paramiko &>> $LOG_FILE
fi

## Reboot since it probably loaded a new kernel
if [ "$REBOOT_AFTER_SETUP" == "true" ]; then
  echo "===== Rebooting..." 2>&1 | tee -a $LOG_FILE
  systemctl reboot
fi