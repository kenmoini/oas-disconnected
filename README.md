# Disconnected OpenShift Assisted Service

> This is a massive work-in-progress, a few things are missing

This set of scripts will allow you to mirror OpenShift and the OpenShift Assisted Installer Service to be deploy into a disconnected environment.  ***Includes turn-key Libvirt lab.***

## Prerequisites

- An **OpenShift Pull Secret** which is used to pull the needed containers from Quay and the Red Hat Registry - https://console.redhat.com/openshift/downloads#tool-pull-secret
- A **Red Hat API Offline Token**, used to interact with the Red Hat Hybrid Console hosted Assisted Installer Service - https://access.redhat.com/management/api
- A **Red Hat Enterprise Linux 8.4+** Subscription and the downloaded ISO to create Mirror VMs from - you can get free RHEL subscriptions via the Developer Subscription, assuming your use case is eligible: https://developers.redhat.com/about

## Lab & Modeled Architecture

In disconnected environments, it's assumed there's a transfer of data from an Internet-connected host that downloads and composes all the needed assets and services needed, packaging up these assets to be transfered in one way or another to a system on a disconnected or isolated network that will then mirror and serve to the systems in this disconnected environment.  This action requires two systems - one in the connected and one in the disconnected environment.

Alternatively, you could use an intermediary system that sits between the different networks - that is what is modeled in the demo Libvirt lab that accompanies this repository.

INSERT VIZ

Ultimately, at the end of the day for truely disconnected environments where data is Sneakernet'd physically across a low-side DMZ and a high-side secure network you'll need at least two RHEL systems to mirror the content and then serve it.

There are scripts that can bootstrap both of these architectures.

---

## Script Directory

### `rhel-libvirt-host.bootstrap.sh`

***Optional turn-key Libvirt Lab***

This script will set up a RHEL 8 host as a hypervisor with Libvirt/KVM.  It will install the needed packages, enable services, and create a Libvirt Network that is bridged to your physical interface.  This is an ***optional*** script and is not needed unless you are performing this as a lab.  The end result is just a Mirror VM that sits between your host's physical network and a virtual disconnected/isolated network.

#### Prerequisites:

- The hypervisor host must be running RHEL 8.4+ and already subscribed to RHSM/Satellite
- The hypervisor host must have a working network connection to the internet with at least one bridged physical interface
- The hypervisor host must be configured with SELinux disabled (this can be corrected with a different work directory)

#### Execution Steps:

- Take in variables, generate a hashed password for the root user
- Define some functions
- Preflight checks, verify that the host can run virtualized workloads
- Update the system and install the required packages, enable services
- Create a working directory
- Create two Libvirt Networks, one bridged to the physical hosts' network and one isolated from other networks
- Create a VM via Kickstart for the Mirror VM with two NICs, one in each network
- Wait for the VM to shutdown, start it, and wait for it to be ready for SSH connections
- [Optional] Create a GUI Bastion VM in the disconnected environment with VNC access from the Libvirt host

### `mirror-vm.preflight.sh`

With just a few variables defined, the `mirror-vm.preflight.sh` script will set up a brand new RHEL 8 system with the following steps:

- Start logging to a file
- Set the hostname
- [Optional] Register to RHSM and enable the codeready-builder-for-rhel-8-x86_64-rpms repo
- [Optional] Update the system
- [Optional] Extend the root logical volume and partition
- [Optional] Set up a bridged network interface for container pods to access IP space in an isolated network, configure systemd-resolved
- [Optional] Install Python3 and Ansible, useful for also mirroring/running automation that leverages the Assisted Installer such [Libvirt](https://github.com/kenmoini/ocp4-ai-svc-libvirt) and [Nutanix](https://github.com/kenmoini/ocp4-ai-svc-nutanix) Ansible collection options
- [Optional] Reboot

### `disconnected-oas.unified.bootstrap.sh`

This script will perform all the needed steps to mirror OpenShift releases, the Operator Catalog, and Assisted Service components into a disconnected environment.

### `disconnected-oas.low-side.bootstrap.sh`

WIP, can be split out from unified bootstrap script as soon as it is complete

### `disconnected-oas.high-side.bootstrap.sh`

WIP, can be split out from unified bootstrap script as soon as it is complete

---

## Helpful Links & Tools

- **RHEL Kickstart Generator**: https://access.redhat.com/labs/kickstartconfig/
- **Red Hat Hybrid Console hosted Assisted Installer Service**: https://console.redhat.com/openshift/assisted-installer/clusters