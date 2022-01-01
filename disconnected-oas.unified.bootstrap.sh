#!/bin/bash

## Uncomment for step debugging
#set -e

########################################################################################################################
## Disconnected OpenShift Assisted Installer Service, Unified Bootstrap Script
##
## This script will set up a RHEL 8 host with all the needed prerequisites to mirror all the needed components for
## deploying OpenShift in a disconnected environment, along with everything needed to run the OpenShift Assisted
## Installer Service.
##
## This script assumes that this host is connected to both the isolated network and the internet.  For separate low-side
## and high-side networks, see the disconnected-oas.low-side.bootstrap.sh and 
## disconnected-oas.high-side.bootstrap.sh scripts.
##
## Prerequisites:
##
## - The host must be running RHEL 8.4+ and already subscribed to RHSM/Satellite, etc - see mirror-vm.preflight.sh
## - 
## - 
########################################################################################################################

########################################################################################################################
## Set needed variables

## MIRROR_DIR is the directory where the mirrored data is located
export MIRROR_DIR="/opt/offline-ai"

## Setting ONLY_MIRROR_DEFAULT_VERSION to true will limit the mirrored data to only the default version instead of all the versions serviced by the AI service
export ONLY_MIRROR_DEFAULT_VERSION="true"

# RH_API_OFFLINE_TOKEN_PATH is the token generated from this page: https://access.redhat.com/management/api
export RH_API_OFFLINE_TOKEN_PATH="/opt/rh-api-offline-token"
# PULL_SECRET_PATH is the RH OpenShift Pull Secret from here: https://console.redhat.com/openshift/downloads#tool-pull-secret
export PULL_SECRET_PATH="/opt/ocp-pull-secret"

export ISOLATED_NETWORK_DOMAIN="isolated.local"
export ISOLATED_NETWORK_SUBNET="192.168.50.0"
export ISOLATED_NETWORK_CIDR="${ISOLATED_NETWORK_SUBNET}/24"
export ISOLATED_NETWORK_GATEWAY="192.168.50.1"
export ISOLATED_NETWORK_START_RANGE="192.168.50.2"
export ISOLATED_NETWORK_END_RANGE="192.168.50.254"

## Service Network Information
## AI Pod
export ISOLATED_AI_SVC_ENDPOINT="assisted-installer"

export ISOLATED_AI_SVC_WEB_UI_HOSTNAME="ai-web-ui"
export ISOLATED_AI_SVC_WEB_UI_IP="192.168.50.10"

export ISOLATED_AI_SVC_API_HOSTNAME="ai-api"
export ISOLATED_AI_SVC_API_IP="192.168.50.11"

export ISOLATED_AI_SVC_DB_HOSTNAME="ai-db"
export ISOLATED_AI_SVC_DB_IP="192.168.50.12"

export ISOLATED_AI_SVC_IMAGE_HOSTNAME="ai-image"
export ISOLATED_AI_SVC_IMAGE_IP="192.168.50.15"

## Ingress Pods
export ISOLATED_AI_SVC_HAPROXY_IP="192.168.50.13"
export ISOLATED_AI_SVC_NGINX_IP="192.168.50.14"

## Mirror VM Variables

# MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP is the IP address of the NIC on the Mirror VM that is in the disconnected isolated network
export MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP="192.168.50.7"

# MIRROR_VM_ISOLATED_BRIDGE_IFACE is the name of your bridged interface (pre-network setup, create a bridge0 from your eth1 in the isolated network)
export MIRROR_VM_ISOLATED_BRIDGE_IFACE="bridge0"

# MIRROR_VM_BRIDGE_IFACE_IP is the IP address of the NIC on the Mirror VM that is in the connected network
export MIRROR_VM_BRIDGE_IFACE_IP="192.168.42.7"

export MIRROR_VM_HOSTNAME="mirror-vm"
export DISABLE_FIREWALLD="true"
export DISABLE_SELINUX="true"

export MIRROR_CONTAINER_REGISTRY_USER="openshift-release-dev+admin"
export MIRROR_CONTAINER_REGISTRY_PASS="Passw0rd123"

## If moving to a different host in a different network then this can automatically set up the needed packages
export PACKAGE_AND_COMPRESS_ASSETS="true"
## Can use either 7ZIP or TAR to compress the assets - TAR requires 3x the disk space where 7Zip only 2x.
## > Keep in mind each mirrored OpenShift release can require about 500GB of disk space
## P7ZIP package is provided by RPMs downloaded manually from EPEL - otherwise use tar
export MIRROR_COMPRESS_ARCHIVER="7zip" # Can be 'tar' or '7zip'
export MIRROR_COMPRESS_SPLIT_SIZE="1024" # MB

########################################################################################################################
## PKI Variables - Do not modify unless you know what you're doing
## Certificate Authority DN Variables
export PKI_CA_COUNTRY="US"
export PKI_CA_STATE="North Carolina"
export PKI_CA_CITY="Raleigh"
export PKI_CA_ORG="Mirrors R Us"
export PKI_CA_ORG_UNIT="Security"
export PKI_CA_COMMON_NAME="MirrorsCA"

## Registry & Wildcard Server Certificate DN Variables - more SANs are defined below
export PKI_SERVER_CERT_COUNTRY="US"
export PKI_SERVER_CERT_STATE="North Carolina"
export PKI_SERVER_CERT_CITY="Raleigh"
export PKI_SERVER_CERT_ORG="Mirrors R Us"
export PKI_SERVER_CERT_ORG_UNIT="Security"
export PKI_REGISTRY_CERT_COMMON_NAME="$MIRROR_VM_HOSTNAME"
export PKI_WILDCARD_CERT_COMMON_NAME="$ISOLATED_NETWORK_DOMAIN"

########################################################################################################################
## Static Variables - Do not modify unless you know what you're doing
export LOG_FILE="${MIRROR_DIR}/logs/disconnected-ai-svc-bootstrap-$(date '+%s').log"

export ASSISTED_SERVICE_HOSTNAME="api.openshift.com"
export ASSISTED_SERVICE_PORT="443" 
export ASSISTED_SERVICE_PROTOCOL="https"
export ASSISTED_SERVICE_ENDPOINT="${ASSISTED_SERVICE_PROTOCOL}://${ASSISTED_SERVICE_HOSTNAME}:${ASSISTED_SERVICE_PORT}"
export ASSISTED_SERVICE_V1_API_PATH="/api/assisted-install/v1"
export ASSISTED_SERVICE_V1_API="${ASSISTED_SERVICE_ENDPOINT}${ASSISTED_SERVICE_V1_API_PATH}"

export LOCAL_REGISTRY="${MIRROR_VM_HOSTNAME}"
export LOCAL_REPOSITORY="ocp4/openshift4"
export PRODUCT_REPO="openshift-release-dev"
export LOCAL_SECRET_JSON="${MIRROR_DIR}/auth/compiled-pull-secret.json"
export RELEASE_NAME="ocp-release"
export ARCHITECTURE="x86_64"

export DETECTED_RHEL_RELEASE_VERSION=$(uname -r | sed 's/^.*\(el[0-9]\+\).*$/\1/')

export P7ZIP_RPM_URL="https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/p/p7zip-16.02-20.el8.x86_64.rpm"
export P7ZIP_DOC_RPM_URL="https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/p/p7zip-doc-16.02-20.el8.noarch.rpm"
export P7ZIP_PLUGINS_RPM_URL="https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/p/p7zip-plugins-16.02-20.el8.x86_64.rpm"

########################################################################################################################
## Global Functions
function checkForProgramAndInstallOrExit() {
    command -v $1 > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        printf '  - %-72s %-7s\n' $1 "PASSED!";
    else
        printf '  - %-72s %-7s\n' $1 "NOT FOUND!";
        echo "    Attempting to install $1 via $2..."
        sudo yum install -y $2
        if [[ $? -eq 0 ]]; then
            printf '  - %-72s %-7s\n' $1 "PASSED!";
        else
            printf '  - %-72s %-7s\n' $1 "FAILED!";
            exit 1
        fi
    fi
}

########################################################################################################################
## Preflight

## Create some directories
mkdir -p ${MIRROR_DIR}/{mirror-ingress/{haproxy,nginx/templates/,scripts}/,ai-svc/{local-store,volumes/{db,opt,imgsvc}}/,auth,dns,logs,pki,downloads/{images,olm,rhcos,tools}}

## Save the set variables to a file
export -p > ${MIRROR_DIR}/set_env

echo -e "\n===== Running preflight...\n" 2>&1 | tee -a $LOG_FILE

echo "  Checking for required assets..." 2>&1 | tee -a $LOG_FILE
## Check/load Pull Secret
if [ -f "$PULL_SECRET_PATH" ]; then
  export PULL_SECRET=$(cat ${PULL_SECRET_PATH} | jq -R .)
else
  echo "    No Pull Secret found!  Looking for ${PULL_SECRET_PATH}" 2>&1 | tee -a $LOG_FILE
  exit 1
fi
## Check/load Offline Token
if [ -f "$RH_API_OFFLINE_TOKEN_PATH" ]; then
  export RH_OFFLINE_TOKEN=$(cat ${RH_API_OFFLINE_TOKEN_PATH})
else
  echo "    No RH API Offline Token found!  Looking for ${RH_API_OFFLINE_TOKEN_PATH}" 2>&1 | tee -a $LOG_FILE
  exit 1
fi

if [ "$DISABLE_FIREWALLD" == "true" ]; then
  echo "  Disabling Firewalld..." 2>&1 | tee -a $LOG_FILE
  systemctl stop firewalld
  systemctl disable firewalld
fi

if [ "$DISABLE_SELINUX" == "true" ]; then
  echo "  Disabling SELinux..." 2>&1 | tee -a $LOG_FILE
  setenforce 0
fi

echo -e "  Checking for needed programs..." 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit jq jq 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit curl curl 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit podman podman 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit openssl openssl 2>&1 | tee -a $LOG_FILE
checkForProgramAndInstallOrExit htpasswd httpd-tools 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## RH API Authentication
echo -e "  Authenticating to the Red Hat API..." 2>&1 | tee -a $LOG_FILE
export ACTIVE_TOKEN=$(curl -s --fail https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token -d grant_type=refresh_token -d client_id=rhsm-api -d refresh_token=$RH_OFFLINE_TOKEN | jq .access_token  | tr -d '"')

if [ -z "$ACTIVE_TOKEN" ]; then
  echo "Failed to authenticate with the RH API!" 2>&1 | tee -a $LOG_FILE
  exit 1
fi
echo -e "  - Using Token: ${ACTIVE_TOKEN:0:15}..." 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Query the API for the list of available versions

echo "  Querying the Assisted Installer Service for supported versions..." 2>&1 | tee -a $LOG_FILE

export QUERY_CLUSTER_VERSIONS_REQUEST=$(curl -s --fail \
--header "Authorization: Bearer $ACTIVE_TOKEN" \
--header "Content-Type: application/json" \
--header "Accept: application/json" \
--request GET \
"${ASSISTED_SERVICE_V1_API}/openshift_versions")

if [ -z "$QUERY_CLUSTER_VERSIONS_REQUEST" ]; then
  echo "===== Failed to find supported cluster release version!" 2>&1 | tee -a $LOG_FILE
  exit 1
fi

## Save the versions to a JSON file for use later
echo $QUERY_CLUSTER_VERSIONS_REQUEST > ${MIRROR_DIR}/ai-svc/cluster-versions.json

echo -e "\n===== Preflight passed!\n" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Set up /etc/hosts
echo -e "===== Setting up /etc/hosts..." 2>&1 | tee -a $LOG_FILE

if [ -n "$(grep $MIRROR_VM_HOSTNAME /etc/hosts)" ]; then
  echo "  $MIRROR_VM_HOSTNAME already exists : $(grep $MIRROR_VM_HOSTNAME /etc/hosts)"
else
  echo "  Adding $MIRROR_VM_HOSTNAME to your /etc/hosts file...";
  printf "%s\t%s\n" "127.0.0.1" "$MIRROR_VM_HOSTNAME" | tee -a /etc/hosts > /dev/null

  ## Discount double-check
  if [ -n "$(grep $MIRROR_VM_HOSTNAME /etc/hosts)" ]; then
      echo "  $MIRROR_VM_HOSTNAME was added succesfully!";
  else
      echo "  Failed to add $MIRROR_VM_HOSTNAME to /etc/hosts";
      exit 1
  fi
fi

########################################################################################################################
##  Create PKI
echo -e "\n===== Creating Credentials & PKI..." 2>&1 | tee -a $LOG_FILE

cat > $MIRROR_DIR/pki/openssl.ca.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
policy             = policy_match
x509_extensions    = v3_ca

# For the CA policy
[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = $PKI_CA_COUNTRY
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = $PKI_CA_STATE
localityName                    = Locality Name (eg, city)
localityName_default            = $PKI_CA_CITY
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = $PKI_CA_ORG
organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = $PKI_CA_ORG_UNIT
commonName                      = Common Name (eg, your name or your server hostname)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_max                = 64

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
EOF

cat > $MIRROR_DIR/pki/openssl.server.cnf <<EOF
[ req ]
distinguished_name  = req_distinguished_name
policy              = policy_match
x509_extensions     = server_cert
req_extensions      = v3_req

# For the CA policy
[ policy_match ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = $PKI_SERVER_CERT_COUNTRY
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = $PKI_SERVER_CERT_STATE
localityName                    = Locality Name (eg, city)
localityName_default            = $PKI_SERVER_CERT_CITY
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = $PKI_SERVER_CERT_ORG
organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = $PKI_SERVER_CERT_ORG_UNIT
commonName                      = Common Name (eg, your name or your server hostname)
commonName_max                  = 64
emailAddress                    = Email Address
emailAddress_max                = 64

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ server_cert ]
nsCertType = client, server, email
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
subjectAltName = @alt_names

[ alt_names ]
IP.1 = ${MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP}
IP.2 = ${MIRROR_VM_BRIDGE_IFACE_IP}
IP.3 = ${ISOLATED_AI_SVC_HAPROXY_IP}
IP.4 = 127.0.0.1
DNS.1 = ${MIRROR_VM_HOSTNAME}
DNS.2 = ${MIRROR_VM_HOSTNAME}.${ISOLATED_NETWORK_DOMAIN}
DNS.3 = mirror.${ISOLATED_NETWORK_DOMAIN}
DNS.4 = registry.${ISOLATED_NETWORK_DOMAIN}

[ iso_wc_cert ]
nsCertType = client, server, email
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
subjectAltName = @iso_wc_alt_names

[ iso_wc_alt_names ]
DNS.1 = *.${ISOLATED_NETWORK_DOMAIN}
EOF

## Generate CA Key and Certificate
if [ ! -f ${MIRROR_DIR}/pki/ca.key.pem ]; then
  echo -e "  Generating Root CA Key and Certificates..." 2>&1 | tee -a $LOG_FILE
  openssl genrsa -out $MIRROR_DIR/pki/ca.key.pem 4096 &>> $LOG_FILE
  openssl req -new -x509 -days 3650 -config $MIRROR_DIR/pki/openssl.ca.cnf -key $MIRROR_DIR/pki/ca.key.pem -out $MIRROR_DIR/pki/ca.cert.pem \
   -subj "/CN=$PKI_CA_COMMON_NAME" &>> $LOG_FILE
  #openssl x509 -text -in $MIRROR_DIR/pki/ca.cert.pem

  ## Update the local ca trust
  cp ${MIRROR_DIR}/pki/ca.cert.pem /etc/pki/ca-trust/source/anchors/
  update-ca-trust
fi

## Copy the CA to the downloads folder in order to be easily downloaded by other nodes
cp $MIRROR_DIR/pki/ca.cert.pem $MIRROR_DIR/downloads/

## Generate Server Key and Certificates
if [ ! -f ${MIRROR_DIR}/pki/server.key.pem ]; then
  echo -e "  Generating Docker Registry Server Key and Certificates..." 2>&1 | tee -a $LOG_FILE
  openssl genrsa -out $MIRROR_DIR/pki/server.key.pem 4096 &>> $LOG_FILE
  openssl req -config $MIRROR_DIR/pki/openssl.server.cnf -new -key $MIRROR_DIR/pki/server.key.pem -out $MIRROR_DIR/pki/server.csr.pem \
   -subj "/CN=$PKI_REGISTRY_CERT_COMMON_NAME" &>> $LOG_FILE
  #openssl req -text -in $MIRROR_DIR/pki/server.csr.pem
  openssl x509 -req -days 365 -in $MIRROR_DIR/pki/server.csr.pem -CA $MIRROR_DIR/pki/ca.cert.pem -CAkey $MIRROR_DIR/pki/ca.key.pem -CAcreateserial -out $MIRROR_DIR/pki/server.cert.pem -extensions server_cert -extfile $MIRROR_DIR/pki/openssl.server.cnf &>> $LOG_FILE
  #openssl x509 -text -in $MIRROR_DIR/pki/server.cert.pem
fi

## Create Wildcard Certificate for Web Services
if [ ! -f ${MIRROR_DIR}/pki/isolated-wildcard.key.pem ]; then
  echo -e "  Generating Isolated Network Wildcard Server Key and Certificates..." 2>&1 | tee -a $LOG_FILE
  openssl genrsa -out $MIRROR_DIR/pki/isolated-wildcard.key.pem 4096 &>> $LOG_FILE
  openssl req -config $MIRROR_DIR/pki/openssl.server.cnf -new -key $MIRROR_DIR/pki/isolated-wildcard.key.pem -out $MIRROR_DIR/pki/isolated-wildcard.csr.pem \
   -subj "/CN=$PKI_WILDCARD_CERT_COMMON_NAME" &>> $LOG_FILE
  #openssl req -text -in $MIRROR_DIR/pki/isolated-wildcard.csr.pem
  openssl x509 -req -days 365 -in $MIRROR_DIR/pki/isolated-wildcard.csr.pem -CA $MIRROR_DIR/pki/ca.cert.pem -CAkey $MIRROR_DIR/pki/ca.key.pem -CAcreateserial -out $MIRROR_DIR/pki/isolated-wildcard.cert.pem -extensions iso_wc_cert -extfile $MIRROR_DIR/pki/openssl.server.cnf &>> $LOG_FILE
  #openssl x509 -text -in $MIRROR_DIR/pki/isolated-wildcard.cert.pem
fi

## Create the HAProxy Certificate Bundle (Key > Cert > CA Chain)
cat $MIRROR_DIR/pki/isolated-wildcard.key.pem > $MIRROR_DIR/pki/isolated-wildcard.haproxy-bundle.pem
cat $MIRROR_DIR/pki/isolated-wildcard.cert.pem >> $MIRROR_DIR/pki/isolated-wildcard.haproxy-bundle.pem
cat $MIRROR_DIR/pki/ca.cert.pem >> $MIRROR_DIR/pki/isolated-wildcard.haproxy-bundle.pem
echo "  HAProxy certificate bundle generated..." 2>&1 | tee -a $LOG_FILE


## Create a basic user to authenticate to the registry via HTPasswd
if [ ! -f ${MIRROR_DIR}/auth/htpasswd ]; then
  echo "  Creating the HTPasswd file for the Docker Registry..." 2>&1 | tee -a $LOG_FILE
  htpasswd -bBc ${MIRROR_DIR}/auth/htpasswd $MIRROR_CONTAINER_REGISTRY_USER $MIRROR_CONTAINER_REGISTRY_PASS &>> $LOG_FILE
fi

echo "  Credentials & PKI Created!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Create Podman Bridged Network
echo -e "\n===== Creating Podman Bridged Network..." 2>&1 | tee -a $LOG_FILE
mkdir -p /etc/cni/net.d/

CUR_PODMAN_NET_SUM=$(md5sum /etc/cni/net.d/$MIRROR_VM_ISOLATED_BRIDGE_IFACE.conflist)
cat > /etc/cni/net.d/$MIRROR_VM_ISOLATED_BRIDGE_IFACE.conflist <<EOF
{
  "cniVersion": "0.4.0",
  "name": "$MIRROR_VM_ISOLATED_BRIDGE_IFACE",
  "plugins": [
      {
        "type": "bridge",
        "bridge": "$MIRROR_VM_ISOLATED_BRIDGE_IFACE",
        "ipam": {
            "type": "host-local",
            "ranges": [
                [
                    {
                        "subnet": "$ISOLATED_NETWORK_CIDR",
                        "rangeStart": "$ISOLATED_NETWORK_START_RANGE",
                        "rangeEnd": "$ISOLATED_NETWORK_END_RANGE",
                        "gateway": "$ISOLATED_NETWORK_GATEWAY"
                    }
                ]
            ],
            "routes": [
                {"dst": "0.0.0.0/0"}
            ]
        }
      },
      {
        "type": "portmap",
        "capabilities": {
            "portMappings": true
        }
      },
      {
        "type": "firewall",
        "backend": ""
      },
      {
        "type": "tuning",
        "capabilities": {
            "mac": true
        }
      }
  ]
}
EOF
NEW_PODMAN_NET_SUM=$(md5sum /etc/cni/net.d/$MIRROR_VM_ISOLATED_BRIDGE_IFACE.conflist)

if [ "$CUR_PODMAN_NET_SUM" != "$NEW_PODMAN_NET_SUM" ]; then
  echo -e "  Podman Bridged Network Configuration Changed!" 2>&1 | tee -a $LOG_FILE
  echo -e "  Restarting Podman..." 2>&1 | tee -a $LOG_FILE
  systemctl restart podman &>> $LOG_FILE
fi

########################################################################################################################
## Deploy BIND DNS via GoZones

echo -e "\n===== Deploying GoZones DNS..." 2>&1 | tee -a $LOG_FILE

## Create some extra directories
mkdir -p ${MIRROR_DIR}/dns/volumes/{go-zones,bind}

CUR_SUM_DNS_SVC=$(md5sum /etc/systemd/system/dns-go-zones.service)
cat > /etc/systemd/system/dns-go-zones.service <<EOF
[Unit]
Description=DNS by GoZones (dns-go-zones)
After=network.target

[Service]
Type=simple
TimeoutStartSec=5m

ExecStartPre=-/usr/bin/podman rm "dns-go-zones"
ExecStartPre=/usr/bin/podman pull quay.io/kenmoini/go-zones:file-to-bind
ExecStart=/usr/bin/podman run --name dns-go-zones --net host \
  -m 512m \
  -v $MIRROR_DIR/dns/volumes/go-zones:/etc/go-zones/ \
  -v $MIRROR_DIR/dns/volumes/bind:/opt/app-root/vendor/bind/ \
  quay.io/kenmoini/go-zones:file-to-bind

ExecReload=-/usr/bin/podman stop "dns-go-zones"
ExecReload=-/usr/bin/podman rm "dns-go-zones"
ExecStop=-/usr/bin/podman stop "dns-go-zones"
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
NEW_SUM_DNS_SVC=$(md5sum /etc/systemd/system/dns-go-zones.service)

## Add additional records as needed, e.g. for the OpenShift Node and VIPs
CUR_SUM_DNS_DEF=$(md5sum $MIRROR_DIR/dns/volumes/go-zones/zones.yml)
cat > $MIRROR_DIR/dns/volumes/go-zones/zones.yml <<EOF
zones:
  - name: $ISOLATED_NETWORK_DOMAIN
    subnet: $ISOLATED_NETWORK_CIDR
    network: internal
    primary_dns_server: $MIRROR_VM_HOSTNAME.$ISOLATED_NETWORK_DOMAIN
    ttl: 3600
    records:
      NS:
        - name: $MIRROR_VM_HOSTNAME
          ttl: 86400
          domain: $ISOLATED_NETWORK_DOMAIN.
          anchor: '@'
      A:
        - name: $MIRROR_VM_HOSTNAME
          ttl: 6400
          value: $MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP

        - name: $ISOLATED_AI_SVC_ENDPOINT
          ttl: 6400
          value: $ISOLATED_AI_SVC_HAPROXY_IP
        - name: mirror
          ttl: 6400
          value: $ISOLATED_AI_SVC_HAPROXY_IP
        - name: registry
          ttl: 6400
          value: $ISOLATED_AI_SVC_HAPROXY_IP
EOF
NEW_SUM_DNS_DEF=$(md5sum $MIRROR_DIR/dns/volumes/go-zones/zones.yml)

CUR_SUM_DNS_FORWARDERS=$(md5sum $MIRROR_DIR/dns/volumes/bind/external_forwarders.conf)
cat > $MIRROR_DIR/dns/volumes/bind/external_forwarders.conf <<EOF
forwarders {
  127.0.0.53;
};
EOF
NEW_SUM_DNS_FORWARDERS=$(md5sum $MIRROR_DIR/dns/volumes/bind/external_forwarders.conf)

CUR_SUM_DNS_CONFIG=$(md5sum $MIRROR_DIR/dns/volumes/bind/named.conf)
cat > $MIRROR_DIR/dns/volumes/bind/named.conf <<EOF
options {
  listen-on port 53 { any; };
  listen-on-v6 port 53 { any; };
  
  listen-on port 8053 { any; };
  listen-on-v6 port 8053 { any; };

	directory "/var/named";
  dump-file "/var/named/data/cache_dump.db";
  statistics-file "/var/named/data/named_stats.txt";
  memstatistics-file "/var/named/data/named_mem_stats.txt";
  secroots-file "/var/named/data/named.secroots";
  recursing-file "/var/named/data/named.recursing";

	version "not available";

	recursion no;

	allow-transfer { none; };

  allow-query { any; };

  dnssec-enable no;
  dnssec-validation no;

  managed-keys-directory "/var/named/dynamic";
  geoip-directory "/usr/share/GeoIP";

  pid-file "/run/named/named.pid";
  session-keyfile "/run/named/session.key";

  include "/etc/crypto-policies/back-ends/bind.config";

  max-cache-size 100m; // maximum cache size of 100MB
};

view "internalNetworks" {
  match-clients { localnets; };

  recursion yes;
  
  include "/opt/app-root/vendor/bind/external_forwarders.conf";

  include "/opt/app-root/generated-conf/config/internal-forward-zones.conf";
  include "/opt/app-root/generated-conf/config/internal-reverse-zones.conf";
};

view "externalNetworks" {
  match-clients { any; };

  include "/opt/app-root/generated-conf/config/external-forward-zones.conf";
  include "/opt/app-root/generated-conf/config/external-reverse-zones.conf";
};

logging {
  channel default_debug {
    file "data/named.run";
    severity dynamic;
  };
};
EOF
NEW_SUM_DNS_CONFIG=$(md5sum $MIRROR_DIR/dns/volumes/bind/named.conf)

## Start the DNS Server

## Reload systemctl if service was updated
if [ "$CUR_SUM_DNS_SVC" != "$NEW_SUM_DNS_SVC" ]; then
  systemctl daemon-reload
fi

## Enable the Service regardless
systemctl enable dns-go-zones &>> $LOG_FILE

## If any other files were changed then reload the service
if [ "$CUR_SUM_DNS_DEF" != "$NEW_SUM_DNS_DEF" ] || \
   [ "$CUR_SUM_DNS_FORWARDERS" != "$NEW_SUM_DNS_FORWARDERS" ] || \
   [ "$CUR_SUM_DNS_CONFIG" != "$NEW_SUM_DNS_CONFIG" ]; then
  systemctl restart dns-go-zones &>> $LOG_FILE
fi

#DNS_SVC_TEST=$(systemctl is-active dns-go-zones)
#if [ "$DNS_SVC_TEST" == "active" ]; then
#  systemctl restart dns-go-zones &>> $LOG_FILE
#else
#  systemctl enable --now dns-go-zones &>> $LOG_FILE
#fi

########################################################################################################################
## Deploy Docker Registry

echo -e "\n===== Deploying Docker Registry..." 2>&1 | tee -a $LOG_FILE

## Create the Docker Registry Service
echo "  Creating the Docker Registry service..." 2>&1 | tee -a $LOG_FILE
CUR_SUM_REG_SVC=$(md5sum /etc/systemd/system/mirror-registry.service)
cat > /etc/systemd/system/mirror-registry.service <<EOF
[Unit]
Description=Mirror registry (mirror-registry)
After=network.target

[Service]
Type=simple
TimeoutStartSec=5m

ExecStartPre=-/usr/bin/podman rm "mirror-registry"
ExecStartPre=/usr/bin/podman pull quay.io/redhat-emea-ssa-team/registry:2
ExecStart=/usr/bin/podman run --name mirror-registry --net host \
  --privileged \
  -v ${MIRROR_DIR}/auth:/auth:z \
  -v ${MIRROR_DIR}/pki:/certs:z \
  -v ${MIRROR_DIR}/downloads/images:/var/lib/registry:z \
  -e "REGISTRY_HTTP_ADDR=0.0.0.0:443" \
  -e "REGISTRY_AUTH=htpasswd" \
  -e "REGISTRY_AUTH_HTPASSWD_REALM=registry-realm" \
  -e "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd" \
  -e "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.cert.pem" \
  -e "REGISTRY_HTTP_TLS_KEY=/certs/server.key.pem" \
  -e "REGISTRY_COMPATIBILITY_SCHEMA1_ENABLED=true" \
  quay.io/redhat-emea-ssa-team/registry:2

ExecReload=-/usr/bin/podman stop "mirror-registry"
ExecReload=-/usr/bin/podman rm "mirror-registry"
ExecStop=-/usr/bin/podman stop "mirror-registry"
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
#-e "REGISTRY_HTTP_ADDR=$LOCAL_REGISTRY" \
NEW_SUM_REG_SVC=$(md5sum /etc/systemd/system/mirror-registry.service)

## Start the Registry
echo "  Starting the Docker Registry..." 2>&1 | tee -a $LOG_FILE

## Reload systemctl if service was updated
if [ "$CUR_SUM_REG_SVC" != "$NEW_SUM_REG_SVC" ]; then
  systemctl daemon-reload

  ## Test the Registry's running state
  REGISTRY_SVC_TEST=$(systemctl is-active mirror-registry)
  if [ "$REGISTRY_SVC_TEST" == "active" ]; then
    systemctl restart mirror-registry &>> $LOG_FILE
    echo "  Waiting 15s for the Docker Registry to restart..." 2>&1 | tee -a $LOG_FILE
    sleep 15
  else
    systemctl enable --now mirror-registry &>> $LOG_FILE
    echo "  Waiting 15s for the Docker Registry to start..." 2>&1 | tee -a $LOG_FILE
    sleep 15
  fi
fi

echo "  Testing the Mirrored Docker Registry..." 2>&1 | tee -a $LOG_FILE
REG_TEST=$(curl -sSL --fail -u $MIRROR_CONTAINER_REGISTRY_USER:$MIRROR_CONTAINER_REGISTRY_PASS https://$LOCAL_REGISTRY/v2/_catalog)
if [ $? -ne 0 ]; then
  echo "ERROR: Docker Registry failed to start" 2>&1 | tee -a $LOG_FILE
  exit 1
fi

echo "  Testing the Isolated Mirrored Docker Registry..." 2>&1 | tee -a $LOG_FILE
REG_TEST=$(curl -sSL --fail -u $MIRROR_CONTAINER_REGISTRY_USER:$MIRROR_CONTAINER_REGISTRY_PASS https://$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/v2/_catalog)
if [ $? -ne 0 ]; then
  echo "ERROR: Docker Registry not reachable" 2>&1 | tee -a $LOG_FILE
  exit 1
fi

########################################################################################################################
##  Create formatted Pull Secrets
echo "  Creating Pull Secret file for Mirrored Docker Registry..." 2>&1 | tee -a $LOG_FILE
podman login --authfile "${MIRROR_DIR}/auth/mirror-pull-secret.json" -u $MIRROR_CONTAINER_REGISTRY_USER -p $MIRROR_CONTAINER_REGISTRY_PASS $LOCAL_REGISTRY &>> $LOG_FILE
podman login --authfile "${MIRROR_DIR}/auth/mirror-pull-secret.json" -u $MIRROR_CONTAINER_REGISTRY_USER -p $MIRROR_CONTAINER_REGISTRY_PASS $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN &>> $LOG_FILE
#podman login --authfile "${MIRROR_DIR}/auth/mirror-pull-secret.json" -u $MIRROR_CONTAINER_REGISTRY_USER -p $MIRROR_CONTAINER_REGISTRY_PASS $MIRROR_VM_HOSTNAME:5000 &>> $LOG_FILE
#podman login --authfile "${MIRROR_DIR}/auth/mirror-pull-secret.json" -u $MIRROR_CONTAINER_REGISTRY_USER -p $MIRROR_CONTAINER_REGISTRY_PASS $MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP:5000 &>> $LOG_FILE

jq '.auths[] += {"email": "admin@isolated.local"}' "${MIRROR_DIR}/auth/mirror-pull-secret.json" > "${MIRROR_DIR}/auth/mirror-pull-secret-email-formatted.json"


echo "  Compiling Pull Secrets..." 2>&1 | tee -a $LOG_FILE
jq -s '{"auths": ( .[0].auths + .[1].auths ) }' ${PULL_SECRET_PATH} ${MIRROR_DIR}/auth/mirror-pull-secret-email-formatted.json > ${MIRROR_DIR}/auth/compiled-pull-secret.json

JSON_MINIFIED=$(jq -Mc '.' $PULL_SECRET_PATH)
echo "'$JSON_MINIFIED'" > ${MIRROR_DIR}/auth/wrapped-ocp-pull-secret.json

JSON_MINIFIED=$(jq -Mc '.' ${MIRROR_DIR}/auth/mirror-pull-secret.json)
echo "'$JSON_MINIFIED'" > ${MIRROR_DIR}/auth/wrapped-mirror-pull-secret.json

JSON_MINIFIED=$(jq -Mc '.' ${MIRROR_DIR}/auth/compiled-pull-secret.json)
echo "'$JSON_MINIFIED'" > ${MIRROR_DIR}/auth/wrapped-compiled-pull-secret.json

########################################################################################################################
## Loop through versions serviced by the AI service and mirror the data
DEFAULT_VERSION=""
LATEST_VERSION=$(cat ${MIRROR_DIR}/ai-svc/cluster-versions.json | jq -r '. | keys_unsorted | max_by( split(".") | map(tonumber) )')
LATEST_VERSION_FULL=$(cat ${MIRROR_DIR}/ai-svc/cluster-versions.json | jq -r '.["'${LATEST_VERSION}'"].display_name')
COMPILED_OPENSHIFT_VERSIONS="{"
echo '[]' > ${MIRROR_DIR}/downloads/rhcos/os_images.json
echo '[]' > ${MIRROR_DIR}/downloads/rhcos/release_images.json

echo -e "\n===== Downloading targeted versions from the hosted Assisted Installer..." 2>&1 | tee -a $LOG_FILE
for version in $(cat ${MIRROR_DIR}/ai-svc/cluster-versions.json | jq -r '.[] | @base64'); do
  _jq() {
    echo ${version} | base64 --decode | jq -r ${1}
  }

  VERSION=$(_jq '.display_name')
  VERSION_ARR=(${VERSION//./ })
  VERSION_MAJOR=${VERSION_ARR[0]}
  VERSION_MINOR=${VERSION_ARR[1]}
  VERSION_PATCH=${VERSION_ARR[2]}
  VERSION_FULL="${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}"
  VERSION_SHORT="${VERSION_MAJOR}.${VERSION_MINOR}"

  IS_DEFAULT=$(_jq '.default')
  if [ "$IS_DEFAULT" == "true" ]; then
    DEFAULT_VERSION=$VERSION_FULL
  fi

  if [ "$ONLY_MIRROR_DEFAULT_VERSION" == "true" ]; then
    if [ "$IS_DEFAULT" != "true" ]; then
      echo "  Found version: ${VERSION_FULL} - skipping..." 2>&1 | tee -a $LOG_FILE
      continue
    else
      echo "  Found version: ${VERSION_FULL}" 2>&1 | tee -a $LOG_FILE
      echo "  ${VERSION_FULL} is the default version!" 2>&1 | tee -a $LOG_FILE
    fi
  fi

  ## Create the directories for the version
  mkdir -p ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}
  mkdir -p ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}

  ## Download oc
  if [ ! -f ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/openshift-client-linux.tar.gz ]; then
    echo "  - Downloading oc..." 2>&1 | tee -a $LOG_FILE
    curl -sSL https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/${VERSION_FULL}/openshift-client-linux.tar.gz -o ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/openshift-client-linux.tar.gz
    cd ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/ &>> $LOG_FILE
    tar --no-same-owner -xzf openshift-client-linux.tar.gz
    chmod a+x oc
    chmod a+x kubectl
    rm README.md
    cd - &>> $LOG_FILE
  fi

  ## Download opm
  if [ ! -f ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/opm-linux.tar.gz ]; then
    echo "  - Downloading opm..." 2>&1 | tee -a $LOG_FILE
    curl -sSL https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/${VERSION_FULL}/opm-linux.tar.gz -o ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/opm-linux.tar.gz
    cd ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/ &>> $LOG_FILE
    tar --no-same-owner -xzf opm-linux.tar.gz
    chmod a+x opm
    cd - &>> $LOG_FILE
  fi

  ## Download RH CoreOS
  if [ ! -f ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live.x86_64.iso ]; then
    echo "  - Downloading RH CoreOS ISO..." 2>&1 | tee -a $LOG_FILE
    curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live.x86_64.iso -o ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live.x86_64.iso
  fi
  if [ ! -f ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live-kernel-x86_64 ]; then
    echo "  - Downloading RH CoreOS Kernel..." 2>&1 | tee -a $LOG_FILE
    curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live-kernel-x86_64 -o ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live-kernel-x86_64
  fi
  if [ ! -f ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live-initramfs.x86_64.img ]; then
    echo "  - Downloading RH CoreOS initramfs..." 2>&1 | tee -a $LOG_FILE
    curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live-initramfs.x86_64.img -o ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live-initramfs.x86_64.img
  fi
  if [ ! -f ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live-rootfs.x86_64.img ]; then
    echo "  - Downloading RH CoreOS RootFS..." 2>&1 | tee -a $LOG_FILE
    curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live-rootfs.x86_64.img -o ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-live-rootfs.x86_64.img
  fi


  ## Mirror needed OCP images
  ## https://docs.openshift.com/container-platform/4.9/installing/installing-mirroring-installation-images.html#installation-mirror-repository_installing-mirroring-installation-images
  echo "  - Downloading OpenShift Release Images..." 2>&1 | tee -a $LOG_FILE
  OCP_RELEASE="$VERSION_FULL"

  ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/oc adm -a ${LOCAL_SECRET_JSON} release mirror \
    --from=quay.io/${PRODUCT_REPO}/${RELEASE_NAME}:${OCP_RELEASE}-${ARCHITECTURE} \
    --to=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY} \
    --to-release-image=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}-${ARCHITECTURE} &>> $LOG_FILE

  ## Extract the openshift-install binary
  echo -e "  - Extracting the openshift-install binary..." 2>&1 | tee -a $LOG_FILE
  cd ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/ &>> $LOG_FILE
  ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/oc adm release extract -a ${LOCAL_SECRET_JSON} --command=openshift-install "${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}-${ARCHITECTURE}" &>> $LOG_FILE
  ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/openshift-install version &>> $LOG_FILE
  cd - &>> $LOG_FILE
  
  echo "  - Mapping OpenShift and RHCOS Images..." 2>&1 | tee -a $LOG_FILE
  ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/oc adm release info ${VERSION_FULL} -o 'jsonpath={.displayVersions.machine-os.Version}' > ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/version
  ${MIRROR_DIR}/downloads/tools/${VERSION_FULL}/oc adm release info ${VERSION_FULL} -o 'jsonpath={.config.architecture}' > ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/architecture
  if [ "$(cat ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/architecture)" == "amd64" ]; then
    RHCOS_ARCHITECTURE="x86_64"
  fi

  ## Generate JSON for OS_IMAGES env var needed by OAS
  cat > ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-image-info.json <<EOF
{"openshift_version":"$VERSION_SHORT","cpu_architecture":"$RHCOS_ARCHITECTURE","url":"https://mirror.${ISOLATED_NETWORK_DOMAIN}/pub/downloads/rhcos/${VERSION_FULL}/rhcos-live.$RHCOS_ARCHITECTURE.iso","rootfs_url":"https://mirror.${ISOLATED_NETWORK_DOMAIN}/pub/downloads/rhcos/${VERSION_FULL}/rhcos-live-rootfs.$RHCOS_ARCHITECTURE.img","version":"$(cat ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/version)"}
EOF
  cat > ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/release-image-info.json <<EOF
{"openshift_version":"$VERSION_SHORT","cpu_architecture":"$RHCOS_ARCHITECTURE","url":"${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}-${ARCHITECTURE}","version":"$VERSION_FULL"}
EOF
oc_version() {
  cat <<EOF
"$VERSION_SHORT":{"display_name":"$VERSION_FULL","release_version":"$VERSION_FULL","release_image":"${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}-${ARCHITECTURE}","rhcos_image":"https://mirror.${ISOLATED_NETWORK_DOMAIN}/pub/downloads/rhcos/${VERSION_FULL}/rhcos-live.$RHCOS_ARCHITECTURE.iso","rhcos_rootfs":"https://mirror.${ISOLATED_NETWORK_DOMAIN}/pub/downloads/rhcos/${VERSION_FULL}/rhcos-live-rootfs.$RHCOS_ARCHITECTURE.img","rhcos_version":"$(cat ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/version)","support_level":"production"},
EOF
}
  COMPILED_OPENSHIFT_VERSIONS+=$(oc_version)

  jq -r -c --argjson value "$(cat ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/rhcos-image-info.json)" '. |= . + [$value]' ${MIRROR_DIR}/downloads/rhcos/os_images.json > ${MIRROR_DIR}/downloads/rhcos/os_images.json.tmp
  jq -r -c --argjson value "$(cat ${MIRROR_DIR}/downloads/rhcos/${VERSION_FULL}/release-image-info.json)" '. |= . + [$value]' ${MIRROR_DIR}/downloads/rhcos/release_images.json > ${MIRROR_DIR}/downloads/rhcos/release_images.json.tmp
  mv ${MIRROR_DIR}/downloads/rhcos/os_images.json.tmp ${MIRROR_DIR}/downloads/rhcos/os_images.json
  mv ${MIRROR_DIR}/downloads/rhcos/release_images.json.tmp ${MIRROR_DIR}/downloads/rhcos/release_images.json

  echo "  - All assets for ${VERSION_FULL} downloaded!" 2>&1 | tee -a $LOG_FILE

  if [ ! -f "$MIRROR_DIR/downloads/olm/.finished" ]; then
    echo "===== Mirroring Operator catalog..." 2>&1 | tee -a $LOG_FILE
    ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc adm catalog mirror registry.redhat.io/redhat/redhat-operator-index:v${VERSION_SHORT} $LOCAL_REGISTRY/olm-mirror -a ${LOCAL_SECRET_JSON} --to-manifests="$MIRROR_DIR/downloads/olm" 2>&1 | tee -a $LOG_FILE
    touch $MIRROR_DIR/downloads/olm/.finished
  fi

done
COMPILED_OPENSHIFT_VERSIONS_COMMA_FIX="${COMPILED_OPENSHIFT_VERSIONS::-1}}"
echo $COMPILED_OPENSHIFT_VERSIONS_COMMA_FIX > ${MIRROR_DIR}/ai-svc/openshift_versions.json

########################################################################################################################
## Download the AI service components
echo -e "\n===== Mirroring the Assisted Installer Service..." 2>&1 | tee -a $LOG_FILE

### Mirror coreos-installer
#if [ ! -d "${MIRROR_DIR}/downloads/images/docker/registry/v2/repositories/coreos/coreos-installer" ]; then
  IMAGE="coreos-installer"
  ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/coreos/$IMAGE:v0.9.1 $LOCAL_REGISTRY/coreos/$IMAGE:v0.9.1 &>> $LOG_FILE
  ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/coreos/$IMAGE:v0.10.0 $LOCAL_REGISTRY/coreos/$IMAGE:v0.10.0 &>> $LOG_FILE
  ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/coreos/$IMAGE:release $LOCAL_REGISTRY/coreos/$IMAGE:release &>> $LOG_FILE
#fi
echo "  coreos-installer images mirrored!" 2>&1 | tee -a $LOG_FILE

### Mirror Library components
if [ ! -d "${MIRROR_DIR}/downloads/images/docker/registry/v2/repositories/library/nginx/_manifests/tags/latest" ]; then
  for IMAGE in haproxy nginx
  do
    ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror docker.io/library/$IMAGE:latest $LOCAL_REGISTRY/library/$IMAGE:latest &>> $LOG_FILE
    echo "  - Mirrored to $LOCAL_REGISTRY/library/$IMAGE:latest" 2>&1 | tee -a $LOG_FILE
  done
fi
echo "  Library images mirrored!" 2>&1 | tee -a $LOG_FILE

### Mirror AI Svc components
if [ ! -d "${MIRROR_DIR}/downloads/images/docker/registry/v2/repositories/ocpmetal/assisted-service/_manifests/tags/latest" ]; then
  for IMAGE in postgresql-12-centos7 ocp-metal-ui agent assisted-installer-agent assisted-iso-create assisted-installer assisted-installer-controller assisted-service
  do
    ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/ocpmetal/$IMAGE:latest $LOCAL_REGISTRY/ocpmetal/$IMAGE:latest &>> $LOG_FILE
    echo "  - Mirrored to $LOCAL_REGISTRY/ocpmetal/$IMAGE:latest" 2>&1 | tee -a $LOG_FILE
  done
fi
if [ ! -d "${MIRROR_DIR}/downloads/images/docker/registry/v2/repositories/edge-infrastructure/assisted-installer-ui/_manifests/tags/latest" ]; then
  for IMAGE in assisted-installer-agent assisted-installer assisted-installer-controller assisted-service assisted-image-service assisted-installer-ui
  do
    ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/edge-infrastructure/$IMAGE:latest $LOCAL_REGISTRY/edge-infrastructure/$IMAGE:latest &>> $LOG_FILE
    echo "  - Mirrored to $LOCAL_REGISTRY/edge-infrastructure/$IMAGE:latest" 2>&1 | tee -a $LOG_FILE
  done
fi
echo "  Latest Assisted Service images mirrored!" 2>&1 | tee -a $LOG_FILE

if [ ! -d "${MIRROR_DIR}/downloads/images/docker/registry/v2/repositories/ocpmetal/assisted-service/_manifests/tags/stable" ]; then
  for IMAGE in ocp-metal-ui assisted-iso-create assisted-installer assisted-installer-controller assisted-service
  do
    ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/ocpmetal/$IMAGE:stable $LOCAL_REGISTRY/ocpmetal/$IMAGE:stable &>> $LOG_FILE
    echo "  - Mirrored to $LOCAL_REGISTRY/ocpmetal/$IMAGE:stable" 2>&1 | tee -a $LOG_FILE
  done
fi
if [ ! -d "${MIRROR_DIR}/downloads/images/docker/registry/v2/repositories/edge-infrastructure/assisted-installer-ui/_manifests/tags/stable" ]; then
  for IMAGE in assisted-installer-agent assisted-installer assisted-installer-controller assisted-service assisted-image-service assisted-installer-ui
  do
    ${MIRROR_DIR}/downloads/tools/${LATEST_VERSION_FULL}/oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/edge-infrastructure/$IMAGE:stable $LOCAL_REGISTRY/edge-infrastructure/$IMAGE:stable &>> $LOG_FILE
    echo "  - Mirrored to $LOCAL_REGISTRY/edge-infrastructure/$IMAGE:stable" 2>&1 | tee -a $LOG_FILE
  done
fi
echo "  Stable Assisted Service images mirrored!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Bake the configuration files needed for the Assisted Installer Service
echo -e "\n===== Generating Assisted Service configuration files..." 2>&1 | tee -a $LOG_FILE
CONTROLLER_DIGEST=$(skopeo inspect --authfile ${LOCAL_SECRET_JSON} docker://$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-installer-controller:latest | jq -r '.Digest')
AGENT_DIGEST=$(skopeo inspect --authfile ${LOCAL_SECRET_JSON} docker://$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-installer-agent:latest | jq -r '.Digest')
INSTALLER_DIGEST=$(skopeo inspect --authfile ${LOCAL_SECRET_JSON} docker://$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-installer:latest | jq -r '.Digest')
INSTALL_RELEASE_DIGEST=$(skopeo inspect --authfile ${LOCAL_SECRET_JSON} docker://$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocp4/openshift4:${LATEST_VERSION_FULL}-x86_64 | jq -r '.Digest')
echo "  Using Digests:" 2>&1 | tee -a $LOG_FILE
echo "  - assisted-installer: $INSTALLER_DIGEST" 2>&1 | tee -a $LOG_FILE
echo "  - assisted-installer-agent: $AGENT_DIGEST" 2>&1 | tee -a $LOG_FILE
echo "  - assisted-installer-controller: $CONTROLLER_DIGEST" 2>&1 | tee -a $LOG_FILE
echo "  - openshift installer release: $INSTALL_RELEASE_DIGEST" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Deploy Ingress Pod
echo -e "\n===== Deploying Mirror Ingress as a container pod service..." 2>&1 | tee -a $LOG_FILE

###########################################
## Ingress Pod Service
cat > /etc/systemd/system/mirror-ingress.service <<EOF
[Unit]
Description=Mirror Ingress
After=network.target
Wants=network.target

[Service]
TimeoutStartSec=1m
Type=forking
Restart=on-failure
RestartSec=30
ExecStop=${MIRROR_DIR}/mirror-ingress/scripts/service_stop.sh
ExecStart=${MIRROR_DIR}/mirror-ingress/scripts/service_start.sh

[Install]
WantedBy=multi-user.target
EOF
echo "  Mirror Ingress SystemD service (mirror-ingress) created!" 2>&1 | tee -a $LOG_FILE

###########################################
## Ingress Pod Start Script
cat > ${MIRROR_DIR}/mirror-ingress/scripts/service_start.sh <<EOF
#!/bin/bash

set -x

${MIRROR_DIR}/mirror-ingress/scripts/service_stop.sh

sleep 3

echo "Checking for stale network lock file..."
FILE_CHECK="/var/lib/cni/networks/$MIRROR_VM_ISOLATED_BRIDGE_IFACE/${ISOLATED_AI_SVC_HAPROXY_IP}"
if [[ -f "\$FILE_CHECK" ]]; then
    rm \$FILE_CHECK
fi
FILE_CHECK="/var/lib/cni/networks/$MIRROR_VM_ISOLATED_BRIDGE_IFACE/${ISOLATED_AI_SVC_NGINX_IP}"
if [[ -f "\$FILE_CHECK" ]]; then
    rm \$FILE_CHECK
fi

# Create Pod and deploy containers
#echo -e "Deploying Pods...\n"
#podman pod create --name mirror-ingress --network $MIRROR_VM_ISOLATED_BRIDGE_IFACE --ip "${ISOLATED_AI_SVC_HAPROXY_IP}" -p 80/tcp -p 443/tcp
#podman pod create --name mirror-websrv --network $MIRROR_VM_ISOLATED_BRIDGE_IFACE --ip "${ISOLATED_AI_SVC_NGINX_IP}" -p 8080/tcp
#sleep 3

# Deploy Nginx
echo -e "Deploying Nginx...\n"
podman run -dt --name mirror-websrv --network $MIRROR_VM_ISOLATED_BRIDGE_IFACE --ip "${ISOLATED_AI_SVC_NGINX_IP}" -p 8080/tcp \
 -m 1024m --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
 -v ${MIRROR_DIR}/downloads:/usr/share/nginx/html/pub/downloads -v ${MIRROR_DIR}/mirror-ingress/nginx/templates:/etc/nginx/templates \
 -e "NGINX_PORT=8080" $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/library/nginx:latest

sleep 3

# Deploy HAProxy
echo -e "Deploying HAProxy...\n"
podman run -dt --sysctl net.ipv4.ip_unprivileged_port_start=0 --name mirror-ingress --network $MIRROR_VM_ISOLATED_BRIDGE_IFACE --ip "${ISOLATED_AI_SVC_HAPROXY_IP}" -p 80/tcp -p 443/tcp \
 -m 1024m \
 --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
 -v ${MIRROR_DIR}/mirror-ingress/haproxy:/usr/local/etc/haproxy:ro -v ${MIRROR_DIR}/pki:/usr/local/etc/certs:ro \
 $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/library/haproxy:latest
EOF
echo "  Mirror Ingress start script created!" 2>&1 | tee -a $LOG_FILE

###########################################
## Ingress Pod Stop Script
cat > ${MIRROR_DIR}/mirror-ingress/scripts/service_stop.sh <<EOF
#!/bin/bash

set -x

echo "Killing containers..."
/usr/bin/podman kill mirror-ingress
/usr/bin/podman kill mirror-websrv

echo "Removing containers..."
/usr/bin/podman rm mirror-ingress -f -i
/usr/bin/podman rm mirror-websrv -f -i
EOF
echo "  Mirror Ingress stop script created!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Ingress HAProxy Configuration
echo -e "\n===== Deploying Mirror Ingress HAProxy as a container service..." 2>&1 | tee -a $LOG_FILE

###########################################
## Create the CRT List for HAProxy
cat > $MIRROR_DIR/mirror-ingress/haproxy/crt-list.cfg <<EOF
/usr/local/etc/certs/isolated-wildcard.haproxy-bundle.pem
EOF
echo "  Mirror Ingress HAProxy CRT List generated!" 2>&1 | tee -a $LOG_FILE

###########################################
## Create the HAProxy Configuration file
cat > $MIRROR_DIR/mirror-ingress/haproxy/haproxy.cfg <<EOF
global
  log stdout format raw local0
  daemon

  # Default ciphers to use on SSL-enabled listening sockets.
  # For more information, see ciphers(1SSL).
  ssl-default-bind-ciphers kEECDH+aRSA+AES:kRSA+AES:+AES256:RC4-SHA:!kEDH:!LOW:!EXP:!MD5:!aNULL:!eNULL

resolvers docker_resolver
  nameserver dns $MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP:53

defaults
  log     global
  mode    http
  option  httplog
  option  dontlognull
  timeout connect 36000s
  timeout client 36000s
  timeout server 36000s

frontend http
  bind *:80
  mode http
	
  acl is_well_known path_beg -i /.well-known/
	
  redirect scheme https code 301 if !is_well_known !{ ssl_fc }

frontend https
  mode tcp
  bind *:443 ssl crt-list /usr/local/etc/haproxy/crt-list.cfg

  acl host_ai_svc_api hdr(host) -i $ISOLATED_AI_SVC_API_HOSTNAME.$ISOLATED_NETWORK_DOMAIN
  acl host_ai_svc_web hdr(host) -i $ISOLATED_AI_SVC_WEB_UI_HOSTNAME.$ISOLATED_NETWORK_DOMAIN
  acl host_ai_svc_endpoint hdr(host) -i $ISOLATED_AI_SVC_ENDPOINT.$ISOLATED_NETWORK_DOMAIN
  acl host_registry hdr(host) -i registry.$ISOLATED_NETWORK_DOMAIN
  acl host_mirror hdr(host) -i mirror.$ISOLATED_NETWORK_DOMAIN
  
  use_backend aiwebui if host_ai_svc_web
  use_backend aiwebui if host_ai_svc_endpoint
  use_backend aiapi if host_ai_svc_api
  use_backend registry if host_registry
  use_backend mirrorhttp if host_mirror

  default_backend mirrorhttp

backend mirrorhttp
  mode http
  server backend1 $ISOLATED_AI_SVC_NGINX_IP:8080
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  http-response set-header Strict-Transport-Security "max-age=16000000; includeSubDomains; preload;"

backend registry
  mode tcp
  server registry1 $MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP:443

backend aiapi
  mode http
  server aiapi1 $ISOLATED_AI_SVC_API_IP:8090
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  http-response set-header Strict-Transport-Security "max-age=16000000; includeSubDomains; preload;"

backend aiwebui
  mode http
  server aiwebui1 $ISOLATED_AI_SVC_API_IP:8080
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  http-response set-header Strict-Transport-Security "max-age=16000000; includeSubDomains; preload;"
EOF
echo "  Mirror Ingress HAProxy configuration generated!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Deploy Nginx to serve the Mirrored Content
echo -e "\n===== Deploying Mirror Ingress Nginx as a container service..." 2>&1 | tee -a $LOG_FILE

###########################################
## Create the Nginx Configuration file
cat > $MIRROR_DIR/mirror-ingress/nginx/templates/default.conf.template <<EOF
server {
    listen       8080;
    server_name  _;

    location / {
        root   /usr/share/nginx/html;
        index mirror-index.html;
        autoindex on;
        autoindex_format html;
        autoindex_exact_size off;
        autoindex_localtime on;
    }
}
EOF
echo "  Mirror Ingress nginx configuration generated!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Deploy the Assisted Installer Service Pod & Container Ensemble
echo -e "\n===== Deploying the AI Service as container services..." 2>&1 | tee -a $LOG_FILE

###########################################
## Create SystemD service for the AI Service
cat > /etc/systemd/system/assisted-installer.service <<EOF
[Unit]
Description=OpenShift Assisted Installer Pod
After=network-online.target
Wants=network-online.target

[Service]
TimeoutStartSec=120
ExecStop=$MIRROR_DIR/ai-svc/service_stop.sh
ExecStart=$MIRROR_DIR/ai-svc/service_start.sh

Type=forking
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
echo "  Assisted Installer SystemD service script created!" 2>&1 | tee -a $LOG_FILE

###########################################
## Create Assisted Installer Configuration
cat > $MIRROR_DIR/ai-svc/volumes/opt/onprem-environment <<EOF
########################################################################
# file: /opt/assisted-service/onprem-environment
########################################################################
#This is the IP or name with the API the OCP discovery agent will callback
SERVICE_FQDN="assisted-installer.${ISOLATED_NETWORK_DOMAIN}"
#SERVICE_BASE_URL=https://assisted-installer.${ISOLATED_NETWORK_DOMAIN}
SERVICE_BASE_URL=http://127.0.0.1:8090
ASSISTED_SERVICE_SCHEME=http
ASSISTED_SERVICE_HOST=127.0.0.1:8090
IMAGE_SERVICE_BASE_URL=http://127.0.0.1:8888
LISTEN_PORT=8888

########################################################################
# NO NEED TO UPDATE AFTER THIS, UNLESS DOING RESTRICTED NETWORK INSTALL
########################################################################
# Host IPs service will be listening
#SERVICE_IPS=<Comma separated list of host IPs where the service should listed>

# Required when using self-signed certifications or no certificates
SKIP_CERT_VERIFICATION=true

DEPLOY_TARGET=onprem
DUMMY_IGNITION=false
STORAGE=filesystem
DISK_ENCRYPTION_SUPPORT=true
NTP_DEFAULT_SERVER=
IPV6_SUPPORT=false
AUTH_TYPE=none

POSTGRESQL_DATABASE=installer
POSTGRESQL_PASSWORD=admin
POSTGRESQL_USER=admin
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=admin
DB_PASS=admin
DB_NAME=installer

OPENSHIFT_VERSIONS=$(cat ${MIRROR_DIR}/ai-svc/openshift_versions.json)
OS_IMAGES=$(cat ${MIRROR_DIR}/downloads/rhcos/os_images.json)
RELEASE_IMAGES=$(cat ${MIRROR_DIR}/downloads/rhcos/release_images.json)

# (OLD INFO NEED TO UPDATE)
# Uncomment the below lines for restricted network install, requires pulling by digest
## Setting these breaks the OAS API, causes a pull secret validation error for some forsaken reason...
#CONTROLLER_IMAGE="quay.io/ocpmetal/assisted-installer-controller@sha256:180d8b8e0381e6498434b2e3e88dc4874e9235827c8d2647cabf88f4bdf50c52"
#OPENSHIFT_INSTALL_RELEASE_IMAGE="quay.io/openshift-release-dev/ocp-release@${INSTALL_RELEASE_DIGEST}"
#OPENSHIFT_INSTALL_RELEASE_IMAGE_MIRROR="$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocp4/openshift4@${INSTALL_RELEASE_DIGEST}"
#AGENT_DOCKER_IMAGE="$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-installer-agent:@${AGENT_DIGEST}"
#INSTALLER_IMAGE="$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-installer:@${INSTALLER_DIGEST}"
#CONTROLLER_IMAGE="$LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-installer-controller:@${CONTROLLER_DIGEST}"

# Uncomment to avoid pull-secret requirement for quay.io on restricted network installs
PUBLIC_CONTAINER_REGISTRIES="quay.io,registry.access.redhat.com,registry.redhat.io,mirror-vm"

# Format has changed for HW validation (Link: https://github.com/openshift/assisted-service/blob/master/onprem-environment#L19)
HW_VALIDATOR_REQUIREMENTS=[{"version":"default","master":{"cpu_cores":4,"ram_mib":16384,"disk_size_gb":120,"installation_disk_speed_threshold_ms":10,"network_latency_threshold_ms":100,"packet_loss_percentage":0},"worker":{"cpu_cores":2,"ram_mib":8192,"disk_size_gb":120,"installation_disk_speed_threshold_ms":10,"network_latency_threshold_ms":1000,"packet_loss_percentage":10},"sno":{"cpu_cores":8,"ram_mib":32768,"disk_size_gb":120,"installation_disk_speed_threshold_ms":10}}]

# Just a base64 encoded version of the un:pw
#PULL_SECRET="$(base64 <<< "${MIRROR_CONTAINER_REGISTRY_USER}:${MIRROR_CONTAINER_REGISTRY_PASSWORD}")"
# Raw Original OCP pull-secret
#PULL_SECRET=$(jq -Mc '.' $PULL_SECRET_PATH)
# Raw mirror-only PS
#PULL_SECRET=$(jq -Mc '.' ${MIRROR_DIR}/auth/mirror-pull-secret-email-formatted.json)
# Raw compiled PS
#PULL_SECRET=$(jq -Mc '.' ${MIRROR_DIR}/auth/compiled-pull-secret.json)

# Inline Double-quote escaped original OCP PS
#PULL_SECRET=$(jq -Mc '. | tostring' $PULL_SECRET_PATH)
# Inline Double-quote escaped mirror-only PS
#PULL_SECRET=$(jq -Mc '. | tostring' $MIRROR_DIR/auth/mirror-pull-secret-email-formatted.json)
# Inline Double-quote escaped compiled PS
#PULL_SECRET=$(jq -Mc '. | tostring' $MIRROR_DIR/auth/compiled-pull-secret.json)

# Inline Single-quote wrapped original OCP PS
#PULL_SECRET=$(cat ${MIRROR_DIR}/auth/wrapped-ocp-pull-secret.json)
# Inline Single-quote wrapped mirror-only PS
#PULL_SECRET=$(cat ${MIRROR_DIR}/auth/wrapped-mirror-pull-secret.json)
# Inline Single-quote wrapped compiled PS
#PULL_SECRET=$(cat ${MIRROR_DIR}/auth/wrapped-compiled-pull-secret.json)

# In-container reference to raw original OCP PS
#PULL_SECRET="/ocp-pull-secret.json"
# In-container reference to raw mirror-only PS
#PULL_SECRET="/mirror-pull-secret-email-formatted.json"
# In-container reference to raw compiled PS
#PULL_SECRET="/compiled-pull-secret.json"

# In-container reference to Single-quote wrapped original OCP PS
#PULL_SECRET="/wrapped-ocp-pull-secret.json"
# In-container reference to Single-quote wrapped mirror-only PS
#PULL_SECRET="/wrapped-mirror-pull-secret.json"
# In-container reference to Single-quote wrapped compiled PS
#PULL_SECRET="/wrapped-compiled-pull-secret.json"

#BASE_DNS_DOMAINS=
#IMAGE_BUILDER=
#CONNECTIVITY_CHECK_IMAGE=
#HARDWARE_INFO_IMAGE=
#INVENTORY_IMAGE=
#OCM_BASE_URL=

# Enabled for SNO Deployments (Link: https://github.com/openshift/assisted-service/blob/master/onprem-environment#L14)
ENABLE_SINGLE_NODE_DNSMASQ=true

#####################################################################################
##  Experimental: Single Node deployment
# Need to be uncommented for single node cluster
#INSTALLER_IMAGE=quay.io/eranco74/assisted-installer:single_node_onprem
#CONTROLLER_IMAGE=quay.io/eranco74/assisted-installer-controller:single_node_onprem
#####################################################################################
EOF
echo "  Assisted Installer configuration created!" 2>&1 | tee -a $LOG_FILE

if [ ! -f "$MIRROR_DIR/ai-svc/local-store/rhcos-live.x86_64.iso" ]; then
  cp ${MIRROR_DIR}/downloads/rhcos/${LATEST_VERSION_FULL}/rhcos-live.x86_64.iso $MIRROR_DIR/ai-svc/local-store/rhcos-live.x86_64.iso
  echo "  Latest RHCOS Image copied!" 2>&1 | tee -a $LOG_FILE
fi

###########################################
## Create Nginx configuration for the Assisted Installer UI
cat > $MIRROR_DIR/ai-svc/volumes/opt/nginx-ui.conf <<EOF
########################################################################
# file: /opt/assisted-service/nginx-ui.conf 
########################################################################
server {
  listen 0.0.0.0:8080;
  server_name _;
  root /app;
  index index.html;
  location /api {
      proxy_pass http://localhost:8090;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection 'upgrade';
      proxy_set_header Host \$host;
      proxy_cache_bypass \$http_upgrade;
  }
  location / {
     try_files \$uri /index.html;
  }
}
EOF
echo "  Assisted Installer Nginx configuration created!" 2>&1 | tee -a $LOG_FILE

###########################################
## Create AI Service Start Script
cat > ${MIRROR_DIR}/ai-svc/service_start.sh <<EOF
#!/bin/bash

set -x

$MIRROR_DIR/ai-svc/service_stop.sh

sleep 3

echo "Checking for stale network lock file..."
FILE_CHECK="/var/lib/cni/networks/${MIRROR_VM_ISOLATED_BRIDGE_IFACE}/${ISOLATED_AI_SVC_DB_IP}"
if [ -f "\$FILE_CHECK" ]; then
    rm \$FILE_CHECK
fi
FILE_CHECK="/var/lib/cni/networks/${MIRROR_VM_ISOLATED_BRIDGE_IFACE}/${ISOLATED_AI_SVC_API_IP}"
if [ -f "\$FILE_CHECK" ]; then
    rm \$FILE_CHECK
fi
FILE_CHECK="/var/lib/cni/networks/${MIRROR_VM_ISOLATED_BRIDGE_IFACE}/${ISOLATED_AI_SVC_WEB_UI_IP}"
if [ -f "\$FILE_CHECK" ]; then
    rm \$FILE_CHECK
fi

# Download RHCOS live CD
if [ ! -f "$MIRROR_DIR/ai-svc/local-store/rhcos-live.x86_64.iso" ]; then
    echo "Base Live ISO not found. Downloading RHCOS live CD from https://mirror.$ISOLATED_NETWORK_DOMAIN/pub/downloads/rhcos/${DEFAULT_VERSION}/rhcos-live.x86_64.iso"
    curl -L https://mirror.$ISOLATED_NETWORK_DOMAIN/pub/downloads/rhcos/${DEFAULT_VERSION}/rhcos-live.x86_64.iso -o $MIRROR_DIR/ai-svc/local-store/rhcos-live.x86_64.iso
fi

# Download RHCOS installer
if [ ! -f "$MIRROR_DIR/ai-svc/local-store/coreos-installer" ]; then
  echo "CoreOS installer not found. Downloading to $MIRROR_DIR/ai-svc/local-store/coreos-installer"
  podman run -it --rm --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
    -v $MIRROR_DIR/ai-svc/local-store:/data \
    -w /data \
    --entrypoint /bin/bash \
    $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/coreos/coreos-installer:v0.10.0 \
    -c 'cp /usr/sbin/coreos-installer /data/coreos-installer'
fi

# Prepare for persistence
# NOTE: Make sure to delete this directory if persistence is not desired for a new environment!
mkdir -p $MIRROR_DIR/ai-svc/volumes/db
chown -R 26 $MIRROR_DIR/ai-svc/volumes/db

# Create containers

# Create Pod
podman pod create --name $ISOLATED_AI_SVC_ENDPOINT -p 5432:5432,8080:8080,8090:8090 --network "${MIRROR_VM_ISOLATED_BRIDGE_IFACE}" --ip "${ISOLATED_AI_SVC_API_IP}" --dns "${MIRROR_VM_ISOLATED_BRIDGE_IFACE_IP}" --dns-search "${ISOLATED_NETWORK_DOMAIN}"

# Deploy database
echo "Deploying Database..."
podman run -dt --pod $ISOLATED_AI_SVC_ENDPOINT --name $ISOLATED_AI_SVC_DB_HOSTNAME --env-file $MIRROR_DIR/ai-svc/volumes/opt/onprem-environment \
  --restart unless-stopped \
  -m 512m \
  --volume $MIRROR_DIR/ai-svc/volumes/db:/var/lib/pgsql:z \
  --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
  $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/postgresql-12-centos7:latest

sleep 3

# Deploy Assisted Image Service
echo "Deploying Assisted Image Service..."
podman run -dt --pod $ISOLATED_AI_SVC_ENDPOINT --name $ISOLATED_AI_SVC_IMAGE_HOSTNAME \
  --env-file $MIRROR_DIR/ai-svc/volumes/opt/onprem-environment \
  -v $MIRROR_DIR/ai-svc/volumes/imgsvc:/data:z \
  -v $MIRROR_DIR/downloads/ca.cert.pem:/etc/pki/ca-trust/source/anchors/ca.cert.pem:z \
  --entrypoint='["/bin/bash", "-c", "update-ca-trust; /assisted-image-service"]' \
  --restart unless-stopped \
  -m 1024m \
  --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
  $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/edge-infrastructure/assisted-image-service:stable

# Deploy Assisted Service
echo "Deploying Assisted Service..."
podman run -dt --pod $ISOLATED_AI_SVC_ENDPOINT --name $ISOLATED_AI_SVC_API_HOSTNAME \
  -v $MIRROR_DIR/ai-svc/local-store/rhcos-live.x86_64.iso:/data/livecd.iso:z \
  -v $MIRROR_DIR/ai-svc/local-store/coreos-installer:/data/coreos-installer:z \
  -v ${MIRROR_DIR}/auth/mirror-pull-secret.json:/mirror-pull-secret.json:z \
  -v ${MIRROR_DIR}/auth/mirror-pull-secret-email-formatted.json:/mirror-pull-secret-email-formatted.json:z \
  -v ${MIRROR_DIR}/auth/wrapped-mirror-pull-secret.json:/wrapped-mirror-pull-secret.json:z \
  -v ${MIRROR_DIR}/auth/compiled-pull-secret.json:/compiled-pull-secret.json:z \
  -v ${MIRROR_DIR}/auth/wrapped-compiled-pull-secret.json:/wrapped-compiled-pull-secret.json:z \
  -v $PULL_SECRET_PATH:/ocp-pull-secret.json:z \
  -v ${MIRROR_DIR}/auth/wrapped-ocp-pull-secret.json:/wrapped-ocp-pull-secret.json:z \
  -v $MIRROR_DIR/downloads/ca.cert.pem:/etc/pki/ca-trust/source/anchors/ca.cert.pem:z \
  --env-file $MIRROR_DIR/ai-svc/volumes/opt/onprem-environment \
  -e DUMMY_IGNITION=False \
  --restart no \
  --entrypoint='["/bin/bash", "-c", "update-ca-trust; /assisted-service"]' \
  -m 1024m \
  --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
  $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/assisted-service:latest

sleep 3

# Deploy UI
echo "Deploying UI..."
podman run -dt --pod $ISOLATED_AI_SVC_ENDPOINT --name $ISOLATED_AI_SVC_WEB_UI_HOSTNAME --env-file $MIRROR_DIR/ai-svc/volumes/opt/onprem-environment \
  -v $MIRROR_DIR/ai-svc/volumes/opt/nginx-ui.conf:/opt/bitnami/nginx/conf/server_blocks/nginx.conf:z \
  --restart unless-stopped \
  -m 512m \
  --authfile ${MIRROR_DIR}/auth/compiled-pull-secret.json \
  $LOCAL_REGISTRY.$ISOLATED_NETWORK_DOMAIN/ocpmetal/ocp-metal-ui:stable

EOF
echo "  Assisted Installer service start script created!" 2>&1 | tee -a $LOG_FILE

###########################################
## Create AI Service Stop Script
cat > $MIRROR_DIR/ai-svc/service_stop.sh <<EOF
#!/bin/bash

set -x

systemctl restart podman

echo "Killing container..."
/usr/bin/podman kill $ISOLATED_AI_SVC_DB_HOSTNAME
/usr/bin/podman kill $ISOLATED_AI_SVC_API_HOSTNAME
/usr/bin/podman kill $ISOLATED_AI_SVC_WEB_UI_HOSTNAME
/usr/bin/podman kill $ISOLATED_AI_SVC_IMAGE_HOSTNAME
/usr/bin/podman pod kill $ISOLATED_AI_SVC_ENDPOINT

echo "Removing container..."
/usr/bin/podman rm $ISOLATED_AI_SVC_DB_HOSTNAME -f -i
/usr/bin/podman rm $ISOLATED_AI_SVC_API_HOSTNAME -f -i
/usr/bin/podman rm $ISOLATED_AI_SVC_WEB_UI_HOSTNAME -f -i
/usr/bin/podman rm $ISOLATED_AI_SVC_IMAGE_HOSTNAME -f -i
/usr/bin/podman pod rm $ISOLATED_AI_SVC_ENDPOINT -f -i

systemctl restart podman

EOF
echo "  Assisted Installer service stop script created!" 2>&1 | tee -a $LOG_FILE

########################################################################################################################
## Start all the services
echo "  Setting service script permissions..." 2>&1 | tee -a $LOG_FILE
chmod a+x $MIRROR_DIR/ai-svc/service_stop.sh
chmod a+x $MIRROR_DIR/ai-svc/service_start.sh
chmod a+x $MIRROR_DIR/mirror-ingress/scripts/service_stop.sh
chmod a+x $MIRROR_DIR/mirror-ingress/scripts/service_start.sh

echo "  Reloading services..." 2>&1 | tee -a $LOG_FILE
systemctl daemon-reload

echo "  Starting Mirror Ingress..." 2>&1 | tee -a $LOG_FILE
set +e
SVC_TEST=$(systemctl is-active --quiet mirror-ingress)
if [ $? -eq 0 ]; then
  systemctl restart mirror-ingress &>> $LOG_FILE
  echo "  Waiting 30s for the Mirror Ingress to restart..." 2>&1 | tee -a $LOG_FILE
  sleep 30
else
  systemctl enable --now mirror-ingress &>> $LOG_FILE
  echo "  Waiting 30s for the Mirror Ingress to start..." 2>&1 | tee -a $LOG_FILE
  sleep 30
fi
set -e

echo "  Starting Assisted Installer..." 2>&1 | tee -a $LOG_FILE
set +e
SVC_TEST=$(systemctl is-active --quiet assisted-installer)
if [ $? -eq 0 ]; then
  systemctl restart assisted-installer &>> $LOG_FILE
  #echo "  Waiting 15s for the Assisted Installer to restart..." 2>&1 | tee -a $LOG_FILE
  #sleep 15
else
  systemctl enable --now assisted-installer &>> $LOG_FILE
  #echo "  Waiting 15s for the Assisted Installer to start..." 2>&1 | tee -a $LOG_FILE
  #sleep 15
fi
set -e


## Package the services in an archive

## Clone down Libvirt automation and run it
## Create CA for OpenShift [Optional]

## FirewallD better stuff
## Get Zone for an interface: firewall-cmd --get-active-zones | grep -B1 'enp1s0' | head -n 1

## Save the set variables to a file at the end to pick up any changes and dynamically created/updated variables
export -p > ${MIRROR_DIR}/set_env.finished

echo -e "\n===== Execution complete! =====\n" 2>&1 | tee -a $LOG_FILE