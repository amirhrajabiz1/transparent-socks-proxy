#! /bin/bash


check_status() {
	if [ $? -eq 0 ]; then
		echo -e "[\e[32mOK\e[0m]: $1"
	else
		echo -e "[\e[31mERROR\e[0m]: $2"
		exit 1
	fi
}

if [ "$EUID" -ne 0 ]; then
	echo "You should be root :)"
	exit 1
fi

clear

apt update 
check_status "Successfully updated the package repository." "Failed to update the package repository."

echo -e "\n================================================\n"

apt install net-tools -y 
check_status "Successfully installed the 'net-tools' package." "Failed to install the 'net-tools' package."
apt install resolvconf -y
check_status "Successfully installed the 'resolvconf' package." "Failed to install the 'resolvconf' package."
apt-get install isc-dhcp-server -y
check_status "Successfully installed the 'isc-dhcp-server' package." "Failed to install the 'isc-dhcp-server' package."
DEBIAN_FRONTEND=noninteractive apt install iptables-persistent -y
check_status "Successfully installed the 'iptables-persistent' package." "Failed to install the 'iptables-persistent' package."
apt install redsocks -y
check_status "Successfully installed the 'redsocks' package." "Failed to install the 'redsocks' package."
apt install python3-pip -y
check_status "Successfully installed the 'python3-pip' package." "Failed to install the 'python3-pip' package."
python3 -m pip install pyinotify
check_status "Successfully installed the 'pyinotify' library." "Failed to install the 'pyinotify' library."

echo -e "\n================================================\n"

echo -en "[\e[33mENTER\e[0m]: To establish a connection with the SSH server, possessing a key pair on this host is essential. Kindly input 'Yes' if you possess one; however, exercise caution when selecting 'No,' as it might potentially remove your existing key pair (YES, no): "
read have_key

if [[ "$have_key" =~ [nN]|[nN][oO] ]]; then
        ssh-keygen
        check_status "Successfully generated a new SSH key pair." "Failed to generate a new SSH key pair."
else
	echo -e  "[\e[32mOK\e[0m]: You already have an existing SSH key pair."
fi



echo -e "\n================================================\n"

echo -e "[\e[33mINFO\e[0m]: If you have not yet transferred your public key to the remote SSH server, you will need to copy the public key that was generated in the previous step to the SSH remote server. This can be done using the ssh-copy-id command like so:

ssh-copy-id your_username@xxx.xxx.xxx.xxx

Be sure to replace 'your_username' with the username you use to log into the remote server, and replace 'xxx.xxx.xxx.xxx' with the actual IP address of the remote SSH server. This will install the public key on the remote server and allow you to connect without being prompted for a password."

echo -en "[\e[33mENTER\e[0m]: Have you copied your public SSH key over to the remote server(s) yet? (No yes): "
read transfered

if [[ "$transfered" =~ [yY]|[Yy][eE][Ss] ]]; then
        echo -e "[\e[32mOk\e[0m]"
else
        echo -e "[\e[31mERROR\e[0m]: Please transfer the public SSH key to continue."
        exit 0
fi
echo

echo -e "\n================================================\n"

echo -e "[\e[33mINFO\e[0m]:To connect to the remote SSH server, you will need to enter an ssh command. If you are connecting directly, the command will look like:

ssh your_username@remote_server_ip

Be sure to replace 'your_username' with the name you log in with, and 'remote_server_ip' with the IP address of the remote server.
If you need to connect through a jump host, the command will be:

ssh -J your_username@jump_host_ip -tt your_username@remote_server_ip

In this case, replace 'your_username' with your login name, 'jump_host_ip' with the IP of the intermediate jump server, and 'remote_server_ip' with the final destination server IP."
echo -en "[\e[33mEnter\e[0m]: Enter the full ssh command for your connection: "
read ssh_command
echo $ssh_command
$ssh_command -o ConnectTimeout=30 true
check_status "SSH connection works." "Can't establish an SSH connection to the remote host. Something is wrong."

echo -e "\n================================================\n"

echo -ne "[\e[33mENTER\e[0m]: Please specify the local port you want to use for the proxy connection.(default port is: 1234): "
read port
if [[ "$port" =~ ^[0-9]+ ]] && (( port > 1 && port <= 65535 )); then # Check if the port is all numbers and is between 1 and 65535.
        port=$port
else
        port=1234
fi
while true; do
        if netstat -tln | grep -q ":$port[^0-9]" ; then # Check if the port already exists in the system and listening.
                echo -e "[\e[33mWARNING\e[0m]: Port $port is already listening on the system."
                if (( $port == 65535 )); then
                        port=0
                fi
                let port=$port+1
        else
                echo -e "[\e[32mOK\e[0m]: Port $port will be listening for SOCKS5 connections."
                break
        fi
done
echo

echo -e "\n================================================\n"

apt-get install gcc -y 
check_status "Successfully installed 'gcc' package." "We had a problem in installing 'gcc' package."


if [ ! -d "/etc/dns2socks/" ]; then
        mkdir /etc/dns2socks/
fi
apt install git
check_status "Successfully installed 'git' package." "We had a problem in installing 'git' package."
cd /etc/dns2socks/
if [ ! -d "/etc/dns2socks/dns2socks" ]; then
	git clone https://github.com/song940/dns2socks.git
fi
check_status "Successfully cloned dns2socks from 'https://github.com/song940/dns2socks.git' in /etc/dns2socks/." "Failed to clone dns2socks from 'https://github.com/song940/dns2socks.git' in /etc/dns2socks/." 


cd dns2socks
gcc -pthread -o dns2socks dns2socks.c
check_status "Successfully compiled dns2socks." "Failed to compile dns2socks."


echo "#! /bin/bash

$ssh_command -f -N -D$port         # ssh command

while true; do          # this while loop check if the port still exists or not. If the port doesn't exist, exit with code '1'.
        if netstat -tln | grep -q \":$port[^0-9]\" ; then
                sleep 30
        else
                echo 'Disconnected to the remote Host'
                exit 1          # exit with code '1' for putting the service in 'failed' state.
        fi
done" > /etc/dns2socks/ssh.sh
check_status "Successfully made /etc/dns2socks/ssh.sh script." "Failed to make /etc/dns2socks/ssh.sh script."
chmod +x /etc/dns2socks/ssh.sh
check_status "Successfully made /etc/dns2socks/ssh.sh script executable." "Failed to make /etc/dns2socks/ssh.sh script executable."


echo '[Unit]
Description=Make a SSH connection to open a Socks5 proxy
After=network-online.target


[Service]
Environment="LOCAL_ADDR=localhost"
ExecStart=/etc/dns2socks/ssh.sh

RestartSec=5
Restart=always

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/ssh-socks5.service
check_status "Successfully made /etc/systemd/system/ssh-socks5.service" "Failed to make /etc/systemd/system/ssh-socks5.service."
systemctl daemon-reload
check_status "Successfully reloaded systemd daemon." "Failed to reload systemd daemon."
systemctl restart ssh-socks5
check_status "Successfully restarted the 'ssh-socks5' service." "Failed to restart the 'ssh-socks5' service."
systemctl enable ssh-socks5
check_status "Successfully enabled the 'ssh-socks5' service." "Failed to enable the 'ssh-socks5' service."

echo -e "\n================================================\n"



if [ ! -d "/var/log/dns2socks/" ]; then
        mkdir /var/log/dns2socks/
fi

echo "#! /bin/bash

/etc/dns2socks/dns2socks/dns2socks 127.0.0.1:$port 8.8.8.8:53 0.0.0.0:53 1>> /var/log/dns2socks/records.log 2>> /var/log/dns2socks/errors.log" > /etc/dns2socks/dns2socks.sh
check_status "Successfully made /etc/dns2socks/dns2socks.sh script." "Failed to make /etc/dns2socks/dns2socks.sh script."

chmod +x /etc/dns2socks/dns2socks.sh
check_status "Successfully made /etc/dns2socks/dns2socks.sh script executable." "Failed to make /etc/dns2socks/dns2socks.sh script executable."


echo "[Unit]
Description=This service setup a DNS server for LAN and sends the DNS queries through a socks5 proxy to 8.8.8.8
After=network-online.target

[Service]
Type=simple
ExecStart=/etc/dns2socks/dns2socks.sh
WorkingDirectory=/etc/dns2socks

RestartSec=5
Restart=always

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/dns2socks.service
check_status "Successfully made /etc/systemd/system/dns2socks.service" "Failed to make /etc/systemd/system/dns2socks.service."


echo 'nameserver 127.0.0.1' >> /etc/resolvconf/resolv.conf.d/head
check_status "Successfully put 'nameserver 127.0.0.1' in /etc/resolvconf/resolv.conf.d/head" "Failed to put 'nameserver 127.0.0.1' in /etc/resolvconf/resolv.conf.d/head"
resolvconf -u
check_status "Successfully run the update scripts of resolvconf." "Failed to run the update scripts of resolvconf."

systemctl list-units --full --all | grep -Fq "systemd-resolved.service"
if [ $? -eq 0 ]; then
	systemctl disable systemd-resolved
	check_status "Successfully disabled 'systemd-resolved'." "Failed to disable 'systemd-resolved'."
	systemctl stop systemd-resolved
	check_status "Successfully stopped 'systemd-resolved'." "Failed to stop 'systemd-resolved'."
	echo -e "\n================================================\n"
fi

systemctl daemon-reload
check_status "Successfully reloaded systemd daemon." "Failed to reload systemd daemon."
systemctl enable dns2socks
check_status "Successfully enabled the 'dns2socks' service." "Failed to enable the 'dns2socks' service."
systemctl restart dns2socks
check_status "Successfully restarted the 'dns2socks' service." "Failed to restart the 'dns2socks' service."


#  echo '/var/log/dns2socks/*.log {
#      daily
#      missingok
#      rotate 70
#      compress
#      delaycompress
#      notifempty
#      create 0640 root root
#  }' > /etc/logrotate.d/dns2socks.conf
#  if [ $? -eq 0 ]; then
#          echo -e "[\e[32mOK\e[0m]: Successfully made a logrotate for service 'dns2socks'."
#  else
#          echo -e "[\e[31mERROR\e[0m]: Failed to make a logrotate for service 'dns2socks'."
#          exit 1
#  fi

echo -e "[\e[32mDONE\e[0m]"
echo -e "\n\e[32m**********\e[0m
A service called 'ssh-socks5' was set up to create a SOCKS5 connection to a remote SSH host.
A service called 'dns2socks' was configured to listen on port 53 on all network interfaces. This service redirects DNS packets through the SOCKS5 proxy to 8.8.8.8 for DNS resolution.
The 'dns2socks' service was configured to write its logs to the '/var/log/dns2socks' directory.
\e[32m**********\e[0m"

####### Make redsocks configs here.


interfaces=`ip link show | egrep '[0-9]: .*:' | cut -d: -f1,2` 
echo -e "Your interfaces:\n$interfaces"
echo "Enter the the lan interface name: "
read laninterface

echo "Enter the the Wan interface name: "
read waninterface

if lsb_release -d | grep 20 || lsb_release -d | grep 22 ; then
	laninterconf=`grep $laninterface /etc/netplan/* -l`
	if [ -z "$laninterconf" ]; then
		laninterconf="/etc/netplan/42-network.yaml"
	else
		laninterconf=$laninterconf
	fi

	echo "network:
  version: 2
  renderer: networkd
  ethernets:
    $laninterface:
      addresses: [10.10.10.1/24]
" > $laninterconf
	netplan apply
	check_status "Successfully configured lan interface." "Failed to configure lan interface."
else
	echo "# Configs for $laninterface
auto $laninterface
iface $laninterface inet static
address 10.10.10.1
netmask 255.255.255.0" >> /etc/network/interfaces
	systemctl restart networking
	check_status "Successfully configured lan interface." "Failed to configure lan interface."
fi


sed -i "s/^INTERFACES.*/INTERFACES=\"$laninterface\"/" /etc/default/isc-dhcp-server

echo "
subnet 10.10.10.0 netmask 255.255.255.0 {
  range 10.10.10.10 10.10.10.100;
  option routers 10.10.10.1;
  option domain-name-servers 10.10.10.1, 8.8.8.8;
  #ddns-update-style none;
  option domain-name \"example.com\";
  default-lease-time 600;
  max-lease-time 7200;
  authoritative;
}
" >> /etc/dhcp/dhcpd.conf
check_status "Successfully copied the dhcp configs in '/etc/dhcp/dhcpd.conf' for lan interface." "Failed to copy the dhcp configs in '/etc/dhcp/dhcpd.conf' for lan interface."

systemctl restart isc-dhcp-server
check_status "Successfully restarted the 'isc-dhcp-server' service." "Failed to restart the 'isc-dhcp-server' service."
systemctl enable isc-dhcp-server
check_status "Successfully enabled the 'isc-dhcp-server' service." "Failed to enable the 'isc-dhcp-server' service."


iptables -t nat -A POSTROUTING -o $waninterface -j MASQUERADE
check_status "Successfully made a nat rule on wan interface" "Failed to make a nat rule on wan interface"


echo "
base {
  log_debug = on;
  log_info = on;
  daemon = on;
  redirector = iptables;
}
redsocks {
  local_ip = 0.0.0.0;
  local_port = 12345;
  ip = 127.0.0.1;
  port = $port;
  type = socks5;
}
" > /etc/redsocks.conf
check_status "Successfully copied the redsocks configs in '/etc/redsocks.conf'." "Failed to copy the redsocks configs in '/etc/redsocks.conf'."
systemctl restart redsocks
check_status "Successfully restarted the 'redsocks' service." "Failed to restart the 'redsocks' service."

iptables -N BLOCK_ROUTE
iptables -t nat -N PROXY_ROUTE
iptables -t nat -N REDSOCKS
iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 100.64.0.0/10 -j RETURN
iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN
iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS -d 198.18.0.0/15 -j RETURN
iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN
iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN
iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345
iptables -t nat -A PREROUTING --in-interface $laninterface -p tcp -j PROXY_ROUTE
iptables -I FORWARD 1 --in-interface $laninterface -p tcp -j BLOCK_ROUTE
check_status "Successfully made redsocks rules." "Failed to make redsocks rules."

iptables-save > /etc/iptables/rules.v4
check_status "Successfully made iptables rules persistent." "Failed to make iptables rules persistent."

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
check_status "Successfully made ipv4 forwarding enable." "Failed to make ipv4 forwarding enable."


#### Make intelroute configs here


if [ ! -f "/etc/dns2socks/block_domains" ]; then
	touch /etc/dns2socks/block_domains
fi
if [ ! -f "/etc/dns2socks/proxy_domains" ]; then
	echo '*' > /etc/dns2socks/proxy_domains
fi
chmod 644 /etc/dns2socks/block_domains /etc/dns2socks/proxy_domains

if [ ! -d "/etc/dns2socks/intelroute.py" ]; then
	echo "
import os
import subprocess
import pyinotify
import threading

# 'proxy_domains' and 'block_domains' should have 664 permissions.

# Initial setup
subprocess.call('iptables -t nat -F PROXY_ROUTE', shell=True)
subprocess.call('iptables -F BLOCK_ROUTE', shell=True)

# Define the path to your file and bash command
records_file_path = '/var/log/dns2socks/records.log'
proxy_domains_file_path = '/etc/dns2socks/proxy_domains'
block_domains_file_path = '/etc/dns2socks/block_domains'
proxy_add_bash_command_template = 'iptables -t nat -I PROXY_ROUTE 1 -p tcp -d {} -j REDSOCKS'
block_add_bash_command_template = 'iptables -I BLOCK_ROUTE 1 -p tcp -d {} -j DROP'

proxy_del_bash_command_template = 'iptables -t nat -D PROXY_ROUTE -p tcp -d {} -j REDSOCKS'
block_del_bash_command_template = 'iptables -D BLOCK_ROUTE -p tcp -d {} -j DROP'

# parse the record and return the domain name
def parse_record(line: str) -> str:
    linelist = line.split()
    if (line.startswith('20') and len(linelist) == 4):
        domain = linelist[-1]
        if domain.endswith('.lan'):
            domain = domain.replace('.lan', '')
        return domain

# Check the domain of the record against the list of the domains and return True if the domain match and False if the domain doesn't match
def domain_is_valid(original_domain: str, domains: list) -> bool:
    if original_domain:
        if original_domain in domains:
            return True
        else:
            for domain in domains:
                if fnmatch.fnmatch(original_domain, domain):
                    return True
    return False

# return the list of lines in file 'domains'
def domains_extractor(file_path: str) -> list:
    with open(file_path, 'r') as file:
        lines = file.readlines()
        final_lines = []
        for line in lines:
            if line.strip() and not line.startswith('#'):
                final_lines.append(line.strip().lower())
        return final_lines


proxy_domains = domains_extractor(proxy_domains_file_path)
block_domains = domains_extractor(block_domains_file_path)
proxy_applied_domains = set()
block_applied_domains = set()
# The iproute command will run in this function
def run_command(line: str) -> None:
    domain = parse_record(line)
    if (domain_is_valid(domain, block_domains)) and (not domain in block_applied_domains):
        block_applied_domains.add(domain)
        if domain in proxy_applied_domains:
            proxy_applied_domains.remove(domain)
            proxy_del_bash_command = proxy_del_bash_command_template.format(domain)
            subprocess.call(proxy_del_bash_command, shell=True)
        block_add_bash_command = block_add_bash_command_template.format(domain)
        subprocess.call(block_add_bash_command, shell=True)
    elif (domain_is_valid(domain, proxy_domains)) and (not domain in proxy_applied_domains) and (not domain_is_valid(domain, block_domains)):
        proxy_applied_domains.add(domain)
        if domain in block_applied_domains:
            block_applied_domains.remove(domain)
            block_del_bash_command = block_del_bash_command_template.format(domain)
            subprocess.call(block_del_bash_command, shell=True)
        proxy_add_bash_command = proxy_add_bash_command_template.format(domain)
        subprocess.call(proxy_add_bash_command, shell=True)



# Create an event handler class for 'records.log' file.
class RecordEventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        # When the file is modified read the new line and run the bash command
        with open(records_file_path, 'r') as file:
            last_line = ''
            while True:
                line = file.readline()
                if not line:
                    break
                last_line = line.strip()

            if last_line:
                run_command(last_line)

class ProxyEventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        global proxy_domains
        proxy_domains = domains_extractor(proxy_domains_file_path)
            
class BlockEventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        global block_domains
        block_domains = domains_extractor(block_domains_file_path)


# Initialize the inotify watcher
wm1 = pyinotify.WatchManager()
mask1 = pyinotify.IN_MODIFY
wm2 = pyinotify.WatchManager()
mask2 = pyinotify.IN_MODIFY
wm3 = pyinotify.WatchManager()
mask3 = pyinotify.IN_MODIFY

# record notifier for records.log
record_notifier = pyinotify.Notifier(wm1, RecordEventHandler())

# record notifier for 'proxy_domains' file
proxy_domains_notifier = pyinotify.Notifier(wm2, ProxyEventHandler())

# record notifier for 'block_domains' file
block_domains_notifier = pyinotify.Notifier(wm3, BlockEventHandler())

# Add the files to be monitored
wdd1 = wm1.add_watch(records_file_path, mask1, rec=False)
wdd2 = wm2.add_watch(proxy_domains_file_path, mask2, rec=False)
wdd3 = wm3.add_watch(block_domains_file_path, mask3, rec=False)


# Define functions to run notifiers in threads
def run_record_notifier():
    record_notifier.loop()

def run_proxy_domains_notifier():
    proxy_domains_notifier.loop()

def run_block_domains_notifier():
    block_domains_notifier.loop()

# Create threads for notifiers
record_thread = threading.Thread(target=run_record_notifier)
proxy_domains_thread = threading.Thread(target=run_proxy_domains_notifier)
block_domains_thread = threading.Thread(target=run_block_domains_notifier)

# Start the threads
record_thread.start()
proxy_domains_thread.start()
block_domains_thread.start()

# Wait for the threads to finish (optional)
record_thread.join()
proxy_domains_thread.join()
block_domains_thread.join()
" > /etc/dns2socks/intelroute.py
check_status "Successfully made /etc/dns2socks/intelroute.py." "Failed to mak /etc/dns2socks/intelroute.py."
fi
chmod u+x /etc/dns2socks/intelroute.py
check_status "Successfully made /etc/dns2socks/intelroute.py executable." "Failed to mak /etc/dns2socks/intelroute.py executable."

echo "[Unit]
Description=make decision to block or proxy a packet.

[Service]
ExecStart=/usr/bin/python3 /etc/dns2socks/intelroute.py
WorkingDirectory = /etc/dns2socks/
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/intelroute.service
check_status "Successfully made /etc/systemd/system/intelroute.service" "Failed to make /etc/systemd/system/intelroute.service."
systemctl daemon-reload
check_status "Successfully reloaded systemd daemon." "Failed to reload systemd daemon."
systemctl enable intelroute.service
check_status "Successfully enabled the 'intelrouite' service." "Failed to enable the 'intelroute' service."
systemctl start intelroute.service
check_status "Successfully started the 'intelrouite' service." "Failed to start the 'intelroute' service."
