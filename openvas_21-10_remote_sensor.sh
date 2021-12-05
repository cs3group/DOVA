#!/usr/bin/env bash

# +----------------------------------------------------------------+
# | OpenVAS 21.04 Remote Sensor Installer for Debian 11 (Bullseye) |
# | (c) 2021 CS3 Group · https://cs3group.com                      |
# | By Pedro C. aka s4ur0n (@NN2ed_s4ur0n)                         |
# | Installation testing by @Belky318, @gibdeon & Superfume        |
# | Licensed under the GNU General Public License v2.0 or later    |
# | Manual script blog (original idea)                             |
# | https://sadsloth.net/post/install-gvm-20_08-src-on-debian/     |
# | https://www.libellux.com/openvas/                              |
# |                                                                |
# | OpenVAS Licenses:                                              |
# | Copyright (C) 2018-2020 Greenbone Networks GmbH                |
# | Licensed under the GNU General Public License v2.0 or later    |
# +----------------------------------------------------------------+


BLUE=`tput setaf 6; tput bold`
YELLOW=`tput setaf 3`
RESET=`tput sgr0`
SUDO="sudo"


press_any_key() {
	read -t 5 -n 1 -s -r -p "${YELLOW}[+] Press any key to continue or wait 5 seconds... ${RESET}"
	echo " "
}


print_credits() {
	echo -e "${BLUE}+----------------------------------------------------------------+${RESET}"
	echo -e "${BLUE}| OpenVAS 21.xx Remote Sensor Installer for Debian 11 (Bullseye) |${RESET}"
	echo -e "${BLUE}| (c) 2021 CS3 Group · https://cs3group.com                      |${RESET}"
	echo -e "${BLUE}| By Pedro C. aka s4ur0n (@NN2ed_s4ur0n)                         |${RESET}"
	echo -e "${BLUE}| Installation testing by @Belky318, @gibdeon & Superfume        |${RESET}"
	echo -e "${BLUE}| Licensed under the GNU General Public License v2.0 or later    |${RESET}"
	echo -e "${BLUE}| Manual script blog (original idea)                             |${RESET}"
	echo -e "${BLUE}| https://sadsloth.net/post/install-gvm-20_08-src-on-debian/     |${RESET}"
	echo -e "${BLUE}| https://www.libellux.com/openvas/                              |${RESET}"
	echo -e "${BLUE}|                                                                |${RESET}"
	echo -e "${BLUE}| OpenVAS Licenses:                                              |${RESET}"
	echo -e "${BLUE}| Copyright (C) 2018-2020 Greenbone Networks GmbH                |${RESET}"
	echo -e "${BLUE}| Licensed under the GNU General Public License v2.0 or later    |${RESET}"
	echo -e "${BLUE}+----------------------------------------------------------------+${RESET}"
	echo -e " "
	press_any_key
}


check_root() {
	[[ $(id -u) -ne 0 ]] && { 
		echo -e "${BLUE}Please run this script as root!${RESET}"
		exit -1
	}
}


check_debian_distro() {
	VERSION=$(sed 's/\..*//' /etc/debian_version)
	if [[ $VERSION != "11" ]]; then
        echo -e "${BLUE}This script currently works only on Debian Bullseye (Stable)${RESET}"
        exit -1
    fi
}


check_sudo() {
    [[ $UID != 0 ]] && {
        type -f $SUDO || {
        	echo -e "${BLUE}You're not root and you don't have $SUDO, please install $SUDO before executing $0${RESET}${RESET}"
            exit -1
        }
    } || {
        SUDO=""
    }
}


system_optimize() {
	#
	# Use it at your own risk
	# https://linux2me.wordpress.com/2018/06/03/tuning-the-tcp-stack-system-administrator/
	# Optimized for 1 Gbps Ethernet card
	#
	clear
	echo -e "${BLUE}[+] Optimizing TCP/IP for OpenVAS${RESET}"
	if grep -Fxq "# --- TCP STACK OPTIMIZATION ---" /etc/sysctl.conf
	then
		echo -e "${BLUE}	Your TCP/IP stack optimization is ok!${RESET}"
		press_any_key
	else
		echo -e "${BLUE}	[+] Setting TCP/IP Stack optimized values${RESET}"
		echo "# --- TCP STACK OPTIMIZATION ---" >> /etc/sysctl.conf
		echo "vm.overcommit_memory=1" >> /etc/sysctl.conf
		echo "net.core.wmem_default=262144" >> /etc/sysctl.conf
		echo "net.core.wmem_max=4194304" >> /etc/sysctl.conf
		echo "net.core.rmem_default=262144" >> /etc/sysctl.conf
		echo "net.core.rmem_max=4194304" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_moderate_rcvbuf=1" >> /etc/sysctl.conf
		echo "net.core.somaxconn=2048" >> /etc/sysctl.conf
		echo "net.core.netdev_max_backlog=8000" >> /etc/sysctl.conf
		echo "net.core.wmem_max=16777216" >> /etc/sysctl.conf
		echo "net.core.rmem_max=16777216" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_fin_timeout=10" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_keepalive_intvl=30" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_keepalive_probes=5" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_keepalive_time=600" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_low_latency=1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_max_orphans=16384" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_max_tw_buckets=1440000" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_no_metrics_save=1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_orphan_retries=0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_rmem=10240 131072 33554432" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_wmem=10240 131072 33554432" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_sack=0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_slow_start_after_idle=0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_syncookies=0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
		# Old kernels
		# echo "net.ipv4.tcp_tw_recycle=1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_tw_reuse=1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_window_scaling=1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_reordering=3" >> /etc/sysctl.conf
		echo "net.core.netdev_budget=600" >> /etc/sysctl.conf
		/usr/sbin/sysctl --system
		echo -e "${BLUE}[+] Done!${RESET}"
		press_any_key
	fi
	clear
	echo -e "${BLUE}[+] Optimizing system limits for OpenVAS${RESET}"
	if grep -Fxq "# --- LIMITS OPTIMIZATION ---" /etc/security/limits.conf
	then
		echo -e "${BLUE}	Your limits optimization are ok!${RESET}"
		press_any_key
	else
		echo -e "${BLUE}	[+] Setting limits for optimized values${RESET}"
		echo "# --- LIMITS OPTIMIZATION ---" >> /etc/security/limits.conf
		echo "gvm             hard    nofile          65535" >> /etc/security/limits.conf
		echo "gvm             soft    nofile          65535" >> /etc/security/limits.conf
		echo -e "${BLUE}[+] Done!${RESET}"
		press_any_key
	fi
}


network_throughput() {
	clear
	echo -e "${BLUE}[+] Installing tuned package...${RESET}"
	apt install -y tuned
	echo -e "${BLUE}[+] Activate network-throughput profile...${RESET}"
	tuned -d -p network-throughput
}


add_more_swap() {
	clear
	echo -e "${BLUE}[+] Adding swap to system${RESET}"
	if [ -f "/swap.img" ]; then
		echo -e "${BLUE}	Swap file exist. Aborted.${RESET}"
		press_any_key
	else
		touch /swap.img
		chmod 600 /swap.img
		dd if=/dev/zero of=/swap.img bs=1024k count=4000
		mkswap /swap.img
		echo "/swap.img none swap sw 0 0" >> /etc/fstab
		swapon /swap.img
		echo vm.swappiness=10 >> /etc/sysctl.conf
		sysctl -p /etc/sysctl.conf
		echo -e "${BLUE}[+] Done!${RESET}"
		press_any_key
	fi
}


issue() {
	clear
	echo -e "${BLUE}[+] Changing issue and issue.net${RESET}"
	echo -e "+------------------------------------------------------------------------------+" > /etc/issue
	echo -e "|                                                                              |" >> /etc/issue
	echo -e "| Debian 11 (Remote Scan Sensor for OpenVAS by CS3 Group https://cs3group.com) |" >> /etc/issue
	echo -e "|                                                                              |" >> /etc/issue
	echo -e "+------------------------------------------------------------------------------+" >> /etc/issue
	IP=$(hostname -I | tr " " "\n" | grep -v "^$" | sort -t . -k 1,1n | head -1 | tr "\n" " ")
	echo -e " " >> /etc/issue
	echo -e "IP: $IP" >> /etc/issue
	echo -e "ssh -p 9390 root@$IP" >> /etc/issue
	echo -e "ssh -i -i ~/.ssh/openvas-agent root@$IP" >> /etc/issue
	echo -e " " >> /etc/issue
	cp /etc/issue /etc/issue.net
	press_any_key
}


sources() {
	clear
	echo -e "${BLUE}[+] Upgrading to sid (unstable) Debian version${RESET}"
	sed -i 's/bullseye main/sid main contrib/g' /etc/apt/sources.list
	apt update
	apt -y full-upgrade
	press_any_key
}


sshd() {
	clear
	echo -e "${BLUE}[+] Upgrading to sid (unstable) Debian version${RESET}"
	sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
	sed -i 's/#Port 22/Port 9390/g' /etc/ssh/sshd_config
	/etc/init.d/ssh restart
	umask 077 && test -d ~/.ssh || mkdir ~/.ssh
	umask 077 && touch ~/.ssh/authorized_keys
	echo -e 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKRvMAzfSiSSEDdg7zUUtmpsN2ojEvLIHalpWuNiryfr scanbox@scanbox' >> ~/.ssh/authorized_keys
	press_any_key
}


openvas_binaries() {
	clear
	echo -e "${BLUE}[+] Installing OpenVAS daemons for Remote Sensor${RESET}"
	apt install -y openvas openvas-scanner ospd-openvas gvm
	apt remove -y greenbone-security-assistant
	/usr/bin/gvm-setup
	sudo runuser -u _gvm -- /usr/sbin/greenbone-feed-sync --type SCAP
	# gvm-check-setup
	press_any_key
}
	

sync_daemon() {
	clear
	echo -e "${BLUE}[+] Creating sync daemon for update feeds from Greenbone${RESET}"
	cat << EOF > /usr/sbin/update-greenbone-feeds 
#!/usr/bin/env bash
/usr/sbin/greenbone-feed-sync --type GVMD_DATA
/usr/sbin/greenbone-feed-sync --type SCAP
/usr/sbin/greenbone-feed-sync --type CERT
EOF
	chmod u+x /usr/sbin/update-greenbone-feeds
	chown _gvm:_gvm /usr/sbin/update-greenbone-feeds
	echo -e "1 1 * * * _gvm /usr/sbin/update-greenbone-feeds 1>/dev/null 2>/dev/null" >> /etc/crontab
	press_any_key
}


autoclean() {
	clear
	echo -e "${BLUE}[+] Removing packages from apt...${RESET}"
	apt -y autoremove
	apt -y clean
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


check_services() {
	systemctl -a --no-pager status gvmd
	systemctl -a --no-pager status ospd-openvas
	press_any_key
}


install_remote_sensor() {
	sources
	issue
	sshd
	openvas_binaries
	sync_daemon
	sudo runuser -u _gvm -- /usr/sbin/update-greenbone-feeds
	autoclean
}


# main()
clear
print_credits
check_root
check_debian_distro
check_sudo
clear
if [ ! -f /usr/bin/dialog ]; then
	echo -e "${BLUE}[+] Installing dialog package...${RESET}"
	apt update
	apt install -y dialog
fi
echo -e "${BLUE}[+] Running script${RESET}"

DIALOG_CANCEL=1
DIALOG_ESC=255
HEIGHT=0
WIDTH=0

display_result() {
  dialog --title "$1" \
    --no-collapse \
    --msgbox "$result" 0 0
}

while true; do
  exec 3>&1
  selection=$(dialog \
    --backtitle "(c) 2021 - CS3 Group (https://cs3group.com) by Pedro C. aka s4ur0n (@NN2ed_s4ur0n) · OpenVAS Installer for Debian 11" \
    --title "Menu" \
    --clear \
    --cancel-label "Exit" \
    --menu "Please select:" $HEIGHT $WIDTH 7 \
    "1" "Optimize TCP/IP Stack & System Limits for OpenVAS" \
    "2" "Optimize network throughput" \
    "3" "Add 4 GB extra swap for OpenVAS" \
    "4" "Install Remote Scan Sensor for OpenVAS" \
    "5" "Check Remote Scan Sensor for OpenVAS services" \
    "6" "Tips" \
    2>&1 1>&3)
  exit_status=$?
  exec 3>&-
  case $exit_status in
    $DIALOG_CANCEL)
      clear
      echo "Program terminated."
      exit
      ;;
    $DIALOG_ESC)
      clear
      echo "Program aborted." >&2
      exit 1
      ;;
  esac
  case $selection in
	  0 )
			clear
			echo "Program terminated."
			;;
	  1 )
			clear
			system_optimize
			result="System status (TCP/IP Stack & System Limits) has been optimized for OpenVAS!"
			display_result "TCP/IP Stack & System Limits"
			;;
	  2 )
			clear
			network_throughput
			result=$(systemctl status tuned.service && ps aux | grep tuned | grep network)
			display_result "Network Throughput Status"
			;;
	  3 )
			clear
			add_more_swap
			result=$(free -h -w)
			display_result "System Memory"
			;;
	  4 )
			clear
			install_remote_sensor
			IP=$(ip route get 8.8.8.8 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}')
			result="Remote Scan Sensor for OpenVAS has been installed into your system (please, enter with ssh -p 9390 root@${IP} and use your private key or p4$$w0rd as default. Enjoy it!"
			display_result "Remote Scan Sensor for OpenVAS sucessfully installed!"
			;;
		5 )
			clear
			check_services
			result="Is all ok? Please report systemd fails to authors with logs. Thanks in advance ;)"
			display_result "OpenVAS systemd services"
			;;
		6 )
			clear
			result="Change admin password:\n # gvmd --user=admin --new-password=YourP4SSHere\n\nScan Status:\n systemctl -a --no-pager status ospd-openvas && ps -aux --forest ..."
			display_result "Tips about Remote Scan Sensor for OpenVAS"
  esac
done

