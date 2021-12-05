#!/usr/bin/env bash

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
	echo -e "${BLUE}| OpenVAS 21.04 Remote Sensor Installer for Debian 11 (Bullseye) |${RESET}"
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


check_dialog() {
	if [ ! -f /usr/bin/dialog ]; then
		echo -e "${BLUE}[+] Installing dialog package...${RESET}"
		apt update
		apt install -y dialog
		press_any_key
	fi
}


create_services() {
	cat << 'EOF' > /etc/systemd/system/ssh-tunnel-by-user@.service 
[Unit]
Description=Setup a secure tunnel to %I
After=network.target

[Service]
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
EnvironmentFile=/etc/default/ssh-tunnel-by-user@%i
ExecStart=/usr/bin/sshpass -p ${PASS} /usr/bin/ssh -p ${PORT} -o 'StrictHostKeyChecking no' -o 'UserKnownHostsFile /dev/null' -nNT -L ${BASE_DIR}/var/run/remote_${IP_DASH}.sock:/var/run/ospd/ospd.sock ${USER}@${IP}
ExecStop=rm "${BASE_DIR}/var/run/remote_${IP_DASH}.sock"

[Install]
WantedBy=multi-user.target
EOF
	cat << 'EOF' > /etc/systemd/system/ssh-tunnel-by-cert@.service 
[Unit]
Description=Setup a secure tunnel to %I
After=network.target

[Service]
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
EnvironmentFile=/etc/default/ssh-tunnel-by-cert@%i
ExecStart=/usr/bin/ssh -p ${PORT} -i ${BASE_DIR}/.ssh/openvas-agent -o 'StrictHostKeyChecking no' -o 'UserKnownHostsFile /dev/null' -nNT -L ${BASE_DIR}/var/run/remote_${IP_DASH}.sock:/var/run/ospd/ospd.sock root@${IP}
ExecStop=rm "${BASE_DIR}/var/run/remote_${IP_DASH}.sock"

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}



# main()
clear
print_credits
check_root
check_sudo
check_dialog
create_services
clear
# Local base directory (from installation)
BASE_DIR=/opt/gvm

# Defaults (Example)
IP=172.16.113.6
PORT=9390
AUTH=1
USER="root"
PASS="p4\$\$w0rd"


# main()
clear
IP=$(dialog --backtitle "RS3 - Remote Sensor Scanner Setup by CS3 Group (https://cs3group.com)" --inputbox "Remote IP sensor:" 0 0 $IP 2>&1 1>/dev/tty);
IP_DASH=$(echo $IP | tr  '.' '-')
PORT=$(dialog --backtitle "RS3 - Remote Sensor Scanner Setup by CS3 Group (https://cs3group.com)" --inputbox "Remote Port:" 0 0 $PORT 2>&1 1>/dev/tty);
AUTH=$(dialog --backtitle "RS3 - Remote Sensor Scanner Setup by CS3 Group (https://cs3group.com)" --radiolist "Remote Scan Sensor Authentication Method" 10 50 2 "1" "Digital Certificate" "on" "2" "username + password" "off" 2>&1 1>/dev/tty);
case $AUTH in
   1 ) 
		su -c "
			umask 077 && test -d $BASE_DIR/.ssh || mkdir $BASE_DIR/.ssh ;\
			echo -e \"-----BEGIN OPENSSH PRIVATE KEY-----\" > $BASE_DIR/.ssh/openvas-agent ;\
			echo -e \"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\" >> $BASE_DIR/.ssh/openvas-agent ;\
			echo -e \"QyNTUxOQAAACCkbzAM30okkhA3YO81FLZqbDdqIxLyyB2paVrjYq8n6wAAAJijsoSBo7KE\" >> $BASE_DIR/.ssh/openvas-agent ;\
			echo -e \"gQAAAAtzc2gtZWQyNTUxOQAAACCkbzAM30okkhA3YO81FLZqbDdqIxLyyB2paVrjYq8n6w\" >> $BASE_DIR/.ssh/openvas-agent ;\
			echo -e \"AAAEBV8n318/Fn+QKTwLjIrK/8r0ZOA5w8Vdllg2gFS/n2IKRvMAzfSiSSEDdg7zUUtmps\" >> $BASE_DIR/.ssh/openvas-agent ;\
			echo -e \"N2ojEvLIHalpWuNiryfrAAAADnM0dXIwbkBNQVdJTElOAQIDBAUGBw==\" >> $BASE_DIR/.ssh/openvas-agent
			echo -e \"-----END OPENSSH PRIVATE KEY-----\" >> $BASE_DIR/.ssh/openvas-agent " gvm
		echo -e "PORT=$PORT" > /etc/default/ssh-tunnel-by-cert@$IP_DASH
		echo -e "BASE_DIR=$BASE_DIR" >> /etc/default/ssh-tunnel-by-cert@$IP_DASH
		echo -e "IP=$IP" >> /etc/default/ssh-tunnel-by-cert@$IP_DASH
		echo -e "IP_DASH=$IP_DASH" >> /etc/default/ssh-tunnel-by-cert@$IP_DASH
		systemctl enable "ssh-tunnel-by-cert@$IP_DASH.service"
		systemctl start "ssh-tunnel-by-cert@$IP_DASH.service"
	    ;;
   2 ) 
		if [ ! -f /usr/bin/sshpass ]; then
			echo -e "${BLUE}[+] Installing sshpass package...${RESET}"
			apt update
			apt install -y sshpass
		fi
		USER=$(dialog --backtitle "RS3 - Remote Sensor Scanner Setup by CS3 Group (https://cs3group.com)" --inputbox "Remote user with root privileges:" 0 0 $USER 2>&1 1>/dev/tty);
	  	PASS=$(dialog --backtitle "RS3 - Remote Sensor Scanner Setup by CS3 Group (https://cs3group.com)" --insecure --passwordbox "Remote $USER password:" 0 0 $PASS 2>&1 1>/dev/tty);
	  	echo -e "PORT=$PORT" > /etc/default/ssh-tunnel-by-user@$IP_DASH
	  	echo -e "BASE_DIR=$BASE_DIR" >> /etc/default/ssh-tunnel-by-user@$IP_DASH
		echo -e "IP=$IP" >> /etc/default/ssh-tunnel-by-user@$IP_DASH
		echo -e "IP_DASH=$IP_DASH" >> /etc/default/ssh-tunnel-by-user@$IP_DASH
		echo -e "USER=$USER" >> /etc/default/ssh-tunnel-by-user@$IP_DASH
		echo -e "PASS=$PASS" >> /etc/default/ssh-tunnel-by-user@$IP_DASH
		systemctl enable "ssh-tunnel-by-user@$IP_DASH.service"
		systemctl start "ssh-tunnel-by-user@$IP_DASH.service"
   		;;
   255) echo "[ESC] key pressed. Aborted"
		exit -1
		;;
esac
clear
echo -e "${BLUE}[+] Installing remote scanner...${RESET}"
su -c "/opt/gvm/sbin/gvmd --create-scanner=\"remote-$IP_DASH\" --scanner-type=\"OpenVas\" --scanner-host=/opt/gvm/var/run/remote_$IP_DASH.sock" gvm
UUID=$(sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --get-scanners | grep $IP_DASH | cut -d ' ' -f1")
su -c "/opt/gvm/sbin/gvmd --verify-scanner=${UUID}" gvm
press_any_key
dialog --backtitle "RS3 - Remote Sensor Scanner Setup by CS3 Group (https://cs3group.com)" --title "Remote Sensor Scanner for OpenVAS" --msgbox "\nSuccessfully installed remote scan sensor for OpenVAS on $IP\n\nThanks for use me!" 10 40 
clear
