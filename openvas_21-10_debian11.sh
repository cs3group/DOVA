#!/usr/bin/env bash

# +-------------------------------------------------------------+
# | OpenVAS 21.4 Installer for Debian 11 (Bullseye)             |
# | (c) 2021 CS3 Group · https://cs3group.com                   |
# | By Pedro C. aka s4ur0n (@NN2ed_s4ur0n)                      |
# | Installation testing by @Belky318, @gibdeon & Superfume     |
# | Licensed under the GNU General Public License v2.0 or later |
# | Manual script blog (original idea)                          |
# | https://sadsloth.net/post/install-gvm-20_08-src-on-debian/  |
# | https://www.libellux.com/openvas/                           |
# |                                                             |
# | OpenVAS Licenses:                                           |
# | Copyright (C) 2018-2020 Greenbone Networks GmbH             |
# | Licensed under the GNU General Public License v2.0 or later |
# +-------------------------------------------------------------+

# OPENVAS_ADMIN_PWD="4dm1nOpenVAS2110isYourP4ss" (Only a-zA-Z0-9)
OPENVAS_ADMIN_PWD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
BLUE=`tput setaf 6; tput bold`
YELLOW=`tput setaf 3`
RESET=`tput sgr0`
SUDO="sudo"
#
BRANCH="main"	# Main/master are development branches in OpenVAS. Try "stable"
LATEST="21.4.4"
#
GVM_LIBS="https://github.com/greenbone/gvm-libs.git"
OPENVAS="https://github.com/greenbone/openvas.git"
GVMD="https://github.com/greenbone/gvmd.git"
OPENVAS_SMB="https://github.com/greenbone/openvas-smb.git"
GSA="https://github.com/greenbone/gsa.git"
OSPD_OPENVAS="https://github.com/greenbone/ospd-openvas.git"
OSPD="https://github.com/greenbone/ospd.git"
PG_GVM="https://github.com/greenbone/pg-gvm"
#
TYPE=Release
BASE=/opt/gvm
#


press_any_key() {
	read -t 5 -n 1 -s -r -p "${YELLOW}[+] Press any key to continue or wait 5 seconds... ${RESET}"
	echo " "
}


print_credits() {
	echo -e "${BLUE}+-------------------------------------------------------------+${RESET}"
	echo -e "${BLUE}| OpenVAS $BRANCH Installer for Debian 11 (Bullseye)          |${RESET}"
	echo -e "${BLUE}| (c) 2021 CS3 Group · https://cs3group.com                   |${RESET}"
	echo -e "${BLUE}| By Pedro C. aka s4ur0n (@NN2ed_s4ur0n)                      |${RESET}"
	echo -e "${BLUE}| Installation testing by @Belky318, @gibdeon & Superfume     |${RESET}"
	echo -e "${BLUE}| Licensed under the GNU General Public License v2.0 or later |${RESET}"
	echo -e "${BLUE}| Manual script post (original idea)                          |${RESET}"
	echo -e "${BLUE}| https://sadsloth.net/post/install-gvm-20_08-src-on-debian/  |${RESET}"
	echo -e "${BLUE}| https://www.libellux.com/openvas/                           |${RESET}"
	echo -e "${BLUE}|                                                             |${RESET}"
	echo -e "${BLUE}| OpenVAS Licenses:                                           |${RESET}"
	echo -e "${BLUE}| Copyright (C) 2018-2021 Greenbone Networks GmbH             |${RESET}"
	echo -e "${BLUE}| Licensed under the GNU General Public License v2.0 or later |${RESET}"
	echo -e "${BLUE}+-------------------------------------------------------------+${RESET}"
	echo -e " "
	press_any_key
}


check_root() {
	[[ $(id -u) -ne 0 ]] && { 
		echo -e "${BLUE}Please run this script as root (or 'su -' if you have privileges)!${RESET}"
		exit -1
	}
}


check_debian_distro() {
	VERSION=$(sed 's/\..*//' /etc/debian_version)
	if [[ $VERSION != 11 ]]; then
        echo -e "${BLUE}This script currently works only on Debian 11 (Bullseye)${RESET}"
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


openvpn_server_install() {
	clear
	echo -e "${BLUE}[+] Installing OpenVPN...${RESET}"
	mkdir -p /opt/vpn
	cd /opt/vpn
	curl -O https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
	chmod u+x openvpn-install.sh
	./openvpn-install.sh
	echo -e "${BLUE}[+] Done!${RESET}"
	press_any_key
}


set_locale() {
	clear
	echo -e "${BLUE}[+] Generating locales${RESET}"
	locale-gen en_US.UTF-8
	locale-gen es_ES.UTF-8
	export LC_ALL="C"
}


install_dependencies() {
	clear
	echo -e "${BLUE}[+] Installing binaries and dependencies...${RESET}"
	apt update
	apt -y upgrade
	apt purge
	apt -y autoremove
	# system tools
	apt install -y build-essential curl git gnupg gnutls-bin net-tools nmap rsync screen smbclient snmp socat sshpass sudo tmux unzip vim wget
	# Daemons (required)
	apt install -y redis-server postgresql postgresql-contrib postgresql-server-dev-all
	# gvm-libs
	apt install -y cmake pkg-config libglib2.0-dev libgpgme-dev libgnutls28-dev libssh-gcrypt-dev libhiredis-dev libxml2-dev libpcap-dev libnet1-dev libldap2-dev libradcli-dev
	# openvas-smb
	apt install -y gcc-mingw-w64 heimdal-dev libpopt-dev libunistring-dev
	# openvas
	apt install -y bison libksba-dev libsnmp-dev doxygen
	# gvmd
	apt install -y libical-dev xsltproc xml-twig-tools
	# gsad
	apt install -y libmicrohttpd-dev libpthreadpool-dev libpthread-stubs0-dev nodejs npm xmltoman
	npm --global install yarn
	[[ -f /usr/bin/yarn ]] && rm /usr/bin/yarn
	ln -s /usr/local/bin/yarn /usr/bin/yarn
	# ospd
	apt install -y python3-pip virtualenv python3-psutil python3-defusedxml python3-lxml python3-paramiko
	pip install packaging
	# Optional (reports, recommended)
	apt install -y texlive-latex-extra --no-install-recommends
	apt install -y texlive-fonts-recommended
	# clean
	apt -y autoremove
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


create_gvm_profile() {
	clear
	echo -e "${BLUE}[+] Creating gvm profile for OpenVAS${RESET}"
	echo 'export PATH="$PATH:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin"' | tee -a /etc/profile.d/gvm.sh
	chmod 0755 /etc/profile.d/gvm.sh
	source /etc/profile.d/gvm.sh
	bash -c 'cat << EOF > /etc/ld.so.conf.d/gvm.conf
# gmv libs location
/opt/gvm/lib
EOF'
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


create_gvm_user() {
	clear
	echo -e "${BLUE}[+] Creating gvm user${RESET}"
	mkdir -p /opt/gvm
	adduser gvm --disabled-password --home /opt/gvm/ --no-create-home --gecos ''
	usermod -aG redis gvm
	chown gvm:gvm /opt/gvm/
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


add_users_to_sudo() {
	clear
	echo -e "${BLUE}[+] Adding users to sudoers${RESET}"
	usermod -aG sudo gvm
	usermod -aG sudo postgres
	echo -e "gvm ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


clone_repositories_stable() {
	clear
	echo -e "${BLUE}[+] Clonning latest Stable OpenVAS repositories from github${RESET}"
	mkdir -p /opt/gvm/src
	cd /opt/gvm/src
	git clone -b $BRANCH ${PG_GVM}
	wget https://github.com/greenbone/gvm-libs/archive/refs/tags/v21.4.3.zip
	unzip v21.4.3.zip 
	rm v21.4.3.zip
	mv gvm-libs-21.4.3 gvm-libs
	wget https://github.com/greenbone/openvas-scanner/archive/refs/tags/v21.4.3.zip
	unzip v21.4.3.zip
	rm v21.4.3.zip
	mv openvas-scanner-21.4.3 openvas
	wget https://github.com/greenbone/gvmd/archive/refs/tags/v$LATEST.zip
	unzip v$LATEST.zip
	rm v$LATEST.zip
	mv gvmd-$LATEST gvmd
	wget https://github.com/greenbone/openvas-smb/archive/refs/tags/v21.4.0.zip
	unzip v21.4.0.zip
	rm v21.4.0.zip
	mv openvas-smb-21.4.0 openvas-smb
	wget https://github.com/greenbone/gsa/archive/refs/tags/v21.4.3.zip
	unzip v21.4.3.zip
	rm v21.4.3.zip
	mv gsa-21.4.3 gsa
	wget https://github.com/greenbone/ospd-openvas/archive/refs/tags/v21.4.3.zip 
	unzip v21.4.3.zip
	rm v21.4.3.zip
	mv ospd-openvas-21.4.3 ospd-openvas
	wget https://github.com/greenbone/ospd/archive/refs/tags/v$LATEST.zip
	unzip v$LATEST.zip
	rm v$LATEST.zip
	mv ospd-$LATEST ospd
	chown -R gvm:gvm /opt/gvm
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


clone_repositories_latest() {
	clear
	echo -e "${BLUE}[+] Clonning latest OpenVAS (v$BRANCH) repositories from github${RESET}"
	mkdir -p /opt/gvm/src
	cd /opt/gvm/src
	# Don't use master branch (dev)... or check if it's working
	echo -e "    ${YELLOW}master and gsa-21.04 are development branches. Those branches may break every time. If you are not a developer and can’t dig into our code to fix such things by yourself (and possibly contribute code) please don’t use a development branch.${RESET}"
	echo -e " "
	echo -e "    Please see ${YELLOW}https://community.greenbone.net/t/something-broken-between-gvm-libs-and-gsad/6872${RESET}"
	echo -e '    \U0001f602\U0001f602\U0001f602 Riding an \U0001F984 (\U0001F44D)'
	echo -e " "
    git clone -b ${BRANCH} --single-branch ${GVM_LIBS}
    git clone -b ${BRANCH} --single-branch ${OPENVAS}
    git clone -b ${BRANCH} --single-branch ${GVMD}
    git clone -b ${BRANCH} --single-branch ${GSA}
    git clone -b ${BRANCH} --single-branch ${OSPD_OPENVAS}
    git clone -b ${BRANCH} --single-branch ${OSPD}
    git clone -b ${BRANCH} --single-branch ${OPENVAS_SMB}
	git clone -b ${BRANCH} ${PG_GVM}
	chown -R gvm:gvm /opt/gvm
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


compile_gvm_libs() {
	clear
	echo -e "${BLUE}[+] Compiling gvm_libs${RESET}"
	cat << EOF > /usr/lib/tmpfiles.d/run.conf
d /run/gvm 0777 gvm gvm
EOF
	mkdir -p /run/gvm
	chown gvm:gvm /run/gvm
	sudo -u gvm -H sh -c "cd /opt/gvm/src/gvm-libs ;\
	export PKG_CONFIG_PATH=$BASE/lib/pkgconfig:$PKG_CONFIG_PATH ;\
	rm -fr build 2>&1 ;\
	mkdir build ;\
	cd build ;\
	cmake -DCMAKE_INSTALL_PREFIX=$BASE -DCMAKE_BUILD_TYPE=$TYPE .. ;\
	make ;\
	sudo make install ;\
	cd /opt/gvm/src"
	chown -R gvm:gvm /opt/gvm
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


compile_openvas_smb() {
	clear
	echo -e "${BLUE}[+] Compiling OpenVAS SMB${RESET}"
	sudo -u gvm -H sh -c "cd /opt/gvm/src/openvas-smb ;\
 	export PKG_CONFIG_PATH=$BASE/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 	rm -fr build 2>&1 ;\
 	mkdir build ;\
 	cd build/ ;\
 	cmake -DCMAKE_INSTALL_PREFIX=$BASE -DCMAKE_BUILD_TYPE=$TYPE .. ;\
 	make ;\
 	make install ;\
 	cd /opt/gvm/src"
 	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


compile_openvas() {
	clear
	echo -e "${BLUE}[+] Compiling OpenVAS${RESET}"
	mkdir -p /var/log/gvm
	chown gvm:gvm /var/log/gvm
	mkdir -p /etc/openvas
	chown gvm:gvm /etc/openvas
	mkdir -p /var/lib/openvas/gnupg
	chown -R gvm:gvm /var/lib/openvas
	sudo -u gvm -H sh -c "cd /opt/gvm/src/openvas ;\
 	export PKG_CONFIG_PATH=$BASE/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 	rm -fr build 2>&1 ;\
 	mkdir build ;\
 	cd build/ ;\
 	cmake -DCMAKE_INSTALL_PREFIX=$BASE -DCMAKE_BUILD_TYPE=$TYPE .. ;\
 	make ;\
 	make install ;\
 	cd /opt/gvm/src"
 	cat << EOF > /tmp/patch
--- sudoers.2	2021-08-22 11:49:17.750642982 +0200
+++ sudoers	2021-08-22 11:51:57.778960791 +0200
@@ -8,7 +8,8 @@
 #
 Defaults	env_reset
 Defaults	mail_badpass
-Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
+Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin"
+

 # Host alias specification

@@ -21,7 +22,8 @@

 # Allow members of group sudo to execute any command
 %sudo	ALL=(ALL:ALL) ALL
-
+gvm ALL = NOPASSWD: /opt/gvm/sbin/openvas
+gvm ALL = NOPASSWD: /opt/gvm/sbin/gsad
 # See sudoers(5) for more information on "@include" directives:

 @includedir /etc/sudoers.d
EOF
	patch -u /etc/sudoers -i /tmp/patch
	rm /tmp/patch
 	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


fix_redis() {
	clear
	echo -e "${BLUE}[+] Fixing Redis...${RESET}"
	export LC_ALL="C"
	ldconfig
	cp /etc/redis/redis.conf /etc/redis/redis.orig
	cp /opt/gvm/src/openvas/config/redis-openvas.conf /etc/redis/
	chown redis:redis /etc/redis/redis-openvas.conf
	echo "db_address = /run/redis-openvas/redis.sock" > /opt/gvm/etc/openvas/openvas.conf
	systemctl enable redis-server@openvas.service
	systemctl start redis-server@openvas.service
	# systemctl status redis-server@openvas.service
	sysctl -w net.core.somaxconn=2048
	sysctl vm.overcommit_memory=1
	echo "net.core.somaxconn=2048"  >> /etc/sysctl.conf
	echo "vm.overcommit_memory=1" >> /etc/sysctl.conf
	cat << EOF > /etc/systemd/system/disable-thp.service
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOF
	ln -s /run/redis-openvas/redis.sock /run/redis/redis.sock
	systemctl daemon-reload
	systemctl start disable-thp
	systemctl enable disable-thp
	systemctl restart redis-server
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}	


nvt_sync() {
	clear
	echo -e "${BLUE}[+] Updating NVTs...${RESET}"
	sudo -u gvm -H sh -c "/opt/gvm/bin/greenbone-nvt-sync"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


compile_gvmd() {
	clear
	echo -e "${BLUE}[+] Building OpenVAS Manager (gvmd)...${RESET}"
	mkdir -p /var/lib/gvm/gvmd
	chown -R gvm:gvm /var/lib/gvm
	mkdir -p /etc/gvm
	chown gvm:gvm /etc/gvm
	touch /lib/systemd/system/gvmd.service
	chown gvm:gvm /lib/systemd/system/gvmd.service
	mkdir -p /etc/logrotate.d/gvmd
	chown -R gvm:gvm /etc/logrotate.d/gvmd
	chown root:root /etc/logrotate.d
	# Se cambia por root
	sudo -u root -H sh -c "cd /opt/gvm/src/gvmd ;\
 	export PKG_CONFIG_PATH=$BASE/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 	rm -fr build 2>&1 ;\
 	mkdir build ;\
 	cd build/ ;\
 	cmake -DCMAKE_INSTALL_PREFIX=$BASE -DCMAKE_BUILD_TYPE=$TYPE -DPostgreSQL_TYPE_INCLUDE_DIR=/usr/include/postgresql/ .. ;\
 	make ;\
 	make install ;\
 	mkdir -p /opt/gvm/var/run/gvm ;\
 	cd /opt/gvm/src"
 	# Se vuelven a cambiar los permisos
 	chown -R gvm:gvm /opt/gvm
 	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


configure_postgresql() {
	clear
	echo -e "${BLUE}[+] Configuring postgresql...${RESET}"
	sudo -u gvm -H sh -c "cd /opt/gvm/src/pg-gvm ;\
	rm -fr build 2>&1 ;\
	mkdir build ;\
	cd build ;\
	export PKG_CONFIG_PATH=$BASE/lib/pkgconfig:$PKG_CONFIG_PATH ;\
	cmake -DCMAKE_INSTALL_PREFIX=$BASE -DCMAKE_BUILD_TYPE=$TYPE -DPostgreSQL_TYPE_INCLUDE_DIR=/usr/include/postgresql/ .. ;\
	make ;\
	sudo make install ;\
	cd /opt/gvm/src"
	sudo -u postgres -H sh -c "cd /tmp ;\
	export LC_ALL='C' ;\
	createuser -DRS gvm ;\
	createdb -O gvm gvmd ;\
	psql -U postgres -c 'create role dba with superuser noinherit;' ;\
	psql -U postgres -c 'grant dba to gvm;' ;\
	psql -U postgres gvmd -c 'create extension \"uuid-ossp\";' ;\
	psql -U postgres gvmd -c 'create extension \"pgcrypto\";' ;\
	psql -U postgres gvmd -c 'create extension \"pg-gvm\";' "
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


manage_certs() {
	clear
	echo -e "${BLUE}[+] Creating OpenVAS CA & Certificates...${RESET}"
	# Modify CA settings
	sed -i 's#GVM_CERTIFICATE_LIFETIME=${GVM_CERTIFICATE_LIFETIME:-730}#GVM_CERTIFICATE_LIFETIME=${GVM_CERTIFICATE_LIFETIME:-1096}#g' /opt/gvm/src/gvmd/build/tools/gvm-manage-certs
	sed -i 's#GVM_CERTIFICATE_COUNTRY=${GVM_CERTIFICATE_COUNTRY:-"DE"}#GVM_CERTIFICATE_COUNTRY=${GVM_CERTIFICATE_COUNTRY:-"ES"}#g' /opt/gvm/src/gvmd/build/tools/gvm-manage-certs
	sed -i 's#GVM_CERTIFICATE_STATE=${GVM_CERTIFICATE_STATE:-""}#GVM_CERTIFICATE_STATE=${GVM_CERTIFICATE_STATE:-"Madrid"}#g' /opt/gvm/src/gvmd/build/tools/gvm-manage-certs
	sed -i 's/Osnabrueck/Madrid/g' /opt/gvm/src/gvmd/build/tools/gvm-manage-certs
	sed -i 's/GVM Users/OpenVAS IT Security/g' /opt/gvm/src/gvmd/build/tools/gvm-manage-certs
	sed -i 's#GVM_CERTIFICATE_ORG_UNIT=${GVM_CERTIFICATE_ORG_UNIT:-""}#GVM_CERTIFICATE_ORG_UNIT=${GVM_CERTIFICATE_ORG_UNIT:-"IT Security"}#g' /opt/gvm/src/gvmd/build/tools/gvm-manage-certs
	sudo -u gvm -H sh -c "/opt/gvm/bin/gvm-manage-certs -f -a"
	sudo -u gvm -H sh -c "mkdir -p /opt/gvm/var/lib/gvm/CA"
	sudo -u gvm -H sh -c "mkdir -p /opt/gvm/var/lib/gvm/private/CA"
	sudo -u gvm -H sh -c "cp /var/lib/gvm/CA/* /opt/gvm/var/lib/gvm/CA"
	sudo -u gvm -H sh -c "cp /var/lib/gvm/private/CA/* /opt/gvm/var/lib/gvm/private/CA"
	echo -e "    Created OpenVAS CA at /var/lib/gvm/private/CA/ and /var/lib/gvm/CA directories"
	echo -e "    Copying certs to /opt/gvm/var/lib/gvm/CA/ & /opt/gvm/var/lib/gvm/private/CA for gsad"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


create_admin_user() {
	clear
	echo -e "${BLUE}[+] Creating admin user for OpenVAS...${RESET}"
	mkdir -p /run/gvm
	touch /run/gvm/gvm-checking
	chown -R gvm:gvm /run/gvm
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --create-user=admin --password=${OPENVAS_ADMIN_PWD}"
	UUID=$(sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --get-users --verbose | grep admin | cut -d ' ' -f2")
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value ${UUID}"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --get-users --verbose"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


update_feeds() {
	clear
	echo -e "${BLUE}[+] Downloading plugins for OpenVAS...${RESET}"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/greenbone-feed-sync --type GVMD_DATA"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/greenbone-feed-sync --type SCAP"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/greenbone-feed-sync --type CERT"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/openvas -u"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


compile_gsa() {
	clear
	echo -e "${BLUE}[+] Building OpenVAS gsa...${RESET}"
	touch /lib/systemd/system/gsad.service
	chown gvm:gvm /lib/systemd/system/gsad.service
	cat << EOF > /tmp/credits.patch
--- about.js_old	2021-09-01 14:45:47.569049578 +0200
+++ about.js	2021-09-05 12:31:01.299597589 +0200
@@ -62,6 +62,9 @@
               ? gmp.settings.vendorVersion
               : _('Version {{version}}', {version: GSA_VERSION})}
           </h3>
+	  <h4>
+		'OpenVAS Installer' for Debian 11 by <a href="https://cs3group.com" target="_new">CS3 Group</a> By @NN2ed_s4ur0n
+	  </h4><DivP>&nbsp;</DivP>
           <DivP>
             {_(
               'The Greenbone Security Assistant (GSA) is the web-based ' +
EOF
	chown gvm:gvm /tmp/credits.patch
	# Date format (es-ES)
 	sudo -u gvm -H sh -c "sed -i \"/^export const/i import 'moment\\/locale\\/es\\.js';\" /opt/gvm/src/gsa/gsa/src/gmp/models/date.js"
	sudo -u gvm -H sh -c "cd /opt/gvm/src/gsa ;\
 	export PKG_CONFIG_PATH=$BASE/lib/pkgconfig:$PKG_CONFIG_PATH ;\
 	rm -fr build 2>&1 ;\
 	patch /opt/gvm/src/gsa/gsa/src/web/pages/help/about.js < /tmp/credits.patch ;\
 	rm /tmp/credits.patch ;\
 	sed -i 's#</Link>#</Link> Debian 11 Installer by <Link target=\"_blank\" rel=\"noopener noreferrer\" href=\"https://cs3group.com\">CS<sup>3</sup> Group</Link>#g' /opt/gvm/src/gsa/gsa/src/web/components/structure/footer.js ;\
 	sed -i \"s/};/es: {name: 'Castellano (España)', native_name: 'Castellano',},};/g\" /opt/gvm/src/gsa/gsa/src/gmp/locale/languages.js ;\
 	mkdir build ;\
 	cd build/ ;\
 	cmake -DCMAKE_INSTALL_PREFIX=$BASE -DCMAKE_BUILD_TYPE=$TYPE .. ;\
 	make ;\
 	make install ;\
 	touch /opt/gvm/var/run/gsad.pid ;\
 	wget -O $BASE/share/gvm/gsad/web/locales/gsa-es.json https://surt.cs3group.com/gsa-es_ES.UTF-8.json ;\
 	cd /opt/gvm/src"
 	# Privilege port as usermode
 	echo -e "    Danger! Use this to start a service as non-root but bind low ports"
 	sysctl net.ipv4.ip_unprivileged_port_start=1
 	echo "net.ipv4.ip_unprivileged_port_start=1" >> /etc/sysctl.conf
	/usr/sbin/sysctl --system
	mkdir -p /opt/gvm/var/log/gvm
	touch /opt/gvm/var/log/gvm/gsad.log
	chown gvm:gvm /opt/gvm/var/log/gvm/gsad.log
	touch /opt/gvm/var/run/gsad.pid
	chown gvm:gvm /opt/gvm/var/run/gsad.pid
	chown -R gvm:gvm /opt/gvm/
 	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


build_ospd_openvas() {
	clear
	echo -e "${BLUE}[+] Building ospd for OpenVAS...${RESET}"
	su -c "cd /opt/gvm/src/ospd ;\
	export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH ;\
	export PYTHONPATH=/opt/gvm/.local/lib/python3.9/site-packages ;\
	mkdir -p /opt/gvm/var/log/gvm ;\
	touch /opt/gvm/var/log/gvm/ospd-scanner.log ;\
	python3 -m pip install . ;\
	python3 setup.py install --prefix=$BASE ;\
	cd /opt/gvm/src/ospd-openvas/ ;\
	python3 -m pip install . ;\
	python3 setup.py install --prefix=$BASE ;\
	cd /opt/gvm/src ;\
	virtualenv --python python3.9 /opt/gvm/bin/ospd-scanner/ ;\
	source /opt/gvm/bin/ospd-scanner/bin/activate ;\
	mkdir -p /opt/gvm/var/run/ospd/ ;\
	cd /opt/gvm/src/ospd/ ;\
	pip install packaging ;\
	pip3 install . ;\
	cd /opt/gvm/src/ospd-openvas/ ;\
	pip3 install . ;\
	cd /opt/gvm/src" gvm
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


create_systemd_files() {
	clear
	echo -e "${BLUE}[+] Creating systemd services...${RESET}"
	cat << EOF > /etc/systemd/system/gvmd.service
[Unit]
Description=Open Vulnerability Assessment System Manager Daemon
Documentation=man:gvmd(8) https://www.greenbone.net
Wants=postgresql.service
After=postgresql.service

[Service]
Type=simple
User=gvm
Group=gvm
PIDFile=/run/gvm/gvmd.pid
WorkingDirectory=/opt/gvm
ExecStart=/opt/gvm/sbin/gvmd -f -a 0.0.0.0 -p 9390 --gnutls-priorities=SECURE128:-AES-128-CBC:-CAMELLIA-128-CBC:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1 --osp-vt-update=/opt/gvm/var/run/ospd.sock
ExecReload=/bin/kill -HUP
KillMode=mixed
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
	IP=$(ip route get 8.8.8.8 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}')
	cat << EOF > /etc/systemd/system/gsad.service
[Unit]
Description=Greenbone Security Assistant (gsad)
Documentation=man:gsad(8) https://www.greenbone.net
After=network.target
Wants=gvmd.service

[Service]
Type=simple
PIDFile=/opt/gvm/var/run/gsad.pid
WorkingDirectory=/opt/gvm
ExecStart=/opt/gvm/sbin/gsad -f --drop-privileges=gvm --secure-cookie --mport=9390 --mlisten=${IP} --gnutls-priorities=SECURE128:-AES-128-CBC:-CAMELLIA-128-CBC:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
cat << EOF > /etc/systemd/system/ospd-openvas.service 
[Unit]
Description=Control the OpenVAS service
After=redis.service postgresql.service
Wants=gvmd.service gsad.service

[Service]
ExecStartPre=-rm -rf /opt/gvm/var/run/ospd-openvas.pid /opt/gvm/var/run/ospd.sock /opt/gvm/var/run/gvmd.sock
ExecStartPre=-sudo ln -s /run/redis-openvas/redis.sock /run/redis/redis.sock
Type=simple
User=gvm
Group=gvm
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin
ExecStart=/usr/bin/python3 /opt/gvm/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --log-file /opt/gvm/var/log/gvm/ospd-openvas.log --lock-file-dir /opt/gvm/var/run -u /opt/gvm/var/run/ospd.sock
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable gvmd
	systemctl enable gsad
	systemctl enable ospd-openvas
	systemctl start gvmd
	systemctl start gsad
	systemctl start ospd-openvas
	chown -R gvm:gvm /opt/gvm
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


check_services() {
	systemctl -a --no-pager status gvmd
	systemctl -a --no-pager status gsad
	systemctl -a --no-pager status ospd-openvas
	press_any_key
}


modify_scanner() {
	clear
	echo -e "${BLUE}[+] Searching and setting socks for OpenVAS scanners...${RESET}"
	UUID=$(sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --get-scanners | grep OpenVAS | cut -d ' ' -f1")
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --modify-scanner=${UUID} --scanner-host=/opt/gvm/var/run/ospd.sock"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --verify-scanner=${UUID}"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


update_crontab_feeds() {
	clear
	echo -e "${BLUE}[+] Creating sync data files into crontab...${RESET}"
	cat << EOF > /opt/gvm/sbin/update-greenbone-feeds 
#!/usr/bin/env bash
#/opt/gvm/bin/greenbone-nvt-sync
/opt/gvm/sbin/greenbone-feed-sync --type GVMD_DATA
/opt/gvm/sbin/greenbone-feed-sync --type SCAP
/opt/gvm/sbin/greenbone-feed-sync --type CERT
#/opt/gvm/sbin/openvas --update-vt-info
EOF
	chmod u+x /opt/gvm/sbin/update-greenbone-feeds
	chown gvm:gvm /opt/gvm/sbin/update-greenbone-feeds
	echo -e "1 1 * * * gvm /opt/gvm/sbin/update-greenbone-feeds 1>/dev/null 2>/dev/null" >> /etc/crontab
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


python_utils() {
	clear
	echo -e "${BLUE}[+] Installing python tools for OpenVAS..${RESET}"
	python3 -m pip install --user python-gvm
	pip3 install --user python-gvm
	sudo -u gvm -H sh -c "pip3 install --user gvm-tools"
	echo -e "    Testing it: gvm-cli socket --socketpath /opt/gvm/var/run/ospd.sock --xml \"<get_version/>\""
	press_any_key
}


nasl_extras() {
	clear
	echo -e "${BLUE}[+] Adding NASLs scripts for OpenVAS..${RESET}"
	cd /tmp
	echo Vulners NASL Plugins
	echo This service is not free... Please register at https://vulners.com/
	# echo Download it for free with chrome directly ;)
	# wget https://vulners.com/api/v3/archive/nasl/?type=centos
	# wget https://vulners.com/api/v3/archive/nasl/?type=debian
	# wget https://vulners.com/api/v3/archive/nasl/?type=ubuntu
	# wget https://vulners.com/api/v3/archive/nasl/?type=redhat
	# mkdir -p vulns-nasl
	# unzip centos_nasl_archive.zip -d vulns-nasl
	# unzip debian_nasl_archive.zip -d vulns-nasl
	# unzip ubuntu_nasl_archive.zip -d vulns-nasl
	# unzip redhat_nasl_archive.zip -d vulns-nasl
	# chown gvm:gvm vulns-nasl/*.nasl
	# cp vulns-nasl/*.nasl /opt/gvm/var/lib/openvas/plugins/
	# rm -fr vulns-nasl
	# systemctl stop gvmd.service
	# sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd -v --rebuild"
	# systemctl start gvmd.service
	# echo Repeat for rebuild all SCAP data (optional): --rebuild-scap
	echo Nessus NASL Plugins
	echo Download tar.gz file from https://plugins.nessus.org/v2/offline.php
	# ...
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


create_new_scanners() {
	clear
	echo -e "${BLUE}[+] Creating new scanners for OpenVAS...${RESET}"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --create-scanner=\"Localhost #2 OPENVAS Scanner\" --scanner-type=\"OpenVas\" --scanner-host=/opt/gvm/var/run/ospd.sock ;\
	/opt/gvm/sbin/gvmd --create-scanner=\"Localhost #3 OPENVAS Scanner\" --scanner-type=\"OpenVas\" --scanner-host=/opt/gvm/var/run/ospd.sock ;\
	/opt/gvm/sbin/gvmd --create-scanner=\"Localhost #4 OPENVAS Scanner\" --scanner-type=\"OpenVas\" --scanner-host=/opt/gvm/var/run/ospd.sock"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


unlimited_report_rows() {
	clear
	echo -e "${BLUE}[+] Creating unlimited reports for OpenVAS...${RESET}"
	sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --modify-setting 76374a7a-0569-11e6-b6da-28d24461215b --value 0 ;\
	/opt/gvm/sbin/gvmd --modify-setting 76374a7a-0569-11e6-b6da-28d24461215b --value 0"
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


install_openvas_reporting() {
	clear
	echo -e "${BLUE}[+] Installing OpenVAS Reporting Tool...${RESET}"
	sudo -u gvm -H sh -c "cd /opt/gvm ;\
	rm -fr openvasreporting ;\
	git clone https://github.com/TheGroundZero/openvasreporting.git ;\
	cd openvasreporting ;\
	pip3 install -r requirements.txt ;\
	pip3 install ."
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


update_iana_ports() {
	sudo -u gvm -H sh -c "cd /opt/gvm ;\
	[[ ! -d iana_service_ports ]] && rm -fr iana_service_ports ;\
	mkdir iana_service_ports ;\
	cd iana_service_ports ;\
	wget https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml ;\
	echo Only old versions: gvm-portnames-update service-names-port-numbers.xml"
}


get_scanconfigs() {
	clear
	echo -e "${BLUE}[+] Downloading scanconfigs (/root/scanconfigs) for importing it into OpenVas...${RESET}"
	[[ -d /root/scanconfigs ]] && rm -fr /root/scanconfigs
	mkdir -p /root/scanconfigs
	cd /root/scanconfigs
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/Policy_Datacom_20200930.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/Policy_EulerOS_20200824.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/Policy_GaussDB_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_bsi_tr_03116_4_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_bsi_tr_03116_4_20200817.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_it_grundschutz_kompendium_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_microsoft_2012_r2_server_secure_configuration_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_microsoft_2016_RTM_server_secure_configuration_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_microsoft_office2013_secure_configuration_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_microsoft_office2016_secure_configuration_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_windows10_secure_configuration_20200813.xml
	wget https://download.greenbone.net/scanconfigs/GOS_6.0/policy_windows8_secure_configuration_20200813.xml
	cd /root
	cat << EOF > ./policy_import.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gvm
import glob

from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

connection =gvm.connections.TLSConnection(hostname='HOSTNAME')
gmp = Gmp(connection)
gmp.authenticate('admin', 'PASS')

# Retrieve current GMP version
version = gmp.get_version()
pretty_print(version)

# Retrive new policies
new_policies=glob.glob("./scanconfigs/*.xml")

# Import new policies
for filename in new_policies:
    print("[+] Importing to Openvas Policy", filename)
    with open(filename) as f:
        lines = f.readlines()
    f.close()
    policy = ''.join(lines)
    cmd = gmp.import_policy(policy)
    pretty_print(cmd)
EOF
	sed -i "s/PASS/$OPENVAS_ADMIN_PWD/g" ./policy_import.py
	IP_SPACE=$(hostname -I | tr " " "\n" | grep -v "^$" | sort -t . -k 1,1n | head -1 | tr "\n" " ")
	IP=${IP_SPACE::-1}
	sed -i "s/HOSTNAME/$IP/g" ./policy_import.py
	chmod u+x ./policy_import.py
	python3 ./policy_import.py
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


get_portlists() {
	clear
	echo -e "${BLUE}[+] Downloading portlists (/root/portlists) for importing it into OpenVas...${RESET}"
	[[ -d /root/portlists ]] && rm -fr /root/portlists
	mkdir -p /root/portlists
	cd /root/portlists
	wget https://surt.cs3group.com/portlist-29ffea8e-3357-4b5c-8512-8447ffe54679.xml
	wget https://surt.cs3group.com/portlist-cd3481ea-dc50-4236-91f0-7b1467b3e15a.xml
	wget https://surt.cs3group.com/portlist-f0f7f917-31a0-4b05-b9a3-d56971b2a206.xml
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


get_gmpscripts() {
	clear
	echo -e "${BLUE}[+] Downloading GMP scripts (/opt/gvm/gmpscripts)...${RESET}"
	[[ -d /opt/gvm/gmpscripts ]] && rm -fr /opt/gvm/gmpscripts
	mkdir -p /opt/gvm/gmpscripts
	cd /opt/gvm/gmpscripts
	git clone https://github.com/greenbone/gvm-tools
	mv gvm-tools/scripts/*.py .
	rm -fr gvm-tools
	cd /opt/gvm
	chown -R gvm:gvm gmpscripts
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


main_install() {
	set_locale
	install_dependencies
	create_gvm_profile
	create_gvm_user
	add_users_to_sudo
	if [[ $1 = "stable" ]]; then
		clone_repositories_stable
	else
		clone_repositories_latest
	fi
	compile_gvm_libs
	compile_openvas_smb
	compile_openvas
	fix_redis
	nvt_sync
	compile_gvmd
	configure_postgresql
	manage_certs
	create_admin_user
	update_feeds
	compile_gsa
	build_ospd_openvas
	create_systemd_files
	modify_scanner
	update_crontab_feeds
	link_gmvd_socket
	link_ospd_socket
	create_check_scanners
}


extra_install() {
	python_utils
	nasl_extras
	create_new_scanners
	unlimited_report_rows
	install_openvas_reporting
	update_iana_ports
	get_scanconfigs
	get_portlists
	get_gmpscripts
}


link_gmvd_socket() {
	clear
	echo -e "${BLUE}[+] Linking gvmd socket...${RESET}"
	mkdir -p /run/gvm
	ln -s /opt/gvm/var/run/gvmd.sock /run/gvm
	chown -R gvm:gvm /run/gvm
	press_any_key
}


link_ospd_socket() {
	clear
	echo -e "${BLUE}[+] Linking ospd socket...${RESET}"
	mkdir -p /run/ospd
	ln -s /opt/gvm/var/run/ospd.sock /run/ospd
	chown -R gvm:gvm /run/ospd
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


create_check_scanners() {
	clear
	echo -e "${BLUE}[+] Creating check_scanners.sh script...${RESET}"
	cat << EOF > /opt/gvm/sbin/check_scanners.sh 
#!/bin/bash
UUID=$(sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --get-scanners | grep OpenVAS | cut -d ' ' -f1")
IFS=$'\n'
for scanner in ${UUID[*]}
do
	result=`sudo -u gvm -H sh -c "/opt/gvm/sbin/gvmd --verify-scanner=${scanner}"`
	echo "Testing scanner UUID: $scanner -> $result"
done
EOF
	chmod u+x /opt/gvm/sbin/check_scanners.sh
	chown gvm:gvm /opt/gvm/sbin/check_scanners.sh
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key

}


create_remote_sensor_script() {
	cd /root
	cat << 'EOFSENSOR' >./create_remote_sensor.sh
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
EOFSENSOR
	chmod u+x ./create_remote_sensor.sh
}


modify_issue() {
	echo -e "${BLUE}[+] Modifying issue banner...${RESET}"
	echo -e "Debian 11 (OpenVAS $BRANCH Installer by CS3 Group https://cs3group.com)" > /etc/issue
	echo -e " " >> /etc/issue
	IP=$(hostname -I | tr " " "\n" | grep -v "^$" | sort -t . -k 1,1n | head -1 | tr "\n" " ")
	echo -e "IP: $IP" >> /etc/issue
	echo -e "ssh root@$IP" >> /etc/issue
	echo -e "OpenVAS admin console: https://$IP (admin/$OPENVAS_ADMIN_PWD)" >> /etc/issue
	echo -e " " >> /etc/issue
	cp /etc/issue /etc/issue.net
	echo "${BLUE}[+] Done!${RESET}"
	press_any_key
}


install_openvas() {
	main_install "$1"
	extra_install
	modify_issue
	create_remote_sensor_script
	autoclean
}


# main()
clear
print_credits
check_root
source /etc/profile
source /root/.bashrc
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
    "4" "Install OpenVPN Server (recommended)" \
    "5" "Install latest stable OpenVAS from github" \
    "6" "Warning! Install latest dev $BRANCH OpenVAS from github" \
    "7" "Check OpenVAS services" \
    "8" "Check Scanners config" \
    "9" "Install remote sensors" \
    "0" "Tips" \
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
		openvpn_server_install
		result="OpenVPN sucessfully installed. Please, use /opt/vpn/openvpn-install.sh for management."
		display_result "OpenVPN Server installed"
		;;
    5 )
		clear
		install_openvas "stable"
		IP=$(ip route get 8.8.8.8 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}')
		result="OpenVAS latest stable has been installed into your system. Please, navigate to https://${IP} and use admin/${OPENVAS_ADMIN_PWD} for access to the latest OpenVAS. Please, wait for database population with new CVEs/CPEs/SCAP/NVTs... Use 'tail -f /opt/gvm/var/log/gvm/*.log' for logfiles. Thanks for your installation. Enjoy it!"
		display_result "OpenVAS sucessfully installed!"
		;;
	6 )
		clear
		install_openvas "dev"
		IP=$(ip route get 8.8.8.8 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}')
		result="OpenVAS latest (${BRANCH}) has been installed into your system. Please, navigate to https://${IP} and use admin/${OPENVAS_ADMIN_PWD} for access to the latest OpenVAS. Please, wait for database population with new CVEs/CPEs/SCAP/NVTs... Use 'tail -f /opt/gvm/var/log/gvm/*.log' for logfiles. Thanks for your installation. Enjoy it!"
		display_result "OpenVAS sucessfully installed!"
		;;
	7 )
		clear
		check_services
		result="Is all ok? Please report systemd fails to authors with logs. Thanks in advance ;)"
		display_result "OpenVAS systemd services"
		;;
	8 )
		clear
		result=$(sudo -u gvm -H sh -c "/opt/gvm/sbin/check_scanners.sh")  
		display_result "Scanner verification"
		;;
	9 )
		./create_remote_sensor.sh
		;;
	0 )
		clear
		result="Change admin password:\n # su - gvm\n \$ gvmd --user=admin --new-password=YourP4SSHere\n\nEnable debug:\n - Edit script and change 'TYPE=Debug', then recompile all."
		display_result "Tips about OpenVAS"
  esac
done


