#!/bin/bash

#
#Linux Security Script
#Writting by Team Kernel, CyberPatriot IX
#Copyright 2017
#This script is intelectual property of Team Kernel and its members.
#Use of this script by any other CyberPatriot team is prohibited without writen consent from the Team Kernel team captain or coach.
#
#Currently Supported Platforms: Ubuntu, Debian
#Currently Tested Platforms: Ubuntu 14.04, Debian 7
#

echo "Starting Linux Script"

password="D0gsD0gsD0gs!!!!"
echo Our password is $password

#Create script log file (for debuging)
echo "Linux Script Log File" > script-log.log

ssh_allowed=n
rdp_allowed=n
ipv6_allowed=n
shared_allowed=n
ftp_server=n
ftp_cllient=n
wordpress_allowed=n
apache_allowed=n
webserver_allowed=

echo "Allow SSH login? (y/n)"
read ssh_allowed
echo "Allow RDP login? (y/n)"
read rdp_allowed
echo "Is IPv6 required? (y/n)"
read ipv6_allowed
echo "Are shared folder required? (y/n)"
read shared_allowed
echo "Is ftp server required? (y/n)"
read ftp_server
echo "Is ftp client (FileZilla) required? (y/n)"
read ftp_client
echo "Is Wordpress required? (y/n)"
read wordpress_allowed
if [ "$wordpress_allowed" == "n" ]; then
  echo "Is Apache web server required? (y/n)"
  read apache_allowed
  if [ "$apache_allowed" == "n" ]; then
    echo "Is a different web server required? (y/n)"
    read webserver_allowed
  fi
  echo "Is PHP required? (y/n)"
  read php_allowed
  echo "Is mySQL required? (y/n)"
  read mysql_allowed
else
  apache_allowed=y
  php_allowed=y
  mysql_allowed=y
fi
clear

#Record the hostname for later
hostname=`hostname`

#Reset Repositories to Default

sudo rm -f /etc/sources.list
echo "Opening update configuration manager, please just click 'Close' and then 'Reload'"
sudo software-properties-gtk


#sudo cp /etc/apt/sources.list /etc/apt/sources.old
#cat /etc/*-release > release.log
#grep -E "^ID=" release.log > release_id.log
#sed -i -e 's/ID=//g' release_id.log
#release_id=`cat release_id.log`
#release_codename=`lsb_relase -sc`
#if [ "$release_id" == "ubuntu" ]; then
#  echo "Ubuntu Detected, reseting repositories to default"
# sudo echo "deb http://archive.ubuntu.com/ubuntu $release_codename main multiverse universe restricted" | sudo tee /etc/apt/sources.tmp
#  sudo echo "deb http://archive.ubuntu.com/ubuntu $release_codename-security main multiverse universe restricted" sudo tee -a /etc/apt/sources.tmp
#  #Setup Grsecurity
#  sudo echo "deb http://ubuntu.cr0.org/repo/ kernel-security/" | sudo tee -a /etc/apt/sources.tmp
#else
#  if [ "$release_id" == "debian" ]; then
#    echo "Debian detected, reseting repositories to default"
#    sudo echo "deb http://ftp.us.debian.org/debian/ $release_codename main" | sudo tee /etc/apt/sources.tmp
#    sudo echo "deb http://security.debian.org/ $release_codename/updates main" | sudo tee -a /etc/apt/sources.tmp
#    sudo echo "deb http://security.debian.org/ $release_codename-updates main" | sudo tee -a /etc/apt/sources.tmp
#  fi
#fi
#sudo mv -f /etc/apt/sources.tmp /etc/apt/sources.list

#Fix any errors with dpkg
sudo dpkg --configure -a

#Get things ready for unattended-upgrades
#sudo cp /etc/apt/apt.conf.d/10-periodic /etc/apt/apt.conf.d/10-periodic.old
#sudo echo "APT::Periodic::Update-Package-Lists \"1\";" | sudo tee /etc/apt/apt.conf.d/10periodic.tmp
#sudo echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" | sudo tee -a /etc/apt/apt.conf.d/10periodic.tmp
#sudo echo "APT::Periodic::AutoCleanInterval \"7\";" | sudo tee -a /etc/apt/apt.conf.d/10periodic.tmp
#sudo echo "APT::Periodic::Unattended-Upgrade \"1\";" | sudo tee -a /etc/apt/apt.conf.d/10periodic.tmp
#sudo mv -f /etc/apt/apt.conf.d/10-periodic.tmp /etc/apt/apt.conf.d/10-periodic

#Install Unattended Upgrade
echo "Installing Unattended Upgrades..."
sudo apt-get -y install unattended-upgrades
sudo unattended-upgrades
sudo service unattended-upgrades start
sudo update-rc.d unattended-upgrades enable
sudo echo "start on runlevel [2345]" | sudo tee /etc/init/unattended-upgrades.override
sudo echo "respawn" | sudo tee /etc/init/unattended-upgrades.override
sudo systemctl enable unattended-upgrades.service
sudo systemctl start unattended-upgrades.service
clear

#Configure apt-get updates
#Configure unattended-updates file
sudo echo "Configuring Unattended Upgrades..."
#sudo cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.old
sudo echo "Unattended-Upgrade::Origins-Pattern {" | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo  echo "  \"$release_id:$release_codename-security;\";" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo echo "  \"$release_id:$release_codename-updates;\";" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo echo "  };" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo echo "Unattended-Upgrade::Package-Blacklist {" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo echo "  };" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo echo "Unattended-Upgrade::AutoFixInterruptedDpkg \"true\";" | sudo tee -a /etc/apt/apt.conf.d/50unattended-upgrades.tmp
sudo mv -f /etc/apt/apt.conf.d/50unattended-upgrades.tmp /etc/apt/apt.conf.d/50unattended-upgrades
#Configure aptitude file
sudo echo "Aptitude::Get-Root-Command \"sudo:/usr/bin/sudo\";" | sudo tee /etc/apt/apt.conf.d/00aptitude.tmp
sudo echo "APT::Authentication::TrustCDROM \"false\";" | sudo tee -a /etc/apt/apt.conf.d/00aptitude.tmp
sudo echo "DPkg::Post-Invoke {\"if [ -d /var/lib/update-notifier ]; then touch /var/lib/update-notifier/dpkg-run-stamp; fi; if [ -e /var/lib/update-notifier/updates-available ]; then echo > /var/lib/update-notifier/updates-available; fi \"};" | sudo tee -a /etc/apt/apt.conf.d/00aptitude.tmp
sudo mv -f /etc/apt/apt.conf.d/00aptitude.tmp /etc/apt/apt.conf.d/00aptitude


#Update apt-key
echo "Updating apt-key..."
sudo apt-key update

#Perform Updates
echo "Updating System, will take some time..."
echo "" > sudo apt-add-repository ppa:nilarimogard/webupd8
if [ "$release_id" == "debian" ]; then
  echo "" > sudo sudo add-apt-repository ppa:n-muench/programs-ppa
fi
echo "Updating System, will take some time..."
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get check -y

#Verify sudo is installed (This should be required for system to boot... but who knows? Might as well check!)
echo "Verifying sudo is installed and updated..."
sudo apt-get install -y sudo

#Install Cracklib
echo "Installing Cracklib..."
sudo apt-get install -y libpam-cracklib

#Install iptables (Should be installed by default, but may have been uninstalled.)
echo "Installing iptables..."
sudo apt-get install -y iptables

#Install sudo dconf-editor gui
echo "Installing dconf-editor..."
sudo apt-get install -y dconf-editor

#Install APG Secure Password Generator
echo "Installing APG secure password generator..."
sudo apt-get install apg -y

#Verify passwd is installed
sudo apt-get install -y passwd

#Install bum (Boot-up manager)
sudo apt-get install -y bum

#Install sysv-rc-conf (for managing services)
echo "Installing sysv-rc-conf..."
sudo apt-get install -y sysv-rc-conf

# Download PGP key from http://kernelsec.cr0.org/kernel-security.asc if "sudo launchpad-getkeys" fails.
echo "Installing launchpad-getkeys..."
sudo apt-get install -y launchpad-getkeys
sudo launchpad-getkeys
sudo apt-key add kernel-security.asc
#sudo apt-get install -y linux-image-2.6.32.15-1-grsec linux-headers-2.6.32.15-1-grsec linux-source-2.6.32.15-1-grsec
#TODO: Not sure what this ^ line does, but need to check into it

#Install security tools
echo "Installing Uncomplicated Firewall..."
sudo apt-get install -y ufw
sudo apt-get install -y gufw
echo "Installing OpenSSL..."
sudo apt-get install -y openssl
echo "Installing Audits"
sudo apt-get install -y auditd
sudo auditctl –e 1
echo "Installing AppArmor..."
sudo apt-get install -y apparmor apparmor-profiles
echo "Installing ClamAV..."
sudo apt-get install -y clamav
sudo apt-get install -y clamtk
echo "Updating ClamAV..."
sudo freshclam
echo "Installing chkrootkit..."
sudo apt-get install -y chkrootkit
echo "Installing tripwire..."
sudo apt-get install -y tripwire
echo "Installing lsmod..."
sudo apt-get install -y lsmod

#Install Lynis, an auditing system which is extremely useful
sudo apt-get install -y lynis

echo "All installations and updates complete."


#Check for and remove common hacking tools
echo "Removing common hacking tools..."
sudo apt-get purge -y john
sudo apt-get purge -y medusa
sudo apt-get purge -y wfuzz
sudo apt-get purge -y ophcrack
sudo apt-get purge -y aircrack
sudo apt-get purge -y aircrack-ng
sudo apt-get purge -y airodump-ng
sudo apt-get purge -y metasploit
sudo apt-get purge -y tshark
sudo apt-get purge -y wireshark
sudo apt-get purge -y hashcat
sudo apt-get purge -y nessus
sudo apt-get purge -y maltego
sudo apt-get purge -y w3af
sudo apt-get purge -y netsparker
sudo apt-get purge -y sqlmap
sudo apt-get purge -y unicornscan
sudo apt-get purge -y hydra

#Although nmap can be used to secure the image, we will reset the firewall, so it won't be needed and could be used as a hacking tool
sudo apt-get purge -y nmap

#Remove Transmission BitTorrent Client
sudo apt-get purge -y transmission-gtk transmission-cli transmission-daemon transmission-common
#Remove other torrent programs
sudo apt-get purge -y deluge
sudo apt-get purge -y qbittorrent
sudo apt-get purge -y vuze
sudo apt-get purge -y tixati
sudo apt-get purge -y frostwire

#Uninstal Samba if not required
if [ "$shared_allowed" == "y" ]; then
  sudo apt-get install -y samba
else
  sudo apt-get purge -y samba
fi

echo "All common hacking tools removed."


#Auto-Install Ubuntu Security Updates
sudo echo "sudo echo \"**************\" >> /var/log/apt-security-updates" | sudo tee /etc/cron.daily/apt-security-updates
sudo echo "date >> /var/log/apt-security-updates" | sudo tee -a /etc/cron.daily/apt-security-updates
sudo echo "aptitude update >> /var/log/apt-security-updates" | sudo tee -a /etc/cron.daily/apt-security-updates
sudo echo "aptitude safe-upgrade -o Aptitude::Delete-Unused=false --assume-yes --target-release `lsb_release -cs`-" | sudo tee -a /etc/cron.daily/apt-security-updates
sudo echo "security >> /var/log/apt-security-updates" | sudo tee -a /etc/cron.daily/apt-security-updates
sudo echo "sudo echo \"Security updates (if any) installed\"" | sudo tee -a /etc/cron.daily/apt-security-updates
sudo chmod +x /etc/cron.daily/apt-security-updates

sudo echo "/var/log/apt-security-updates {" | sudo tee /etc/logrotate.d/apt-security-updates
sudo echo "        rotate 2" | sudo tee -a /etc/logrotate.d/apt-security-updates
sudo echo "        weekly" | sudo tee -a /etc/logrotate.d/apt-security-updates
sudo echo "        size 250k" | sudo tee -a /etc/logrotate.d/apt-security-updates
sudo echo "        compress" | sudo tee -a /etc/logrotate.d/apt-security-updates
sudo echo "        notifempty" | sudo tee -a /etc/logrotate.d/apt-security-updates
sudo echo "}" | sudo tee -a /etc/logrotate.d/apt-security-updates


#Package Loop
echo "Listing..." > safe-packages.tmp
echo "a11y-profile-manager-indicator" >> safe-packages.tmp
echo "account-plugin-facebook" >> safe-packages.tmp
echo "account-plugin-flickr" >> safe-packages.tmp
echo "account-plugin-google" >> safe-packages.tmp
echo "accountsservice" >> safe-packages.tmp
echo "acl" >> safe-packages.tmp
echo "acpi-support" >> safe-packages.tmp
echo "acpid" >> safe-packages.tmp
echo "activity-log-manager" >> safe-packages.tmp
echo "adduser" >> safe-packages.tmp
echo "adium-theme-ubuntu" >> safe-packages.tmp
echo "adwaita-icon-theme" >> safe-packages.tmp
echo "aisleriot" >> safe-packages.tmp
echo "alsa-base" >> safe-packages.tmp
echo "alsa-utils" >> safe-packages.tmp
echo "anacron" >> safe-packages.tmp
echo "apg" >> safe-packages.tmp
echo "app-install-data" >> safe-packages.tmp
echo "app-install-data-partner" >> safe-packages.tmp
echo "apparmor" >> safe-packages.tmp
echo "apparmor-profiles" >> safe-packages.tmp
echo "appmenu-qt" >> safe-packages.tmp
echo "appmenu-qt5" >> safe-packages.tmp
echo "apport" >> safe-packages.tmp
echo "apport-gtk" >> safe-packages.tmp
echo "apport-symptoms" >> safe-packages.tmp
echo "appstream" >> safe-packages.tmp
echo "apt" >> safe-packages.tmp
echo "apt-transport-https" >> safe-packages.tmp
echo "apt-utils" >> safe-packages.tmp
echo "aptdaemon" >> safe-packages.tmp
echo "aptdaemon-data" >> safe-packages.tmp
echo "apturl" >> safe-packages.tmp
echo "apturl-common" >> safe-packages.tmp
echo "aspell" >> safe-packages.tmp
echo "aspell-en" >> safe-packages.tmp
echo "at-spi2-core" >> safe-packages.tmp
echo "auditd" >> safe-packages.tmp
echo "avahi-autoipd" >> safe-packages.tmp
echo "avahi-daemon" >> safe-packages.tmp
echo "avahi-utils" >> safe-packages.tmp
echo "bamfdaemon" >> safe-packages.tmp
echo "baobab" >> safe-packages.tmp
echo "base-files" >> safe-packages.tmp
echo "base-passwd" >> safe-packages.tmp
echo "bash" >> safe-packages.tmp
echo "bash-completion" >> safe-packages.tmp
echo "bc" >> safe-packages.tmp
echo "bind9-host" >> safe-packages.tmp
echo "binutils" >> safe-packages.tmp
echo "bluez" >> safe-packages.tmp
echo "bluez-cups" >> safe-packages.tmp
echo "bluez-obexd" >> safe-packages.tmp
echo "branding-ubuntu" >> safe-packages.tmp
echo "brltty" >> safe-packages.tmp
echo "bsdmainutils" >> safe-packages.tmp
echo "bsdutils" >> safe-packages.tmp
echo "build-essential" >> safe-packages.tmp
echo "bum" >> safe-packages.tmp
echo "busybox-initramfs" >> safe-packages.tmp
echo "busybox-static" >> safe-packages.tmp
echo "bzip2" >> safe-packages.tmp
echo "ca-certificates" >> safe-packages.tmp
echo "checkbox-converged" >> safe-packages.tmp
echo "checkbox-gui" >> safe-packages.tmp
echo "cheese" >> safe-packages.tmp
echo "cheese-common" >> safe-packages.tmp
echo "chkrootkit" >> safe-packages.tmp
echo "clamav" >> safe-packages.tmp
echo "clamav-base" >> safe-packages.tmp
echo "clamav-freshclam" >> safe-packages.tmp
echo "clamtk" >> safe-packages.tmp
echo "colord" >> safe-packages.tmp
echo "colord-data" >> safe-packages.tmp
echo "command-not-found" >> safe-packages.tmp
echo "command-not-found-data" >> safe-packages.tmp
echo "compiz" >> safe-packages.tmp
echo "compiz-core" >> safe-packages.tmp
echo "compiz-gnome" >> safe-packages.tmp
echo "compiz-plugins-default" >> safe-packages.tmp
echo "console-setup" >> safe-packages.tmp
echo "console-setup-linux" >> safe-packages.tmp
echo "coreutils" >> safe-packages.tmp
echo "cpio" >> safe-packages.tmp
echo "cpp" >> safe-packages.tmp
echo "cpp-5" >> safe-packages.tmp
echo "cracklib-runtime" >> safe-packages.tmp
echo "crda" >> safe-packages.tmp
echo "cron" >> safe-packages.tmp
echo "cups" >> safe-packages.tmp
echo "cups-browsed" >> safe-packages.tmp
echo "cups-bsd" >> safe-packages.tmp
echo "cups-client" >> safe-packages.tmp
echo "cups-common" >> safe-packages.tmp
echo "cups-core-drivers" >> safe-packages.tmp
echo "cups-daemon" >> safe-packages.tmp
echo "cups-filters" >> safe-packages.tmp
echo "cups-filters-core-drivers" >> safe-packages.tmp
echo "cups-pk-helper" >> safe-packages.tmp
echo "cups-ppdc" >> safe-packages.tmp
echo "cups-server-common" >> safe-packages.tmp
echo "curl" >> safe-packages.tmp
echo "dash" >> safe-packages.tmp
echo "dbus" >> safe-packages.tmp
echo "dbus-x11" >> safe-packages.tmp
echo "dc" >> safe-packages.tmp
echo "dconf-cli" >> safe-packages.tmp
echo "dconf-editor" >> safe-packages.tmp
echo "dconf-gsettings-backend" >> safe-packages.tmp
echo "dconf-service" >> safe-packages.tmp
echo "debconf" >> safe-packages.tmp
echo "debconf-i18n" >> safe-packages.tmp
echo "debianutils" >> safe-packages.tmp
echo "deja-dup" >> safe-packages.tmp
echo "desktop-file-utils" >> safe-packages.tmp
echo "dh-python" >> safe-packages.tmp
echo "dictionaries-common" >> safe-packages.tmp
echo "diffstat" >> safe-packages.tmp
echo "diffutils" >> safe-packages.tmp
echo "dirmngr" >> safe-packages.tmp
echo "distro-info-data" >> safe-packages.tmp
echo "dkms" >> safe-packages.tmp
echo "dmidecode" >> safe-packages.tmp
echo "dmz-cursor-theme" >> safe-packages.tmp
echo "dns-root-data" >> safe-packages.tmp
echo "dnsmasq-base" >> safe-packages.tmp
echo "dnsutils" >> safe-packages.tmp
echo "doc-base" >> safe-packages.tmp
echo "dosfstools" >> safe-packages.tmp
echo "dpkg" >> safe-packages.tmp
echo "dpkg-dev" >> safe-packages.tmp
echo "e2fslibs" >> safe-packages.tmp
echo "e2fsprogs" >> safe-packages.tmp
echo "ed" >> safe-packages.tmp
echo "efibootmgr" >> safe-packages.tmp
echo "eject" >> safe-packages.tmp
echo "emacsen-common" >> safe-packages.tmp
echo "enchant" >> safe-packages.tmp
echo "eog" >> safe-packages.tmp
echo "espeak-data" >> safe-packages.tmp
echo "ethtool" >> safe-packages.tmp
echo "evince" >> safe-packages.tmp
echo "evince-common" >> safe-packages.tmp
echo "evolution-data-server" >> safe-packages.tmp
echo "evolution-data-server-common" >> safe-packages.tmp
echo "evolution-data-server-online-accounts" >> safe-packages.tmp
echo "example-content" >> safe-packages.tmp
echo "fakeroot" >> safe-packages.tmp
echo "file" >> safe-packages.tmp
echo "file-roller" >> safe-packages.tmp
echo "findutils" >> safe-packages.tmp
echo "firefox" >> safe-packages.tmp
echo "firefox-locale-en" >> safe-packages.tmp
echo "fontconfig" >> safe-packages.tmp
echo "fontconfig-config" >> safe-packages.tmp
echo "fonts-dejavu-core" >> safe-packages.tmp
echo "fonts-freefont-ttf" >> safe-packages.tmp
echo "fonts-guru" >> safe-packages.tmp
echo "fonts-guru-extra" >> safe-packages.tmp
echo "fonts-kacst" >> safe-packages.tmp
echo "fonts-kacst-one" >> safe-packages.tmp
echo "fonts-khmeros-core" >> safe-packages.tmp
echo "fonts-lao" >> safe-packages.tmp
echo "fonts-liberation" >> safe-packages.tmp
echo "fonts-lklug-sinhala" >> safe-packages.tmp
echo "fonts-lohit-guru" >> safe-packages.tmp
echo "fonts-nanum" >> safe-packages.tmp
echo "fonts-noto-cjk" >> safe-packages.tmp
echo "fonts-opensymbol" >> safe-packages.tmp
echo "fonts-sil-abyssinica" >> safe-packages.tmp
echo "fonts-sil-padauk" >> safe-packages.tmp
echo "fonts-stix" >> safe-packages.tmp
echo "fonts-symbola" >> safe-packages.tmp
echo "fonts-takao-pgothic" >> safe-packages.tmp
echo "fonts-thai-tlwg" >> safe-packages.tmp
echo "fonts-tibetan-machine" >> safe-packages.tmp
echo "fonts-tlwg-garuda" >> safe-packages.tmp
echo "fonts-tlwg-garuda-ttf" >> safe-packages.tmp
echo "fonts-tlwg-kinnari" >> safe-packages.tmp
echo "fonts-tlwg-kinnari-ttf" >> safe-packages.tmp
echo "fonts-tlwg-laksaman" >> safe-packages.tmp
echo "fonts-tlwg-laksaman-ttf" >> safe-packages.tmp
echo "fonts-tlwg-loma" >> safe-packages.tmp
echo "fonts-tlwg-loma-ttf" >> safe-packages.tmp
echo "fonts-tlwg-mono" >> safe-packages.tmp
echo "fonts-tlwg-mono-ttf" >> safe-packages.tmp
echo "fonts-tlwg-norasi" >> safe-packages.tmp
echo "fonts-tlwg-norasi-ttf" >> safe-packages.tmp
echo "fonts-tlwg-purisa" >> safe-packages.tmp
echo "fonts-tlwg-purisa-ttf" >> safe-packages.tmp
echo "fonts-tlwg-sawasdee" >> safe-packages.tmp
echo "fonts-tlwg-sawasdee-ttf" >> safe-packages.tmp
echo "fonts-tlwg-typewriter" >> safe-packages.tmp
echo "fonts-tlwg-typewriter-ttf" >> safe-packages.tmp
echo "fonts-tlwg-typist" >> safe-packages.tmp
echo "fonts-tlwg-typist-ttf" >> safe-packages.tmp
echo "fonts-tlwg-typo" >> safe-packages.tmp
echo "fonts-tlwg-typo-ttf" >> safe-packages.tmp
echo "fonts-tlwg-umpush" >> safe-packages.tmp
echo "fonts-tlwg-umpush-ttf" >> safe-packages.tmp
echo "fonts-tlwg-waree" >> safe-packages.tmp
echo "fonts-tlwg-waree-ttf" >> safe-packages.tmp
echo "foomatic-db-compressed-ppds" >> safe-packages.tmp
echo "friendly-recovery" >> safe-packages.tmp
echo "fuse" >> safe-packages.tmp
echo "fwupd" >> safe-packages.tmp
echo "fwupdate" >> safe-packages.tmp
echo "fwupdate-signed" >> safe-packages.tmp
echo "g++" >> safe-packages.tmp
echo "g++-5" >> safe-packages.tmp
echo "gcc" >> safe-packages.tmp
echo "gcc-5" >> safe-packages.tmp
echo "gcc-5-base" >> safe-packages.tmp
echo "gcc-6-base" >> safe-packages.tmp
echo "gconf-service" >> safe-packages.tmp
echo "gconf-service-backend" >> safe-packages.tmp
echo "gconf2" >> safe-packages.tmp
echo "gconf2-common" >> safe-packages.tmp
echo "gcr" >> safe-packages.tmp
echo "gdb" >> safe-packages.tmp
echo "gdbserver" >> safe-packages.tmp
echo "gdisk" >> safe-packages.tmp
echo "gedit" >> safe-packages.tmp
echo "gedit-common" >> safe-packages.tmp
echo "genisoimage" >> safe-packages.tmp
echo "geoclue" >> safe-packages.tmp
echo "geoclue-ubuntu-geoip" >> safe-packages.tmp
echo "geoip-database" >> safe-packages.tmp
echo "gettext" >> safe-packages.tmp
echo "gettext-base" >> safe-packages.tmp
echo "ghostscript" >> safe-packages.tmp
echo "ghostscript-x" >> safe-packages.tmp
echo "gir1.2-accounts-1.0" >> safe-packages.tmp
echo "gir1.2-appindicator3-0.1" >> safe-packages.tmp
echo "gir1.2-atk-1.0" >> safe-packages.tmp
echo "gir1.2-atspi-2.0" >> safe-packages.tmp
echo "gir1.2-dbusmenu-glib-0.4" >> safe-packages.tmp
echo "gir1.2-dee-1.0" >> safe-packages.tmp
echo "gir1.2-freedesktop" >> safe-packages.tmp
echo "gir1.2-gdata-0.0" >> safe-packages.tmp
echo "gir1.2-gdkpixbuf-2.0" >> safe-packages.tmp
echo "gir1.2-glib-2.0" >> safe-packages.tmp
echo "gir1.2-gnomekeyring-1.0" >> safe-packages.tmp
echo "gir1.2-goa-1.0" >> safe-packages.tmp
echo "gir1.2-gst-plugins-base-1.0" >> safe-packages.tmp
echo "gir1.2-gstreamer-1.0" >> safe-packages.tmp
echo "gir1.2-gtk-3.0" >> safe-packages.tmp
echo "gir1.2-gtksource-3.0" >> safe-packages.tmp
echo "gir1.2-gudev-1.0" >> safe-packages.tmp
echo "gir1.2-ibus-1.0" >> safe-packages.tmp
echo "gir1.2-javascriptcoregtk-4.0" >> safe-packages.tmp
echo "gir1.2-json-1.0" >> safe-packages.tmp
echo "gir1.2-notify-0.7" >> safe-packages.tmp
echo "gir1.2-packagekitglib-1.0" >> safe-packages.tmp
echo "gir1.2-pango-1.0" >> safe-packages.tmp
echo "gir1.2-peas-1.0" >> safe-packages.tmp
echo "gir1.2-rb-3.0" >> safe-packages.tmp
echo "gir1.2-secret-1" >> safe-packages.tmp
echo "gir1.2-signon-1.0" >> safe-packages.tmp
echo "gir1.2-soup-2.4" >> safe-packages.tmp
echo "gir1.2-totem-1.0" >> safe-packages.tmp
echo "gir1.2-totem-plparser-1.0" >> safe-packages.tmp
echo "gir1.2-udisks-2.0" >> safe-packages.tmp
echo "gir1.2-unity-5.0" >> safe-packages.tmp
echo "gir1.2-vte-2.91" >> safe-packages.tmp
echo "gir1.2-webkit2-4.0" >> safe-packages.tmp
echo "gir1.2-wnck-3.0" >> safe-packages.tmp
echo "gkbd-capplet" >> safe-packages.tmp
echo "glib-networking" >> safe-packages.tmp
echo "glib-networking-common" >> safe-packages.tmp
echo "glib-networking-services" >> safe-packages.tmp
echo "gnome-accessibility-themes" >> safe-packages.tmp
echo "gnome-bluetooth" >> safe-packages.tmp
echo "gnome-calculator" >> safe-packages.tmp
echo "gnome-calendar" >> safe-packages.tmp
echo "gnome-desktop3-data" >> safe-packages.tmp
echo "gnome-disk-utility" >> safe-packages.tmp
echo "gnome-font-viewer" >> safe-packages.tmp
echo "gnome-icon-theme" >> safe-packages.tmp
echo "gnome-keyring" >> safe-packages.tmp
echo "gnome-mahjongg" >> safe-packages.tmp
echo "gnome-menus" >> safe-packages.tmp
echo "gnome-mines" >> safe-packages.tmp
echo "gnome-orca" >> safe-packages.tmp
echo "gnome-power-manager" >> safe-packages.tmp
echo "gnome-screensaver" >> safe-packages.tmp
echo "gnome-screenshot" >> safe-packages.tmp
echo "gnome-session-bin" >> safe-packages.tmp
echo "gnome-session-canberra" >> safe-packages.tmp
echo "gnome-session-common" >> safe-packages.tmp
echo "gnome-settings-daemon-schemas" >> safe-packages.tmp
echo "gnome-software" >> safe-packages.tmp
echo "gnome-software-common" >> safe-packages.tmp
echo "gnome-sudoku" >> safe-packages.tmp
echo "gnome-system-log" >> safe-packages.tmp
echo "gnome-system-monitor" >> safe-packages.tmp
echo "gnome-terminal" >> safe-packages.tmp
echo "gnome-terminal-data" >> safe-packages.tmp
echo "gnome-user-guide" >> safe-packages.tmp
echo "gnome-user-share" >> safe-packages.tmp
echo "gnome-video-effects" >> safe-packages.tmp
echo "gnupg" >> safe-packages.tmp
echo "gnupg-agent" >> safe-packages.tmp
echo "gnupg2" >> safe-packages.tmp
echo "gpgv" >> safe-packages.tmp
echo "grep" >> safe-packages.tmp
echo "grilo-plugins-0.2-base" >> safe-packages.tmp
echo "groff-base" >> safe-packages.tmp
echo "grub-common" >> safe-packages.tmp
echo "grub-gfxpayload-lists" >> safe-packages.tmp
echo "grub-pc" >> safe-packages.tmp
echo "grub-pc-bin" >> safe-packages.tmp
echo "grub2-common" >> safe-packages.tmp
echo "gsettings-desktop-schemas" >> safe-packages.tmp
echo "gsettings-ubuntu-schemas" >> safe-packages.tmp
echo "gsfonts" >> safe-packages.tmp
echo "gstreamer1.0-alsa" >> safe-packages.tmp
echo "gstreamer1.0-clutter-3.0" >> safe-packages.tmp
echo "gstreamer1.0-plugins-base" >> safe-packages.tmp
echo "gstreamer1.0-plugins-base-apps" >> safe-packages.tmp
echo "gstreamer1.0-plugins-good" >> safe-packages.tmp
echo "gstreamer1.0-pulseaudio" >> safe-packages.tmp
echo "gstreamer1.0-tools" >> safe-packages.tmp
echo "gstreamer1.0-x" >> safe-packages.tmp
echo "gtk2-engines-murrine" >> safe-packages.tmp
echo "gucharmap" >> safe-packages.tmp
echo "guile-2.0-libs" >> safe-packages.tmp
echo "gvfs" >> safe-packages.tmp
echo "gvfs-backends" >> safe-packages.tmp
echo "gvfs-bin" >> safe-packages.tmp
echo "gvfs-common" >> safe-packages.tmp
echo "gvfs-daemons" >> safe-packages.tmp
echo "gvfs-fuse" >> safe-packages.tmp
echo "gvfs-libs" >> safe-packages.tmp
echo "gzip" >> safe-packages.tmp
echo "hardening-includes" >> safe-packages.tmp
echo "hdparm" >> safe-packages.tmp
echo "hicolor-icon-theme" >> safe-packages.tmp
echo "hostname" >> safe-packages.tmp
echo "hplip" >> safe-packages.tmp
echo "hplip-data" >> safe-packages.tmp
echo "hud" >> safe-packages.tmp
echo "humanity-icon-theme" >> safe-packages.tmp
echo "hunspell-en-us" >> safe-packages.tmp
echo "hwdata" >> safe-packages.tmp
echo "hyphen-en-us" >> safe-packages.tmp
echo "ibus" >> safe-packages.tmp
echo "ibus-gtk" >> safe-packages.tmp
echo "ibus-gtk3" >> safe-packages.tmp
echo "ibus-table" >> safe-packages.tmp
echo "ifupdown" >> safe-packages.tmp
echo "im-config" >> safe-packages.tmp
echo "imagemagick" >> safe-packages.tmp
echo "imagemagick-6.q16" >> safe-packages.tmp
echo "imagemagick-common" >> safe-packages.tmp
echo "indicator-application" >> safe-packages.tmp
echo "indicator-appmenu" >> safe-packages.tmp
echo "indicator-bluetooth" >> safe-packages.tmp
echo "indicator-datetime" >> safe-packages.tmp
echo "indicator-keyboard" >> safe-packages.tmp
echo "indicator-messages" >> safe-packages.tmp
echo "indicator-power" >> safe-packages.tmp
echo "indicator-printers" >> safe-packages.tmp
echo "indicator-session" >> safe-packages.tmp
echo "indicator-sound" >> safe-packages.tmp
echo "info" >> safe-packages.tmp
echo "init" >> safe-packages.tmp
echo "init-system-helpers" >> safe-packages.tmp
echo "initramfs-tools" >> safe-packages.tmp
echo "initramfs-tools-bin" >> safe-packages.tmp
echo "initramfs-tools-core" >> safe-packages.tmp
echo "initscripts" >> safe-packages.tmp
echo "inputattach" >> safe-packages.tmp
echo "insserv" >> safe-packages.tmp
echo "install-info" >> safe-packages.tmp
echo "intel-gpu-tools" >> safe-packages.tmp
echo "intltool-debian" >> safe-packages.tmp
echo "ippusbxd" >> safe-packages.tmp
echo "iproute2" >> safe-packages.tmp
echo "iptables" >> safe-packages.tmp
echo "iputils-arping" >> safe-packages.tmp
echo "iputils-ping" >> safe-packages.tmp
echo "iputils-tracepath" >> safe-packages.tmp
echo "irqbalance" >> safe-packages.tmp
echo "isc-dhcp-client" >> safe-packages.tmp
echo "isc-dhcp-common" >> safe-packages.tmp
echo "iso-codes" >> safe-packages.tmp
echo "iw" >> safe-packages.tmp
echo "jayatana" >> safe-packages.tmp
echo "kbd" >> safe-packages.tmp
echo "kerneloops-daemon" >> safe-packages.tmp
echo "keyboard-configuration" >> safe-packages.tmp
echo "klibc-utils" >> safe-packages.tmp
echo "kmod" >> safe-packages.tmp
echo "krb5-locales" >> safe-packages.tmp
echo "language-pack-en" >> safe-packages.tmp
echo "language-pack-en-base" >> safe-packages.tmp
echo "language-pack-gnome-en" >> safe-packages.tmp
echo "language-pack-gnome-en-base" >> safe-packages.tmp
echo "language-selector-common" >> safe-packages.tmp
echo "language-selector-gnome" >> safe-packages.tmp
echo "laptop-detect" >> safe-packages.tmp
echo "less" >> safe-packages.tmp
echo "liba11y-profile-manager-0.1-0" >> safe-packages.tmp
echo "liba11y-profile-manager-data" >> safe-packages.tmp
echo "libaa1" >> safe-packages.tmp
echo "libabw-0.1-1v5" >> safe-packages.tmp
echo "libaccount-plugin-1.0-0" >> safe-packages.tmp
echo "libaccount-plugin-generic-oauth" >> safe-packages.tmp
echo "libaccount-plugin-google" >> safe-packages.tmp
echo "libaccounts-glib0" >> safe-packages.tmp
echo "libaccounts-qt5-1" >> safe-packages.tmp
echo "libaccountsservice0" >> safe-packages.tmp
echo "libacl1" >> safe-packages.tmp
echo "libalgorithm-diff-perl" >> safe-packages.tmp
echo "libalgorithm-diff-xs-perl" >> safe-packages.tmp
echo "libalgorithm-merge-perl" >> safe-packages.tmp
echo "libandroid-properties1" >> safe-packages.tmp
echo "libao-common" >> safe-packages.tmp
echo "libao4" >> safe-packages.tmp
echo "libapparmor-perl" >> safe-packages.tmp
echo "libapparmor1" >> safe-packages.tmp
echo "libappindicator3-1" >> safe-packages.tmp
echo "libappstream-glib8" >> safe-packages.tmp
echo "libappstream3" >> safe-packages.tmp
echo "libapt-inst2.0" >> safe-packages.tmp
echo "libapt-pkg-perl" >> safe-packages.tmp
echo "libapt-pkg5.0" >> safe-packages.tmp
echo "libarchive-zip-perl" >> safe-packages.tmp
echo "libarchive13" >> safe-packages.tmp
echo "libart-2.0-2" >> safe-packages.tmp
echo "libasan2" >> safe-packages.tmp
echo "libasn1-8-heimdal" >> safe-packages.tmp
echo "libasound2" >> safe-packages.tmp
echo "libasound2-data" >> safe-packages.tmp
echo "libasound2-plugins" >> safe-packages.tmp
echo "libaspell15" >> safe-packages.tmp
echo "libasprintf-dev" >> safe-packages.tmp
echo "libasprintf0v5" >> safe-packages.tmp
echo "libassuan0" >> safe-packages.tmp
echo "libasyncns0" >> safe-packages.tmp
echo "libatasmart4" >> safe-packages.tmp
echo "libatk-adaptor" >> safe-packages.tmp
echo "libatk-bridge2.0-0" >> safe-packages.tmp
echo "libatk1.0-0" >> safe-packages.tmp
echo "libatk1.0-data" >> safe-packages.tmp
echo "libatkmm-1.6-1v5" >> safe-packages.tmp
echo "libatm1" >> safe-packages.tmp
echo "libatomic1" >> safe-packages.tmp
echo "libatspi2.0-0" >> safe-packages.tmp
echo "libattr1" >> safe-packages.tmp
echo "libaudio2" >> safe-packages.tmp
echo "libaudit-common" >> safe-packages.tmp
echo "libaudit1" >> safe-packages.tmp
echo "libauparse0" >> safe-packages.tmp
echo "libauthen-sasl-perl" >> safe-packages.tmp
echo "libavahi-client3" >> safe-packages.tmp
echo "libavahi-common-data" >> safe-packages.tmp
echo "libavahi-common3" >> safe-packages.tmp
echo "libavahi-core7" >> safe-packages.tmp
echo "libavahi-glib1" >> safe-packages.tmp
echo "libavahi-ui-gtk3-0" >> safe-packages.tmp
echo "libavc1394-0" >> safe-packages.tmp
echo "libbabeltrace-ctf1" >> safe-packages.tmp
echo "libbabeltrace1" >> safe-packages.tmp
echo "libbamf3-2" >> safe-packages.tmp
echo "libbind9-140" >> safe-packages.tmp
echo "libblkid1" >> safe-packages.tmp
echo "libbluetooth3" >> safe-packages.tmp
echo "libboost-date-time1.58.0" >> safe-packages.tmp
echo "libboost-filesystem1.58.0" >> safe-packages.tmp
echo "libboost-iostreams1.58.0" >> safe-packages.tmp
echo "libboost-system1.58.0" >> safe-packages.tmp
echo "libbrlapi0.6" >> safe-packages.tmp
echo "libbsd0" >> safe-packages.tmp
echo "libbz2-1.0" >> safe-packages.tmp
echo "libc-bin" >> safe-packages.tmp
echo "libc-dev-bin" >> safe-packages.tmp
echo "libc6" >> safe-packages.tmp
echo "libc6-dbg" >> safe-packages.tmp
echo "libc6-dev" >> safe-packages.tmp
echo "libcaca0" >> safe-packages.tmp
echo "libcairo-gobject2" >> safe-packages.tmp
echo "libcairo-perl" >> safe-packages.tmp
echo "libcairo2" >> safe-packages.tmp
echo "libcairomm-1.0-1v5" >> safe-packages.tmp
echo "libcamel-1.2-54" >> safe-packages.tmp
echo "libcanberra-gtk-module" >> safe-packages.tmp
echo "libcanberra-gtk0" >> safe-packages.tmp
echo "libcanberra-gtk3-0" >> safe-packages.tmp
echo "libcanberra-gtk3-module" >> safe-packages.tmp
echo "libcanberra-pulse" >> safe-packages.tmp
echo "libcanberra0" >> safe-packages.tmp
echo "libcap-ng0" >> safe-packages.tmp
echo "libcap2" >> safe-packages.tmp
echo "libcap2-bin" >> safe-packages.tmp
echo "libcapnp-0.5.3" >> safe-packages.tmp
echo "libcc1-0" >> safe-packages.tmp
echo "libcdio-cdda1" >> safe-packages.tmp
echo "libcdio-paranoia1" >> safe-packages.tmp
echo "libcdio13" >> safe-packages.tmp
echo "libcdparanoia0" >> safe-packages.tmp
echo "libcdr-0.1-1" >> safe-packages.tmp
echo "libcgi-fast-perl" >> safe-packages.tmp
echo "libcgi-pm-perl" >> safe-packages.tmp
echo "libcgmanager0" >> safe-packages.tmp
echo "libcheese-gtk25" >> safe-packages.tmp
echo "libcheese8" >> safe-packages.tmp
echo "libcilkrts5" >> safe-packages.tmp
echo "libclamav7" >> safe-packages.tmp
echo "libclass-accessor-perl" >> safe-packages.tmp
echo "libclone-perl" >> safe-packages.tmp
echo "libclucene-contribs1v5" >> safe-packages.tmp
echo "libclucene-core1v5" >> safe-packages.tmp
echo "libclutter-1.0-0" >> safe-packages.tmp
echo "libclutter-1.0-common" >> safe-packages.tmp
echo "libclutter-gst-3.0-0" >> safe-packages.tmp
echo "libclutter-gtk-1.0-0" >> safe-packages.tmp
echo "libcmis-0.5-5v5" >> safe-packages.tmp
echo "libcogl-common" >> safe-packages.tmp
echo "libcogl-pango20" >> safe-packages.tmp
echo "libcogl-path20" >> safe-packages.tmp
echo "libcogl20" >> safe-packages.tmp
echo "libcolamd2.9.1" >> safe-packages.tmp
echo "libcolord2" >> safe-packages.tmp
echo "libcolorhug2" >> safe-packages.tmp
echo "libcolumbus1-common" >> safe-packages.tmp
echo "libcolumbus1v5" >> safe-packages.tmp
echo "libcomerr2" >> safe-packages.tmp
echo "libcommon-sense-perl" >> safe-packages.tmp
echo "libcompizconfig0" >> safe-packages.tmp
echo "libcrack2" >> safe-packages.tmp
echo "libcroco3" >> safe-packages.tmp
echo "libcryptsetup4" >> safe-packages.tmp
echo "libcups2" >> safe-packages.tmp
echo "libcupscgi1" >> safe-packages.tmp
echo "libcupsfilters1" >> safe-packages.tmp
echo "libcupsimage2" >> safe-packages.tmp
echo "libcupsmime1" >> safe-packages.tmp
echo "libcupsppdc1" >> safe-packages.tmp
echo "libcurl3" >> safe-packages.tmp
echo "libcurl3-gnutls" >> safe-packages.tmp
echo "libcurses-perl" >> safe-packages.tmp
echo "libcurses-ui-perl" >> safe-packages.tmp
echo "libdaemon0" >> safe-packages.tmp
echo "libdata-alias-perl" >> safe-packages.tmp
echo "libdatrie1" >> safe-packages.tmp
echo "libdb5.3" >> safe-packages.tmp
echo "libdbus-1-3" >> safe-packages.tmp
echo "libdbus-glib-1-2" >> safe-packages.tmp
echo "libdbusmenu-glib4" >> safe-packages.tmp
echo "libdbusmenu-gtk3-4" >> safe-packages.tmp
echo "libdbusmenu-gtk4" >> safe-packages.tmp
echo "libdbusmenu-qt2" >> safe-packages.tmp
echo "libdbusmenu-qt5" >> safe-packages.tmp
echo "libdconf1" >> safe-packages.tmp
echo "libdebconfclient0" >> safe-packages.tmp
echo "libdecoration0" >> safe-packages.tmp
echo "libdee-1.0-4" >> safe-packages.tmp
echo "libdevmapper1.02.1" >> safe-packages.tmp
echo "libdfu1" >> safe-packages.tmp
echo "libdigest-hmac-perl" >> safe-packages.tmp
echo "libdjvulibre-text" >> safe-packages.tmp
echo "libdjvulibre21" >> safe-packages.tmp
echo "libdmapsharing-3.0-2" >> safe-packages.tmp
echo "libdns-export162" >> safe-packages.tmp
echo "libdns162" >> safe-packages.tmp
echo "libdotconf0" >> safe-packages.tmp
echo "libdouble-conversion1v5" >> safe-packages.tmp
echo "libdpkg-perl" >> safe-packages.tmp
echo "libdrm-amdgpu1" >> safe-packages.tmp
echo "libdrm-common" >> safe-packages.tmp
echo "libdrm-intel1" >> safe-packages.tmp
echo "libdrm-nouveau2" >> safe-packages.tmp
echo "libdrm-radeon1" >> safe-packages.tmp
echo "libdrm2" >> safe-packages.tmp
echo "libdumbnet1" >> safe-packages.tmp
echo "libdv4" >> safe-packages.tmp
echo "libe-book-0.1-1" >> safe-packages.tmp
echo "libebackend-1.2-10" >> safe-packages.tmp
echo "libebook-1.2-16" >> safe-packages.tmp
echo "libebook-contacts-1.2-2" >> safe-packages.tmp
echo "libecal-1.2-19" >> safe-packages.tmp
echo "libedata-book-1.2-25" >> safe-packages.tmp
echo "libedata-cal-1.2-28" >> safe-packages.tmp
echo "libedataserver-1.2-21" >> safe-packages.tmp
echo "libedataserverui-1.2-1" >> safe-packages.tmp
echo "libedit2" >> safe-packages.tmp
echo "libefivar0" >> safe-packages.tmp
echo "libegl1-mesa" >> safe-packages.tmp
echo "libelf1" >> safe-packages.tmp
echo "libemail-valid-perl" >> safe-packages.tmp
echo "libenchant1c2a" >> safe-packages.tmp
echo "libencode-locale-perl" >> safe-packages.tmp
echo "libeot0" >> safe-packages.tmp
echo "libepoxy0" >> safe-packages.tmp
echo "libespeak1" >> safe-packages.tmp
echo "libestr0" >> safe-packages.tmp
echo "libetonyek-0.1-1" >> safe-packages.tmp
echo "libevdev2" >> safe-packages.tmp
echo "libevdocument3-4" >> safe-packages.tmp
echo "libevent-2.0-5" >> safe-packages.tmp
echo "libevview3-3" >> safe-packages.tmp
echo "libexempi3" >> safe-packages.tmp
echo "libexif12" >> safe-packages.tmp
echo "libexiv2-14" >> safe-packages.tmp
echo "libexpat1" >> safe-packages.tmp
echo "libexporter-tiny-perl" >> safe-packages.tmp
echo "libexttextcat-2.0-0" >> safe-packages.tmp
echo "libexttextcat-data" >> safe-packages.tmp
echo "libfakeroot" >> safe-packages.tmp
echo "libfcgi-perl" >> safe-packages.tmp
echo "libfcitx-config4" >> safe-packages.tmp
echo "libfcitx-gclient0" >> safe-packages.tmp
echo "libfcitx-utils0" >> safe-packages.tmp
echo "libfdisk1" >> safe-packages.tmp
echo "libffi6" >> safe-packages.tmp
echo "libfftw3-double3" >> safe-packages.tmp
echo "libfftw3-single3" >> safe-packages.tmp
echo "libfile-basedir-perl" >> safe-packages.tmp
echo "libfile-copy-recursive-perl" >> safe-packages.tmp
echo "libfile-desktopentry-perl" >> safe-packages.tmp
echo "libfile-fcntllock-perl" >> safe-packages.tmp
echo "libfile-listing-perl" >> safe-packages.tmp
echo "libfile-mimeinfo-perl" >> safe-packages.tmp
echo "libflac8" >> safe-packages.tmp
echo "libfont-afm-perl" >> safe-packages.tmp
echo "libfontconfig1" >> safe-packages.tmp
echo "libfontembed1" >> safe-packages.tmp
echo "libfontenc1" >> safe-packages.tmp
echo "libframe6" >> safe-packages.tmp
echo "libfreehand-0.1-1" >> safe-packages.tmp
echo "libfreerdp-cache1.1" >> safe-packages.tmp
echo "libfreerdp-client1.1" >> safe-packages.tmp
echo "libfreerdp-codec1.1" >> safe-packages.tmp
echo "libfreerdp-common1.1.0" >> safe-packages.tmp
echo "libfreerdp-core1.1" >> safe-packages.tmp
echo "libfreerdp-crypto1.1" >> safe-packages.tmp
echo "libfreerdp-gdi1.1" >> safe-packages.tmp
echo "libfreerdp-locale1.1" >> safe-packages.tmp
echo "libfreerdp-plugins-standard" >> safe-packages.tmp
echo "libfreerdp-primitives1.1" >> safe-packages.tmp
echo "libfreerdp-utils1.1" >> safe-packages.tmp
echo "libfreetype6" >> safe-packages.tmp
echo "libfribidi0" >> safe-packages.tmp
echo "libfuse2" >> safe-packages.tmp
echo "libfwup0" >> safe-packages.tmp
echo "libfwupd1" >> safe-packages.tmp
echo "libgail-3-0" >> safe-packages.tmp
echo "libgail-common" >> safe-packages.tmp
echo "libgail18" >> safe-packages.tmp
echo "libgbm1" >> safe-packages.tmp
echo "libgc1c2" >> safe-packages.tmp
echo "libgcab-1.0-0" >> safe-packages.tmp
echo "libgcc-5-dev" >> safe-packages.tmp
echo "libgcc1" >> safe-packages.tmp
echo "libgck-1-0" >> safe-packages.tmp
echo "libgconf-2-4" >> safe-packages.tmp
echo "libgcr-3-common" >> safe-packages.tmp
echo "libgcr-base-3-1" >> safe-packages.tmp
echo "libgcr-ui-3-1" >> safe-packages.tmp
echo "libgcrypt20" >> safe-packages.tmp
echo "libgd3" >> safe-packages.tmp
echo "libgdata-common" >> safe-packages.tmp
echo "libgdata22" >> safe-packages.tmp
echo "libgdbm3" >> safe-packages.tmp
echo "libgdk-pixbuf2.0-0" >> safe-packages.tmp
echo "libgdk-pixbuf2.0-common" >> safe-packages.tmp
echo "libgee-0.8-2" >> safe-packages.tmp
echo "libgeis1" >> safe-packages.tmp
echo "libgeoclue0" >> safe-packages.tmp
echo "libgeocode-glib0" >> safe-packages.tmp
echo "libgeoip1" >> safe-packages.tmp
echo "libgeonames0" >> safe-packages.tmp
echo "libgettextpo-dev" >> safe-packages.tmp
echo "libgettextpo0" >> safe-packages.tmp
echo "libgexiv2-2" >> safe-packages.tmp
echo "libgirepository-1.0-1" >> safe-packages.tmp
echo "libgl1-mesa-dri" >> safe-packages.tmp
echo "libgl1-mesa-glx" >> safe-packages.tmp
echo "libglapi-mesa" >> safe-packages.tmp
echo "libglew1.13" >> safe-packages.tmp
echo "libglewmx1.13" >> safe-packages.tmp
echo "libglib-perl" >> safe-packages.tmp
echo "libglib2.0-0" >> safe-packages.tmp
echo "libglib2.0-bin" >> safe-packages.tmp
echo "libglib2.0-data" >> safe-packages.tmp
echo "libglibmm-2.4-1v5" >> safe-packages.tmp
echo "libglu1-mesa" >> safe-packages.tmp
echo "libgmime-2.6-0" >> safe-packages.tmp
echo "libgmp10" >> safe-packages.tmp
echo "libgnome-bluetooth13" >> safe-packages.tmp
echo "libgnome-desktop-3-12" >> safe-packages.tmp
echo "libgnome-keyring-common" >> safe-packages.tmp
echo "libgnome-keyring0" >> safe-packages.tmp
echo "libgnome-menu-3-0" >> safe-packages.tmp
echo "libgnomekbd-common" >> safe-packages.tmp
echo "libgnomekbd8" >> safe-packages.tmp
echo "libgnutls-openssl27" >> safe-packages.tmp
echo "libgnutls30" >> safe-packages.tmp
echo "libgoa-1.0-0b" >> safe-packages.tmp
echo "libgoa-1.0-common" >> safe-packages.tmp
echo "libgom-1.0-0" >> safe-packages.tmp
echo "libgom-1.0-common" >> safe-packages.tmp
echo "libgomp1" >> safe-packages.tmp
echo "libgpg-error0" >> safe-packages.tmp
echo "libgpgme11" >> safe-packages.tmp
echo "libgphoto2-6" >> safe-packages.tmp
echo "libgphoto2-l10n" >> safe-packages.tmp
echo "libgphoto2-port12" >> safe-packages.tmp
echo "libgpm2" >> safe-packages.tmp
echo "libgpod-common" >> safe-packages.tmp
echo "libgpod4" >> safe-packages.tmp
echo "libgrail6" >> safe-packages.tmp
echo "libgraphite2-3" >> safe-packages.tmp
echo "libgrilo-0.2-1" >> safe-packages.tmp
echo "libgs9" >> safe-packages.tmp
echo "libgs9-common" >> safe-packages.tmp
echo "libgsettings-qt1" >> safe-packages.tmp
echo "libgssapi-krb5-2" >> safe-packages.tmp
echo "libgssapi3-heimdal" >> safe-packages.tmp
echo "libgstreamer-plugins-base1.0-0" >> safe-packages.tmp
echo "libgstreamer-plugins-good1.0-0" >> safe-packages.tmp
echo "libgstreamer1.0-0" >> safe-packages.tmp
echo "libgtk-3-0" >> safe-packages.tmp
echo "libgtk-3-bin" >> safe-packages.tmp
echo "libgtk-3-common" >> safe-packages.tmp
echo "libgtk2-perl" >> safe-packages.tmp
echo "libgtk2.0-0" >> safe-packages.tmp
echo "libgtk2.0-bin" >> safe-packages.tmp
echo "libgtk2.0-common" >> safe-packages.tmp
echo "libgtkmm-2.4-1v5" >> safe-packages.tmp
echo "libgtkmm-3.0-1v5" >> safe-packages.tmp
echo "libgtksourceview-3.0-1" >> safe-packages.tmp
echo "libgtksourceview-3.0-common" >> safe-packages.tmp
echo "libgtkspell3-3-0" >> safe-packages.tmp
echo "libgtop-2.0-10" >> safe-packages.tmp
echo "libgtop2-common" >> safe-packages.tmp
echo "libgucharmap-2-90-7" >> safe-packages.tmp
echo "libgudev-1.0-0" >> safe-packages.tmp
echo "libgusb2" >> safe-packages.tmp
echo "libgutenprint2" >> safe-packages.tmp
echo "libgweather-3-6" >> safe-packages.tmp
echo "libgweather-common" >> safe-packages.tmp
echo "libgxps2" >> safe-packages.tmp
echo "libhardware2" >> safe-packages.tmp
echo "libharfbuzz-icu0" >> safe-packages.tmp
echo "libharfbuzz0b" >> safe-packages.tmp
echo "libhcrypto4-heimdal" >> safe-packages.tmp
echo "libheimbase1-heimdal" >> safe-packages.tmp
echo "libheimntlm0-heimdal" >> safe-packages.tmp
echo "libhogweed4" >> safe-packages.tmp
echo "libhpmud0" >> safe-packages.tmp
echo "libhtml-form-perl" >> safe-packages.tmp
echo "libhtml-format-perl" >> safe-packages.tmp
echo "libhtml-parser-perl" >> safe-packages.tmp
echo "libhtml-tagset-perl" >> safe-packages.tmp
echo "libhtml-tree-perl" >> safe-packages.tmp
echo "libhttp-cookies-perl" >> safe-packages.tmp
echo "libhttp-daemon-perl" >> safe-packages.tmp
echo "libhttp-date-perl" >> safe-packages.tmp
echo "libhttp-message-perl" >> safe-packages.tmp
echo "libhttp-negotiate-perl" >> safe-packages.tmp
echo "libhud2" >> safe-packages.tmp
echo "libhunspell-1.3-0" >> safe-packages.tmp
echo "libhx509-5-heimdal" >> safe-packages.tmp
echo "libhybris" >> safe-packages.tmp
echo "libhybris-common1" >> safe-packages.tmp
echo "libhyphen0" >> safe-packages.tmp
echo "libibus-1.0-5" >> safe-packages.tmp
echo "libical1a" >> safe-packages.tmp
echo "libice6" >> safe-packages.tmp
echo "libicu55" >> safe-packages.tmp
echo "libidn11" >> safe-packages.tmp
echo "libido3-0.1-0" >> safe-packages.tmp
echo "libiec61883-0" >> safe-packages.tmp
echo "libieee1284-3" >> safe-packages.tmp
echo "libijs-0.35" >> safe-packages.tmp
echo "libilmbase12" >> safe-packages.tmp
echo "libimobiledevice6" >> safe-packages.tmp
echo "libindicator3-7" >> safe-packages.tmp
echo "libinput-bin" >> safe-packages.tmp
echo "libinput10" >> safe-packages.tmp
echo "libio-html-perl" >> safe-packages.tmp
echo "libio-pty-perl" >> safe-packages.tmp
echo "libio-socket-inet6-perl" >> safe-packages.tmp
echo "libio-socket-ssl-perl" >> safe-packages.tmp
echo "libio-string-perl" >> safe-packages.tmp
echo "libipc-run-perl" >> safe-packages.tmp
echo "libipc-system-simple-perl" >> safe-packages.tmp
echo "libisc-export160" >> safe-packages.tmp
echo "libisc160" >> safe-packages.tmp
echo "libisccc140" >> safe-packages.tmp
echo "libisccfg140" >> safe-packages.tmp
echo "libisl15" >> safe-packages.tmp
echo "libitm1" >> safe-packages.tmp
echo "libiw30" >> safe-packages.tmp
echo "libjack-jackd2-0" >> safe-packages.tmp
echo "libjasper1" >> safe-packages.tmp
echo "libjavascriptcoregtk-4.0-18" >> safe-packages.tmp
echo "libjbig0" >> safe-packages.tmp
echo "libjbig2dec0" >> safe-packages.tmp
echo "libjpeg-turbo8" >> safe-packages.tmp
echo "libjpeg8" >> safe-packages.tmp
echo "libjson-c2" >> safe-packages.tmp
echo "libjson-glib-1.0-0" >> safe-packages.tmp
echo "libjson-glib-1.0-common" >> safe-packages.tmp
echo "libjson-perl" >> safe-packages.tmp
echo "libjson-xs-perl" >> safe-packages.tmp
echo "libk5crypto3" >> safe-packages.tmp
echo "libkeyutils1" >> safe-packages.tmp
echo "libklibc" >> safe-packages.tmp
echo "libkmod2" >> safe-packages.tmp
echo "libkpathsea6" >> safe-packages.tmp
echo "libkrb5-26-heimdal" >> safe-packages.tmp
echo "libkrb5-3" >> safe-packages.tmp
echo "libkrb5support0" >> safe-packages.tmp
echo "libksba8" >> safe-packages.tmp
echo "liblangtag-common" >> safe-packages.tmp
echo "liblangtag1" >> safe-packages.tmp
echo "liblcms2-2" >> safe-packages.tmp
echo "liblcms2-utils" >> safe-packages.tmp
echo "libldap-2.4-2" >> safe-packages.tmp
echo "libldb1" >> safe-packages.tmp
echo "liblightdm-gobject-1-0" >> safe-packages.tmp
echo "liblircclient0" >> safe-packages.tmp
echo "liblist-moreutils-perl" >> safe-packages.tmp
echo "libllvm3.6v5" >> safe-packages.tmp
echo "libllvm5.0" >> safe-packages.tmp
echo "liblocale-gettext-perl" >> safe-packages.tmp
echo "liblouis-data" >> safe-packages.tmp
echo "liblouis9" >> safe-packages.tmp
echo "liblouisutdml-bin" >> safe-packages.tmp
echo "liblouisutdml-data" >> safe-packages.tmp
echo "liblouisutdml6" >> safe-packages.tmp
echo "liblqr-1-0" >> safe-packages.tmp
echo "liblsan0" >> safe-packages.tmp
echo "libltdl7" >> safe-packages.tmp
echo "liblua5.2-0" >> safe-packages.tmp
echo "liblwp-mediatypes-perl" >> safe-packages.tmp
echo "liblwp-protocol-https-perl" >> safe-packages.tmp
echo "liblwres141" >> safe-packages.tmp
echo "liblz4-1" >> safe-packages.tmp
echo "liblzma5" >> safe-packages.tmp
echo "liblzo2-2" >> safe-packages.tmp
echo "libmagic1" >> safe-packages.tmp
echo "libmagickcore-6.q16-2" >> safe-packages.tmp
echo "libmagickcore-6.q16-2-extra" >> safe-packages.tmp
echo "libmagickwand-6.q16-2" >> safe-packages.tmp
echo "libmailtools-perl" >> safe-packages.tmp
echo "libmbim-glib4" >> safe-packages.tmp
echo "libmbim-proxy" >> safe-packages.tmp
echo "libmedia1" >> safe-packages.tmp
echo "libmediaart-2.0-0" >> safe-packages.tmp
echo "libmessaging-menu0" >> safe-packages.tmp
echo "libmetacity-private3a" >> safe-packages.tmp
echo "libmhash2" >> safe-packages.tmp
echo "libminiupnpc10" >> safe-packages.tmp
echo "libmirclient9" >> safe-packages.tmp
echo "libmircommon7" >> safe-packages.tmp
echo "libmircore1" >> safe-packages.tmp
echo "libmirprotobuf3" >> safe-packages.tmp
echo "libmm-glib0" >> safe-packages.tmp
echo "libmng2" >> safe-packages.tmp
echo "libmnl0" >> safe-packages.tmp
echo "libmount1" >> safe-packages.tmp
echo "libmpc3" >> safe-packages.tmp
echo "libmpdec2" >> safe-packages.tmp
echo "libmpfr4" >> safe-packages.tmp
echo "libmpx0" >> safe-packages.tmp
echo "libmspack0" >> safe-packages.tmp
echo "libmspub-0.1-1" >> safe-packages.tmp
echo "libmtdev1" >> safe-packages.tmp
echo "libmtp-common" >> safe-packages.tmp
echo "libmtp-runtime" >> safe-packages.tmp
echo "libmtp9" >> safe-packages.tmp
echo "libmwaw-0.3-3" >> safe-packages.tmp
echo "libmythes-1.2-0" >> safe-packages.tmp
echo "libnatpmp1" >> safe-packages.tmp
echo "libnautilus-extension1a" >> safe-packages.tmp
echo "libncurses5" >> safe-packages.tmp
echo "libncursesw5" >> safe-packages.tmp
echo "libndp0" >> safe-packages.tmp
echo "libneon27-gnutls" >> safe-packages.tmp
echo "libnet-dbus-perl" >> safe-packages.tmp
echo "libnet-dns-perl" >> safe-packages.tmp
echo "libnet-domain-tld-perl" >> safe-packages.tmp
echo "libnet-http-perl" >> safe-packages.tmp
echo "libnet-ip-perl" >> safe-packages.tmp
echo "libnet-libidn-perl" >> safe-packages.tmp
echo "libnet-smtp-ssl-perl" >> safe-packages.tmp
echo "libnet-ssleay-perl" >> safe-packages.tmp
echo "libnetfilter-conntrack3" >> safe-packages.tmp
echo "libnetpbm10" >> safe-packages.tmp
echo "libnettle6" >> safe-packages.tmp
echo "libnewt0.52" >> safe-packages.tmp
echo "libnfnetlink0" >> safe-packages.tmp
echo "libnih-dbus1" >> safe-packages.tmp
echo "libnih1" >> safe-packages.tmp
echo "libnl-3-200" >> safe-packages.tmp
echo "libnl-genl-3-200" >> safe-packages.tmp
echo "libnm-glib-vpn1" >> safe-packages.tmp
echo "libnm-glib4" >> safe-packages.tmp
echo "libnm-gtk-common" >> safe-packages.tmp
echo "libnm-gtk0" >> safe-packages.tmp
echo "libnm-util2" >> safe-packages.tmp
echo "libnm0" >> safe-packages.tmp
echo "libnma-common" >> safe-packages.tmp
echo "libnma0" >> safe-packages.tmp
echo "libnotify-bin" >> safe-packages.tmp
echo "libnotify4" >> safe-packages.tmp
echo "libnpth0" >> safe-packages.tmp
echo "libnspr4" >> safe-packages.tmp
echo "libnss-mdns" >> safe-packages.tmp
echo "libnss3" >> safe-packages.tmp
echo "libnss3-nssdb" >> safe-packages.tmp
echo "libnuma1" >> safe-packages.tmp
echo "libnux-4.0-0" >> safe-packages.tmp
echo "libnux-4.0-common" >> safe-packages.tmp
echo "liboauth0" >> safe-packages.tmp
echo "libodfgen-0.1-1" >> safe-packages.tmp
echo "libogg0" >> safe-packages.tmp
echo "libopenexr22" >> safe-packages.tmp
echo "libopus0" >> safe-packages.tmp
echo "liborc-0.4-0" >> safe-packages.tmp
echo "liborcus-0.10-0v5" >> safe-packages.tmp
echo "liboxideqt-qmlplugin" >> safe-packages.tmp
echo "liboxideqtcore0" >> safe-packages.tmp
echo "liboxideqtquick0" >> safe-packages.tmp
echo "libp11-kit-gnome-keyring" >> safe-packages.tmp
echo "libp11-kit0" >> safe-packages.tmp
echo "libpackagekit-glib2-16" >> safe-packages.tmp
echo "libpagemaker-0.0-0" >> safe-packages.tmp
echo "libpam-cracklib" >> safe-packages.tmp
echo "libpam-gnome-keyring" >> safe-packages.tmp
echo "libpam-modules" >> safe-packages.tmp
echo "libpam-modules-bin" >> safe-packages.tmp
echo "libpam-runtime" >> safe-packages.tmp
echo "libpam-systemd" >> safe-packages.tmp
echo "libpam0g" >> safe-packages.tmp
echo "libpango-1.0-0" >> safe-packages.tmp
echo "libpango-perl" >> safe-packages.tmp
echo "libpangocairo-1.0-0" >> safe-packages.tmp
echo "libpangoft2-1.0-0" >> safe-packages.tmp
echo "libpangomm-1.4-1v5" >> safe-packages.tmp
echo "libpangoxft-1.0-0" >> safe-packages.tmp
echo "libpaper-utils" >> safe-packages.tmp
echo "libpaper1" >> safe-packages.tmp
echo "libparse-debianchangelog-perl" >> safe-packages.tmp
echo "libparted2" >> safe-packages.tmp
echo "libpcap0.8" >> safe-packages.tmp
echo "libpci3" >> safe-packages.tmp
echo "libpciaccess0" >> safe-packages.tmp
echo "libpcre16-3" >> safe-packages.tmp
echo "libpcre3" >> safe-packages.tmp
echo "libpcsclite1" >> safe-packages.tmp
echo "libpeas-1.0-0" >> safe-packages.tmp
echo "libpeas-1.0-0-python3loader" >> safe-packages.tmp
echo "libpeas-common" >> safe-packages.tmp
echo "libperl5.22" >> safe-packages.tmp
echo "libperlio-gzip-perl" >> safe-packages.tmp
echo "libpipeline1" >> safe-packages.tmp
echo "libpixman-1-0" >> safe-packages.tmp
echo "libplist3" >> safe-packages.tmp
echo "libplymouth4" >> safe-packages.tmp
echo "libpng12-0" >> safe-packages.tmp
echo "libpolkit-agent-1-0" >> safe-packages.tmp
echo "libpolkit-backend-1-0" >> safe-packages.tmp
echo "libpolkit-gobject-1-0" >> safe-packages.tmp
echo "libpoppler-glib8" >> safe-packages.tmp
echo "libpoppler58" >> safe-packages.tmp
echo "libpopt0" >> safe-packages.tmp
echo "libportaudio2" >> safe-packages.tmp
echo "libprocps4" >> safe-packages.tmp
echo "libprotobuf-lite9v5" >> safe-packages.tmp
echo "libprotobuf9v5" >> safe-packages.tmp
echo "libproxy1-plugin-gsettings" >> safe-packages.tmp
echo "libproxy1-plugin-networkmanager" >> safe-packages.tmp
echo "libproxy1v5" >> safe-packages.tmp
echo "libpulse-mainloop-glib0" >> safe-packages.tmp
echo "libpulse0" >> safe-packages.tmp
echo "libpulsedsp" >> safe-packages.tmp
echo "libpwquality-common" >> safe-packages.tmp
echo "libpwquality1" >> safe-packages.tmp
echo "libpython-stdlib" >> safe-packages.tmp
echo "libpython2.7" >> safe-packages.tmp
echo "libpython2.7-minimal" >> safe-packages.tmp
echo "libpython2.7-stdlib" >> safe-packages.tmp
echo "libpython3-stdlib" >> safe-packages.tmp
echo "libpython3.5" >> safe-packages.tmp
echo "libpython3.5-minimal" >> safe-packages.tmp
echo "libpython3.5-stdlib" >> safe-packages.tmp
echo "libqmi-glib1" >> safe-packages.tmp
echo "libqmi-proxy" >> safe-packages.tmp
echo "libqpdf17" >> safe-packages.tmp
echo "libqqwing2v5" >> safe-packages.tmp
echo "libqt4-dbus" >> safe-packages.tmp
echo "libqt4-declarative" >> safe-packages.tmp
echo "libqt4-network" >> safe-packages.tmp
echo "libqt4-script" >> safe-packages.tmp
echo "libqt4-sql" >> safe-packages.tmp
echo "libqt4-sql-sqlite" >> safe-packages.tmp
echo "libqt4-xml" >> safe-packages.tmp
echo "libqt4-xmlpatterns" >> safe-packages.tmp
echo "libqt5core5a" >> safe-packages.tmp
echo "libqt5dbus5" >> safe-packages.tmp
echo "libqt5feedback5" >> safe-packages.tmp
echo "libqt5gui5" >> safe-packages.tmp
echo "libqt5multimedia5" >> safe-packages.tmp
echo "libqt5network5" >> safe-packages.tmp
echo "libqt5opengl5" >> safe-packages.tmp
echo "libqt5organizer5" >> safe-packages.tmp
echo "libqt5positioning5" >> safe-packages.tmp
echo "libqt5printsupport5" >> safe-packages.tmp
echo "libqt5qml5" >> safe-packages.tmp
echo "libqt5quick5" >> safe-packages.tmp
echo "libqt5quicktest5" >> safe-packages.tmp
echo "libqt5sql5" >> safe-packages.tmp
echo "libqt5sql5-sqlite" >> safe-packages.tmp
echo "libqt5svg5" >> safe-packages.tmp
echo "libqt5test5" >> safe-packages.tmp
echo "libqt5webkit5" >> safe-packages.tmp
echo "libqt5widgets5" >> safe-packages.tmp
echo "libqt5xml5" >> safe-packages.tmp
echo "libqtcore4" >> safe-packages.tmp
echo "libqtdbus4" >> safe-packages.tmp
echo "libqtgui4" >> safe-packages.tmp
echo "libquadmath0" >> safe-packages.tmp
echo "libquvi-scripts" >> safe-packages.tmp
echo "libquvi7" >> safe-packages.tmp
echo "libraptor2-0" >> safe-packages.tmp
echo "librasqal3" >> safe-packages.tmp
echo "libraw1394-11" >> safe-packages.tmp
echo "libraw15" >> safe-packages.tmp
echo "librdf0" >> safe-packages.tmp
echo "libreadline6" >> safe-packages.tmp
echo "libreoffice-avmedia-backend-gstreamer" >> safe-packages.tmp
echo "libreoffice-base-core" >> safe-packages.tmp
echo "libreoffice-calc" >> safe-packages.tmp
echo "libreoffice-common" >> safe-packages.tmp
echo "libreoffice-core" >> safe-packages.tmp
echo "libreoffice-draw" >> safe-packages.tmp
echo "libreoffice-gnome" >> safe-packages.tmp
echo "libreoffice-gtk" >> safe-packages.tmp
echo "libreoffice-help-en-us" >> safe-packages.tmp
echo "libreoffice-impress" >> safe-packages.tmp
echo "libreoffice-math" >> safe-packages.tmp
echo "libreoffice-ogltrans" >> safe-packages.tmp
echo "libreoffice-pdfimport" >> safe-packages.tmp
echo "libreoffice-style-breeze" >> safe-packages.tmp
echo "libreoffice-style-galaxy" >> safe-packages.tmp
echo "libreoffice-writer" >> safe-packages.tmp
echo "librest-0.7-0" >> safe-packages.tmp
echo "librevenge-0.0-0" >> safe-packages.tmp
echo "librhythmbox-core9" >> safe-packages.tmp
echo "libroken18-heimdal" >> safe-packages.tmp
echo "librsvg2-2" >> safe-packages.tmp
echo "librsvg2-common" >> safe-packages.tmp
echo "librtmp1" >> safe-packages.tmp
echo "libsamplerate0" >> safe-packages.tmp
echo "libsane" >> safe-packages.tmp
echo "libsane-common" >> safe-packages.tmp
echo "libsane-hpaio" >> safe-packages.tmp
echo "libsasl2-2" >> safe-packages.tmp
echo "libsasl2-modules" >> safe-packages.tmp
echo "libsasl2-modules-db" >> safe-packages.tmp
echo "libsbc1" >> safe-packages.tmp
echo "libseccomp2" >> safe-packages.tmp
echo "libsecret-1-0" >> safe-packages.tmp
echo "libsecret-common" >> safe-packages.tmp
echo "libselinux1" >> safe-packages.tmp
echo "libsemanage-common" >> safe-packages.tmp
echo "libsemanage1" >> safe-packages.tmp
echo "libsensors4" >> safe-packages.tmp
echo "libsepol1" >> safe-packages.tmp
echo "libsgutils2-2" >> safe-packages.tmp
echo "libshout3" >> safe-packages.tmp
echo "libsigc++-2.0-0v5" >> safe-packages.tmp
echo "libsignon-extension1" >> safe-packages.tmp
echo "libsignon-glib1" >> safe-packages.tmp
echo "libsignon-plugins-common1" >> safe-packages.tmp
echo "libsignon-qt5-1" >> safe-packages.tmp
echo "libslang2" >> safe-packages.tmp
echo "libsm6" >> safe-packages.tmp
echo "libsmartcols1" >> safe-packages.tmp
echo "libsmbclient" >> safe-packages.tmp
echo "libsnapd-glib1" >> safe-packages.tmp
echo "libsndfile1" >> safe-packages.tmp
echo "libsnmp-base" >> safe-packages.tmp
echo "libsnmp30" >> safe-packages.tmp
echo "libsocket6-perl" >> safe-packages.tmp
echo "libsonic0" >> safe-packages.tmp
echo "libsoup-gnome2.4-1" >> safe-packages.tmp
echo "libsoup2.4-1" >> safe-packages.tmp
echo "libspectre1" >> safe-packages.tmp
echo "libspeechd2" >> safe-packages.tmp
echo "libspeex1" >> safe-packages.tmp
echo "libspeexdsp1" >> safe-packages.tmp
echo "libsqlite3-0" >> safe-packages.tmp
echo "libss2" >> safe-packages.tmp
echo "libssh-4" >> safe-packages.tmp
echo "libssl1.0.0" >> safe-packages.tmp
echo "libstartup-notification0" >> safe-packages.tmp
echo "libstdc++-5-dev" >> safe-packages.tmp
echo "libstdc++6" >> safe-packages.tmp
echo "libsub-name-perl" >> safe-packages.tmp
echo "libsuitesparseconfig4.4.6" >> safe-packages.tmp
echo "libsystemd0" >> safe-packages.tmp
echo "libtag1v5" >> safe-packages.tmp
echo "libtag1v5-vanilla" >> safe-packages.tmp
echo "libtalloc2" >> safe-packages.tmp
echo "libtasn1-6" >> safe-packages.tmp
echo "libtcl8.6" >> safe-packages.tmp
echo "libtdb1" >> safe-packages.tmp
echo "libtelepathy-glib0" >> safe-packages.tmp
echo "libterm-readkey-perl" >> safe-packages.tmp
echo "libtevent0" >> safe-packages.tmp
echo "libtext-charwidth-perl" >> safe-packages.tmp
echo "libtext-csv-perl" >> safe-packages.tmp
echo "libtext-csv-xs-perl" >> safe-packages.tmp
echo "libtext-iconv-perl" >> safe-packages.tmp
echo "libtext-levenshtein-perl" >> safe-packages.tmp
echo "libtext-wrapi18n-perl" >> safe-packages.tmp
echo "libthai-data" >> safe-packages.tmp
echo "libthai0" >> safe-packages.tmp
echo "libtheora0" >> safe-packages.tmp
echo "libtie-ixhash-perl" >> safe-packages.tmp
echo "libtiff5" >> safe-packages.tmp
echo "libtimedate-perl" >> safe-packages.tmp
echo "libtimezonemap-data" >> safe-packages.tmp
echo "libtimezonemap1" >> safe-packages.tmp
echo "libtinfo5" >> safe-packages.tmp
echo "libtk8.6" >> safe-packages.tmp
echo "libtotem-plparser-common" >> safe-packages.tmp
echo "libtotem-plparser18" >> safe-packages.tmp
echo "libtotem0" >> safe-packages.tmp
echo "libtracker-sparql-1.0-0" >> safe-packages.tmp
echo "libtsan0" >> safe-packages.tmp
echo "libtxc-dxtn-s2tc0" >> safe-packages.tmp
echo "libtypes-serialiser-perl" >> safe-packages.tmp
echo "libubsan0" >> safe-packages.tmp
echo "libubuntugestures5" >> safe-packages.tmp
echo "libubuntutoolkit5" >> safe-packages.tmp
echo "libudev1" >> safe-packages.tmp
echo "libudisks2-0" >> safe-packages.tmp
echo "libunistring0" >> safe-packages.tmp
echo "libunity-action-qt1" >> safe-packages.tmp
echo "libunity-control-center1" >> safe-packages.tmp
echo "libunity-core-6.0-9" >> safe-packages.tmp
echo "libunity-gtk2-parser0" >> safe-packages.tmp
echo "libunity-gtk3-parser0" >> safe-packages.tmp
echo "libunity-misc4" >> safe-packages.tmp
echo "libunity-protocol-private0" >> safe-packages.tmp
echo "libunity-scopes-json-def-desktop" >> safe-packages.tmp
echo "libunity-settings-daemon1" >> safe-packages.tmp
echo "libunity-webapps0" >> safe-packages.tmp
echo "libunity9" >> safe-packages.tmp
echo "libunwind8" >> safe-packages.tmp
echo "libupower-glib3" >> safe-packages.tmp
echo "liburi-perl" >> safe-packages.tmp
echo "liburl-dispatcher1" >> safe-packages.tmp
echo "libusb-0.1-4" >> safe-packages.tmp
echo "libusb-1.0-0" >> safe-packages.tmp
echo "libusbmuxd4" >> safe-packages.tmp
echo "libustr-1.0-1" >> safe-packages.tmp
echo "libutempter0" >> safe-packages.tmp
echo "libuuid-perl" >> safe-packages.tmp
echo "libuuid1" >> safe-packages.tmp
echo "libv4l-0" >> safe-packages.tmp
echo "libv4lconvert0" >> safe-packages.tmp
echo "libvisio-0.1-1" >> safe-packages.tmp
echo "libvisual-0.4-0" >> safe-packages.tmp
echo "libvncclient1" >> safe-packages.tmp
echo "libvorbis0a" >> safe-packages.tmp
echo "libvorbisenc2" >> safe-packages.tmp
echo "libvorbisfile3" >> safe-packages.tmp
echo "libvpx3" >> safe-packages.tmp
echo "libvte-2.91-0" >> safe-packages.tmp
echo "libvte-2.91-common" >> safe-packages.tmp
echo "libwacom-bin" >> safe-packages.tmp
echo "libwacom-common" >> safe-packages.tmp
echo "libwacom2" >> safe-packages.tmp
echo "libwavpack1" >> safe-packages.tmp
echo "libwayland-client0" >> safe-packages.tmp
echo "libwayland-cursor0" >> safe-packages.tmp
echo "libwayland-egl1-mesa" >> safe-packages.tmp
echo "libwayland-server0" >> safe-packages.tmp
echo "libwbclient0" >> safe-packages.tmp
echo "libwebkit2gtk-4.0-37" >> safe-packages.tmp
echo "libwebkit2gtk-4.0-37-gtk2" >> safe-packages.tmp
echo "libwebp5" >> safe-packages.tmp
echo "libwebpmux1" >> safe-packages.tmp
echo "libwebrtc-audio-processing-0" >> safe-packages.tmp
echo "libwhoopsie-preferences0" >> safe-packages.tmp
echo "libwhoopsie0" >> safe-packages.tmp
echo "libwind0-heimdal" >> safe-packages.tmp
echo "libwinpr-crt0.1" >> safe-packages.tmp
echo "libwinpr-dsparse0.1" >> safe-packages.tmp
echo "libwinpr-environment0.1" >> safe-packages.tmp
echo "libwinpr-file0.1" >> safe-packages.tmp
echo "libwinpr-handle0.1" >> safe-packages.tmp
echo "libwinpr-heap0.1" >> safe-packages.tmp
echo "libwinpr-input0.1" >> safe-packages.tmp
echo "libwinpr-interlocked0.1" >> safe-packages.tmp
echo "libwinpr-library0.1" >> safe-packages.tmp
echo "libwinpr-path0.1" >> safe-packages.tmp
echo "libwinpr-pool0.1" >> safe-packages.tmp
echo "libwinpr-registry0.1" >> safe-packages.tmp
echo "libwinpr-rpc0.1" >> safe-packages.tmp
echo "libwinpr-sspi0.1" >> safe-packages.tmp
echo "libwinpr-synch0.1" >> safe-packages.tmp
echo "libwinpr-sysinfo0.1" >> safe-packages.tmp
echo "libwinpr-thread0.1" >> safe-packages.tmp
echo "libwinpr-utils0.1" >> safe-packages.tmp
echo "libwmf0.2-7" >> safe-packages.tmp
echo "libwmf0.2-7-gtk" >> safe-packages.tmp
echo "libwnck-3-0" >> safe-packages.tmp
echo "libwnck-3-common" >> safe-packages.tmp
echo "libwpd-0.10-10" >> safe-packages.tmp
echo "libwpg-0.3-3" >> safe-packages.tmp
echo "libwps-0.4-4" >> safe-packages.tmp
echo "libwrap0" >> safe-packages.tmp
echo "libwww-perl" >> safe-packages.tmp
echo "libwww-robotrules-perl" >> safe-packages.tmp
echo "libx11-6" >> safe-packages.tmp
echo "libx11-data" >> safe-packages.tmp
echo "libx11-protocol-perl" >> safe-packages.tmp
echo "libx11-xcb1" >> safe-packages.tmp
echo "libx86-1" >> safe-packages.tmp
echo "libxapian22v5" >> safe-packages.tmp
echo "libxatracker2" >> safe-packages.tmp
echo "libxau6" >> safe-packages.tmp
echo "libxaw7" >> safe-packages.tmp
echo "libxcb-dri2-0" >> safe-packages.tmp
echo "libxcb-dri3-0" >> safe-packages.tmp
echo "libxcb-glx0" >> safe-packages.tmp
echo "libxcb-icccm4" >> safe-packages.tmp
echo "libxcb-image0" >> safe-packages.tmp
echo "libxcb-keysyms1" >> safe-packages.tmp
echo "libxcb-present0" >> safe-packages.tmp
echo "libxcb-randr0" >> safe-packages.tmp
echo "libxcb-render-util0" >> safe-packages.tmp
echo "libxcb-render0" >> safe-packages.tmp
echo "libxcb-shape0" >> safe-packages.tmp
echo "libxcb-shm0" >> safe-packages.tmp
echo "libxcb-sync1" >> safe-packages.tmp
echo "libxcb-util1" >> safe-packages.tmp
echo "libxcb-xfixes0" >> safe-packages.tmp
echo "libxcb-xkb1" >> safe-packages.tmp
echo "libxcb1" >> safe-packages.tmp
echo "libxcomposite1" >> safe-packages.tmp
echo "libxcursor1" >> safe-packages.tmp
echo "libxdamage1" >> safe-packages.tmp
echo "libxdmcp6" >> safe-packages.tmp
echo "libxext6" >> safe-packages.tmp
echo "libxfixes3" >> safe-packages.tmp
echo "libxfont1" >> safe-packages.tmp
echo "libxft2" >> safe-packages.tmp
echo "libxi6" >> safe-packages.tmp
echo "libxinerama1" >> safe-packages.tmp
echo "libxkbcommon-x11-0" >> safe-packages.tmp
echo "libxkbcommon0" >> safe-packages.tmp
echo "libxkbfile1" >> safe-packages.tmp
echo "libxklavier16" >> safe-packages.tmp
echo "libxml-parser-perl" >> safe-packages.tmp
echo "libxml-twig-perl" >> safe-packages.tmp
echo "libxml-xpathengine-perl" >> safe-packages.tmp
echo "libxml2" >> safe-packages.tmp
echo "libxmu6" >> safe-packages.tmp
echo "libxmuu1" >> safe-packages.tmp
echo "libxpm4" >> safe-packages.tmp
echo "libxrandr2" >> safe-packages.tmp
echo "libxrender1" >> safe-packages.tmp
echo "libxres1" >> safe-packages.tmp
echo "libxshmfence1" >> safe-packages.tmp
echo "libxslt1.1" >> safe-packages.tmp
echo "libxss1" >> safe-packages.tmp
echo "libxt6" >> safe-packages.tmp
echo "libxtables11" >> safe-packages.tmp
echo "libxtst6" >> safe-packages.tmp
echo "libxv1" >> safe-packages.tmp
echo "libxvmc1" >> safe-packages.tmp
echo "libxxf86dga1" >> safe-packages.tmp
echo "libxxf86vm1" >> safe-packages.tmp
echo "libyajl2" >> safe-packages.tmp
echo "libyaml-0-2" >> safe-packages.tmp
echo "libyaml-libyaml-perl" >> safe-packages.tmp
echo "libyaml-tiny-perl" >> safe-packages.tmp
echo "libyelp0" >> safe-packages.tmp
echo "libzeitgeist-1.0-1" >> safe-packages.tmp
echo "libzeitgeist-2.0-0" >> safe-packages.tmp
echo "light-themes" >> safe-packages.tmp
echo "lightdm" >> safe-packages.tmp
echo "lintian" >> safe-packages.tmp
echo "linux-base" >> safe-packages.tmp
echo "linux-firmware" >> safe-packages.tmp
echo "linux-generic" >> safe-packages.tmp
echo "linux-headers-4.4.0-112" >> safe-packages.tmp
echo "linux-headers-4.4.0-112-generic" >> safe-packages.tmp
echo "linux-headers-4.4.0-31" >> safe-packages.tmp
echo "linux-headers-4.4.0-31-generic" >> safe-packages.tmp
echo "linux-headers-generic" >> safe-packages.tmp
echo "linux-image-4.4.0-112-generic" >> safe-packages.tmp
echo "linux-image-4.4.0-31-generic" >> safe-packages.tmp
echo "linux-image-extra-4.4.0-112-generic" >> safe-packages.tmp
echo "linux-image-extra-4.4.0-31-generic" >> safe-packages.tmp
echo "linux-image-generic" >> safe-packages.tmp
echo "linux-libc-dev" >> safe-packages.tmp
echo "linux-sound-base" >> safe-packages.tmp
echo "locales" >> safe-packages.tmp
echo "login" >> safe-packages.tmp
echo "logrotate" >> safe-packages.tmp
echo "lp-solve" >> safe-packages.tmp
echo "lsb-base" >> safe-packages.tmp
echo "lsb-release" >> safe-packages.tmp
echo "lshw" >> safe-packages.tmp
echo "lsof" >> safe-packages.tmp
echo "ltrace" >> safe-packages.tmp
echo "lynis" >> safe-packages.tmp
echo "make" >> safe-packages.tmp
echo "makedev" >> safe-packages.tmp
echo "man-db" >> safe-packages.tmp
echo "manpages" >> safe-packages.tmp
echo "manpages-dev" >> safe-packages.tmp
echo "mawk" >> safe-packages.tmp
echo "media-player-info" >> safe-packages.tmp
echo "memtest86+" >> safe-packages.tmp
echo "menu" >> safe-packages.tmp
echo "metacity-common" >> safe-packages.tmp
echo "mime-support" >> safe-packages.tmp
echo "mlocate" >> safe-packages.tmp
echo "mobile-broadband-provider-info" >> safe-packages.tmp
echo "modemmanager" >> safe-packages.tmp
echo "mount" >> safe-packages.tmp
echo "mountall" >> safe-packages.tmp
echo "mousetweaks" >> safe-packages.tmp
echo "mscompress" >> safe-packages.tmp
echo "mtools" >> safe-packages.tmp
echo "mtr-tiny" >> safe-packages.tmp
echo "multiarch-support" >> safe-packages.tmp
echo "mythes-en-us" >> safe-packages.tmp
echo "nano" >> safe-packages.tmp
echo "nautilus" >> safe-packages.tmp
echo "nautilus-data" >> safe-packages.tmp
echo "nautilus-sendto" >> safe-packages.tmp
echo "nautilus-share" >> safe-packages.tmp
echo "ncurses-base" >> safe-packages.tmp
echo "ncurses-bin" >> safe-packages.tmp
echo "net-tools" >> safe-packages.tmp
echo "netbase" >> safe-packages.tmp
echo "netcat-openbsd" >> safe-packages.tmp
echo "netpbm" >> safe-packages.tmp
echo "network-manager" >> safe-packages.tmp
echo "network-manager-gnome" >> safe-packages.tmp
echo "network-manager-pptp" >> safe-packages.tmp
echo "network-manager-pptp-gnome" >> safe-packages.tmp
echo "notify-osd" >> safe-packages.tmp
echo "notify-osd-icons" >> safe-packages.tmp
echo "ntfs-3g" >> safe-packages.tmp
echo "nux-tools" >> safe-packages.tmp
echo "onboard" >> safe-packages.tmp
echo "onboard-data" >> safe-packages.tmp
echo "open-vm-tools" >> safe-packages.tmp
echo "open-vm-tools-desktop" >> safe-packages.tmp
echo "open-vm-tools-dkms" >> safe-packages.tmp
echo "openoffice.org-hyphenation" >> safe-packages.tmp
echo "openprinting-ppds" >> safe-packages.tmp
echo "openssh-client" >> safe-packages.tmp
echo "openssl" >> safe-packages.tmp
echo "os-prober" >> safe-packages.tmp
echo "overlay-scrollbar" >> safe-packages.tmp
echo "overlay-scrollbar-gtk2" >> safe-packages.tmp
echo "oxideqt-codecs" >> safe-packages.tmp
echo "p11-kit" >> safe-packages.tmp
echo "p11-kit-modules" >> safe-packages.tmp
echo "parted" >> safe-packages.tmp
echo "passwd" >> safe-packages.tmp
echo "patch" >> safe-packages.tmp
echo "patchutils" >> safe-packages.tmp
echo "pciutils" >> safe-packages.tmp
echo "pcmciautils" >> safe-packages.tmp
echo "perl" >> safe-packages.tmp
echo "perl-base" >> safe-packages.tmp
echo "perl-modules-5.22" >> safe-packages.tmp
echo "pinentry-gnome3" >> safe-packages.tmp
echo "pkg-config" >> safe-packages.tmp
echo "plainbox-provider-checkbox" >> safe-packages.tmp
echo "plainbox-provider-resource-generic" >> safe-packages.tmp
echo "plainbox-secure-policy" >> safe-packages.tmp
echo "plymouth" >> safe-packages.tmp
echo "plymouth-label" >> safe-packages.tmp
echo "plymouth-theme-ubuntu-logo" >> safe-packages.tmp
echo "plymouth-theme-ubuntu-text" >> safe-packages.tmp
echo "pm-utils" >> safe-packages.tmp
echo "policykit-1" >> safe-packages.tmp
echo "policykit-1-gnome" >> safe-packages.tmp
echo "policykit-desktop-privileges" >> safe-packages.tmp
echo "poppler-data" >> safe-packages.tmp
echo "poppler-utils" >> safe-packages.tmp
echo "popularity-contest" >> safe-packages.tmp
echo "postfix" >> safe-packages.tmp
echo "powermgmt-base" >> safe-packages.tmp
echo "ppp" >> safe-packages.tmp
echo "pppconfig" >> safe-packages.tmp
echo "pppoeconf" >> safe-packages.tmp
echo "pptp-linux" >> safe-packages.tmp
echo "printer-driver-brlaser" >> safe-packages.tmp
echo "printer-driver-c2esp" >> safe-packages.tmp
echo "printer-driver-foo2zjs" >> safe-packages.tmp
echo "printer-driver-foo2zjs-common" >> safe-packages.tmp
echo "printer-driver-gutenprint" >> safe-packages.tmp
echo "printer-driver-hpcups" >> safe-packages.tmp
echo "printer-driver-min12xxw" >> safe-packages.tmp
echo "printer-driver-pnm2ppa" >> safe-packages.tmp
echo "printer-driver-postscript-hp" >> safe-packages.tmp
echo "printer-driver-ptouch" >> safe-packages.tmp
echo "printer-driver-pxljr" >> safe-packages.tmp
echo "printer-driver-sag-gdi" >> safe-packages.tmp
echo "printer-driver-splix" >> safe-packages.tmp
echo "procps" >> safe-packages.tmp
echo "psmisc" >> safe-packages.tmp
echo "pulseaudio" >> safe-packages.tmp
echo "pulseaudio-module-bluetooth" >> safe-packages.tmp
echo "pulseaudio-module-x11" >> safe-packages.tmp
echo "pulseaudio-utils" >> safe-packages.tmp
echo "pyotherside" >> safe-packages.tmp
echo "python" >> safe-packages.tmp
echo "python-apt-common" >> safe-packages.tmp
echo "python-minimal" >> safe-packages.tmp
echo "python-talloc" >> safe-packages.tmp
echo "python2.7" >> safe-packages.tmp
echo "python2.7-minimal" >> safe-packages.tmp
echo "python3" >> safe-packages.tmp
echo "python3-apport" >> safe-packages.tmp
echo "python3-apt" >> safe-packages.tmp
echo "python3-aptdaemon" >> safe-packages.tmp
echo "python3-aptdaemon.gtk3widgets" >> safe-packages.tmp
echo "python3-aptdaemon.pkcompat" >> safe-packages.tmp
echo "python3-blinker" >> safe-packages.tmp
echo "python3-brlapi" >> safe-packages.tmp
echo "python3-bs4" >> safe-packages.tmp
echo "python3-cairo" >> safe-packages.tmp
echo "python3-cffi-backend" >> safe-packages.tmp
echo "python3-chardet" >> safe-packages.tmp
echo "python3-checkbox-support" >> safe-packages.tmp
echo "python3-commandnotfound" >> safe-packages.tmp
echo "python3-cryptography" >> safe-packages.tmp
echo "python3-cups" >> safe-packages.tmp
echo "python3-cupshelpers" >> safe-packages.tmp
echo "python3-dbus" >> safe-packages.tmp
echo "python3-debian" >> safe-packages.tmp
echo "python3-defer" >> safe-packages.tmp
echo "python3-distupgrade" >> safe-packages.tmp
echo "python3-feedparser" >> safe-packages.tmp
echo "python3-gdbm" >> safe-packages.tmp
echo "python3-gi" >> safe-packages.tmp
echo "python3-gi-cairo" >> safe-packages.tmp
echo "python3-guacamole" >> safe-packages.tmp
echo "python3-html5lib" >> safe-packages.tmp
echo "python3-httplib2" >> safe-packages.tmp
echo "python3-idna" >> safe-packages.tmp
echo "python3-jinja2" >> safe-packages.tmp
echo "python3-jwt" >> safe-packages.tmp
echo "python3-louis" >> safe-packages.tmp
echo "python3-lxml" >> safe-packages.tmp
echo "python3-mako" >> safe-packages.tmp
echo "python3-markupsafe" >> safe-packages.tmp
echo "python3-minimal" >> safe-packages.tmp
echo "python3-oauthlib" >> safe-packages.tmp
echo "python3-padme" >> safe-packages.tmp
echo "python3-pexpect" >> safe-packages.tmp
echo "python3-pil" >> safe-packages.tmp
echo "python3-pkg-resources" >> safe-packages.tmp
echo "python3-plainbox" >> safe-packages.tmp
echo "python3-problem-report" >> safe-packages.tmp
echo "python3-ptyprocess" >> safe-packages.tmp
echo "python3-pyasn1" >> safe-packages.tmp
echo "python3-pyatspi" >> safe-packages.tmp
echo "python3-pycurl" >> safe-packages.tmp
echo "python3-pyparsing" >> safe-packages.tmp
echo "python3-renderpm" >> safe-packages.tmp
echo "python3-reportlab" >> safe-packages.tmp
echo "python3-reportlab-accel" >> safe-packages.tmp
echo "python3-requests" >> safe-packages.tmp
echo "python3-six" >> safe-packages.tmp
echo "python3-software-properties" >> safe-packages.tmp
echo "python3-speechd" >> safe-packages.tmp
echo "python3-systemd" >> safe-packages.tmp
echo "python3-uno" >> safe-packages.tmp
echo "python3-update-manager" >> safe-packages.tmp
echo "python3-urllib3" >> safe-packages.tmp
echo "python3-xdg" >> safe-packages.tmp
echo "python3-xkit" >> safe-packages.tmp
echo "python3-xlsxwriter" >> safe-packages.tmp
echo "python3.5" >> safe-packages.tmp
echo "python3.5-minimal" >> safe-packages.tmp
echo "qdbus" >> safe-packages.tmp
echo "qml-module-io-thp-pyotherside" >> safe-packages.tmp
echo "qml-module-qt-labs-folderlistmodel" >> safe-packages.tmp
echo "qml-module-qt-labs-settings" >> safe-packages.tmp
echo "qml-module-qtfeedback" >> safe-packages.tmp
echo "qml-module-qtgraphicaleffects" >> safe-packages.tmp
echo "qml-module-qtquick-layouts" >> safe-packages.tmp
echo "qml-module-qtquick-window2" >> safe-packages.tmp
echo "qml-module-qtquick2" >> safe-packages.tmp
echo "qml-module-qttest" >> safe-packages.tmp
echo "qml-module-ubuntu-components" >> safe-packages.tmp
echo "qml-module-ubuntu-layouts" >> safe-packages.tmp
echo "qml-module-ubuntu-onlineaccounts" >> safe-packages.tmp
echo "qml-module-ubuntu-performancemetrics" >> safe-packages.tmp
echo "qml-module-ubuntu-test" >> safe-packages.tmp
echo "qml-module-ubuntu-web" >> safe-packages.tmp
echo "qmlscene" >> safe-packages.tmp
echo "qpdf" >> safe-packages.tmp
echo "qt-at-spi" >> safe-packages.tmp
echo "qtchooser" >> safe-packages.tmp
echo "qtcore4-l10n" >> safe-packages.tmp
echo "qtdeclarative5-accounts-plugin" >> safe-packages.tmp
echo "qtdeclarative5-dev-tools" >> safe-packages.tmp
echo "qtdeclarative5-qtquick2-plugin" >> safe-packages.tmp
echo "qtdeclarative5-test-plugin" >> safe-packages.tmp
echo "qtdeclarative5-ubuntu-ui-toolkit-plugin" >> safe-packages.tmp
echo "qtdeclarative5-unity-action-plugin" >> safe-packages.tmp
echo "qttranslations5-l10n" >> safe-packages.tmp
echo "readline-common" >> safe-packages.tmp
echo "remmina" >> safe-packages.tmp
echo "remmina-common" >> safe-packages.tmp
echo "remmina-plugin-rdp" >> safe-packages.tmp
echo "remmina-plugin-vnc" >> safe-packages.tmp
echo "rename" >> safe-packages.tmp
echo "resolvconf" >> safe-packages.tmp
echo "rfkill" >> safe-packages.tmp
echo "rhythmbox" >> safe-packages.tmp
echo "rhythmbox-data" >> safe-packages.tmp
echo "rhythmbox-plugin-zeitgeist" >> safe-packages.tmp
echo "rhythmbox-plugins" >> safe-packages.tmp
echo "rsync" >> safe-packages.tmp
echo "rsyslog" >> safe-packages.tmp
echo "rtkit" >> safe-packages.tmp
echo "samba-libs" >> safe-packages.tmp
echo "sane-utils" >> safe-packages.tmp
echo "sbsigntool" >> safe-packages.tmp
echo "seahorse" >> safe-packages.tmp
echo "secureboot-db" >> safe-packages.tmp
echo "sed" >> safe-packages.tmp
echo "sensible-utils" >> safe-packages.tmp
echo "session-migration" >> safe-packages.tmp
echo "session-shortcuts" >> safe-packages.tmp
echo "sessioninstaller" >> safe-packages.tmp
echo "sgml-base" >> safe-packages.tmp
echo "shared-mime-info" >> safe-packages.tmp
echo "shotwell" >> safe-packages.tmp
echo "shotwell-common" >> safe-packages.tmp
echo "signon-keyring-extension" >> safe-packages.tmp
echo "signon-plugin-oauth2" >> safe-packages.tmp
echo "signon-plugin-password" >> safe-packages.tmp
echo "signon-ui" >> safe-packages.tmp
echo "signon-ui-service" >> safe-packages.tmp
echo "signon-ui-x11" >> safe-packages.tmp
echo "signond" >> safe-packages.tmp
echo "simple-scan" >> safe-packages.tmp
echo "snapd" >> safe-packages.tmp
echo "snapd-login-service" >> safe-packages.tmp
echo "sni-qt" >> safe-packages.tmp
echo "software-properties-common" >> safe-packages.tmp
echo "software-properties-gtk" >> safe-packages.tmp
echo "sound-theme-freedesktop" >> safe-packages.tmp
echo "speech-dispatcher" >> safe-packages.tmp
echo "speech-dispatcher-audio-plugins" >> safe-packages.tmp
echo "squashfs-tools" >> safe-packages.tmp
echo "ssl-cert" >> safe-packages.tmp
echo "strace" >> safe-packages.tmp
echo "sudo" >> safe-packages.tmp
echo "suru-icon-theme" >> safe-packages.tmp
echo "syslinux" >> safe-packages.tmp
echo "syslinux-common" >> safe-packages.tmp
echo "syslinux-legacy" >> safe-packages.tmp
echo "system-config-printer-common" >> safe-packages.tmp
echo "system-config-printer-gnome" >> safe-packages.tmp
echo "system-config-printer-udev" >> safe-packages.tmp
echo "systemd" >> safe-packages.tmp
echo "systemd-sysv" >> safe-packages.tmp
echo "sysv-rc" >> safe-packages.tmp
echo "sysv-rc-conf" >> safe-packages.tmp
echo "sysvinit-utils" >> safe-packages.tmp
echo "t1utils" >> safe-packages.tmp
echo "tar" >> safe-packages.tmp
echo "tcl" >> safe-packages.tmp
echo "tcl8.6" >> safe-packages.tmp
echo "tcpd" >> safe-packages.tmp
echo "tcpdump" >> safe-packages.tmp
echo "telnet" >> safe-packages.tmp
echo "thermald" >> safe-packages.tmp
echo "thunderbird" >> safe-packages.tmp
echo "thunderbird-gnome-support" >> safe-packages.tmp
echo "thunderbird-locale-en" >> safe-packages.tmp
echo "thunderbird-locale-en-us" >> safe-packages.tmp
echo "time" >> safe-packages.tmp
echo "tk" >> safe-packages.tmp
echo "tk8.6" >> safe-packages.tmp
echo "toshset" >> safe-packages.tmp
echo "totem" >> safe-packages.tmp
echo "totem-common" >> safe-packages.tmp
echo "totem-plugins" >> safe-packages.tmp
echo "transmission-common" >> safe-packages.tmp
echo "transmission-gtk" >> safe-packages.tmp
echo "tripwire" >> safe-packages.tmp
echo "ttf-ancient-fonts-symbola" >> safe-packages.tmp
echo "ttf-ubuntu-font-family" >> safe-packages.tmp
echo "tzdata" >> safe-packages.tmp
echo "ubuntu-artwork" >> safe-packages.tmp
echo "ubuntu-desktop" >> safe-packages.tmp
echo "ubuntu-docs" >> safe-packages.tmp
echo "ubuntu-drivers-common" >> safe-packages.tmp
echo "ubuntu-keyring" >> safe-packages.tmp
echo "ubuntu-minimal" >> safe-packages.tmp
echo "ubuntu-mobile-icons" >> safe-packages.tmp
echo "ubuntu-mono" >> safe-packages.tmp
echo "ubuntu-release-upgrader-core" >> safe-packages.tmp
echo "ubuntu-release-upgrader-gtk" >> safe-packages.tmp
echo "ubuntu-session" >> safe-packages.tmp
echo "ubuntu-settings" >> safe-packages.tmp
echo "ubuntu-software" >> safe-packages.tmp
echo "ubuntu-sounds" >> safe-packages.tmp
echo "ubuntu-system-service" >> safe-packages.tmp
echo "ubuntu-touch-sounds" >> safe-packages.tmp
echo "ubuntu-ui-toolkit-theme" >> safe-packages.tmp
echo "ubuntu-wallpapers" >> safe-packages.tmp
echo "ubuntu-wallpapers-xenial" >> safe-packages.tmp
echo "ucf" >> safe-packages.tmp
echo "udev" >> safe-packages.tmp
echo "udisks2" >> safe-packages.tmp
echo "ufw" >> safe-packages.tmp
echo "unattended-upgrades" >> safe-packages.tmp
echo "unity" >> safe-packages.tmp
echo "unity-accessibility-profiles" >> safe-packages.tmp
echo "unity-asset-pool" >> safe-packages.tmp
echo "unity-control-center" >> safe-packages.tmp
echo "unity-control-center-faces" >> safe-packages.tmp
echo "unity-control-center-signon" >> safe-packages.tmp
echo "unity-greeter" >> safe-packages.tmp
echo "unity-gtk-module-common" >> safe-packages.tmp
echo "unity-gtk2-module" >> safe-packages.tmp
echo "unity-gtk3-module" >> safe-packages.tmp
echo "unity-lens-applications" >> safe-packages.tmp
echo "unity-lens-files" >> safe-packages.tmp
echo "unity-lens-music" >> safe-packages.tmp
echo "unity-lens-photos" >> safe-packages.tmp
echo "unity-lens-video" >> safe-packages.tmp
echo "unity-schemas" >> safe-packages.tmp
echo "unity-scope-calculator" >> safe-packages.tmp
echo "unity-scope-chromiumbookmarks" >> safe-packages.tmp
echo "unity-scope-colourlovers" >> safe-packages.tmp
echo "unity-scope-devhelp" >> safe-packages.tmp
echo "unity-scope-firefoxbookmarks" >> safe-packages.tmp
echo "unity-scope-gdrive" >> safe-packages.tmp
echo "unity-scope-home" >> safe-packages.tmp
echo "unity-scope-manpages" >> safe-packages.tmp
echo "unity-scope-openclipart" >> safe-packages.tmp
echo "unity-scope-texdoc" >> safe-packages.tmp
echo "unity-scope-tomboy" >> safe-packages.tmp
echo "unity-scope-video-remote" >> safe-packages.tmp
echo "unity-scope-virtualbox" >> safe-packages.tmp
echo "unity-scope-yelp" >> safe-packages.tmp
echo "unity-scope-zotero" >> safe-packages.tmp
echo "unity-scopes-master-default" >> safe-packages.tmp
echo "unity-scopes-runner" >> safe-packages.tmp
echo "unity-services" >> safe-packages.tmp
echo "unity-settings-daemon" >> safe-packages.tmp
echo "unity-webapps-common" >> safe-packages.tmp
echo "unity-webapps-qml" >> safe-packages.tmp
echo "unity-webapps-service" >> safe-packages.tmp
echo "uno-libs3" >> safe-packages.tmp
echo "unzip" >> safe-packages.tmp
echo "update-inetd" >> safe-packages.tmp
echo "update-manager" >> safe-packages.tmp
echo "update-manager-core" >> safe-packages.tmp
echo "update-notifier" >> safe-packages.tmp
echo "update-notifier-common" >> safe-packages.tmp
echo "upower" >> safe-packages.tmp
echo "upstart" >> safe-packages.tmp
echo "ure" >> safe-packages.tmp
echo "ureadahead" >> safe-packages.tmp
echo "usb-creator-common" >> safe-packages.tmp
echo "usb-creator-gtk" >> safe-packages.tmp
echo "usb-modeswitch" >> safe-packages.tmp
echo "usb-modeswitch-data" >> safe-packages.tmp
echo "usbmuxd" >> safe-packages.tmp
echo "usbutils" >> safe-packages.tmp
echo "util-linux" >> safe-packages.tmp
echo "uuid-runtime" >> safe-packages.tmp
echo "vbetool" >> safe-packages.tmp
echo "vim-common" >> safe-packages.tmp
echo "vim-tiny" >> safe-packages.tmp
echo "vino" >> safe-packages.tmp
echo "wamerican" >> safe-packages.tmp
echo "wbritish" >> safe-packages.tmp
echo "webapp-container" >> safe-packages.tmp
echo "webbrowser-app" >> safe-packages.tmp
echo "wget" >> safe-packages.tmp
echo "whiptail" >> safe-packages.tmp
echo "whoopsie" >> safe-packages.tmp
echo "whoopsie-preferences" >> safe-packages.tmp
echo "wireless-regdb" >> safe-packages.tmp
echo "wireless-tools" >> safe-packages.tmp
echo "wpasupplicant" >> safe-packages.tmp
echo "x11-apps" >> safe-packages.tmp
echo "x11-common" >> safe-packages.tmp
echo "x11-session-utils" >> safe-packages.tmp
echo "x11-utils" >> safe-packages.tmp
echo "x11-xkb-utils" >> safe-packages.tmp
echo "x11-xserver-utils" >> safe-packages.tmp
echo "xauth" >> safe-packages.tmp
echo "xbitmaps" >> safe-packages.tmp
echo "xbrlapi" >> safe-packages.tmp
echo "xcursor-themes" >> safe-packages.tmp
echo "xdg-user-dirs" >> safe-packages.tmp
echo "xdg-user-dirs-gtk" >> safe-packages.tmp
echo "xdg-utils" >> safe-packages.tmp
echo "xdiagnose" >> safe-packages.tmp
echo "xfonts-base" >> safe-packages.tmp
echo "xfonts-encodings" >> safe-packages.tmp
echo "xfonts-scalable" >> safe-packages.tmp
echo "xfonts-utils" >> safe-packages.tmp
echo "xinit" >> safe-packages.tmp
echo "xinput" >> safe-packages.tmp
echo "xkb-data" >> safe-packages.tmp
echo "xml-core" >> safe-packages.tmp
echo "xorg" >> safe-packages.tmp
echo "xorg-docs-core" >> safe-packages.tmp
echo "xserver-common" >> safe-packages.tmp
echo "xserver-xorg" >> safe-packages.tmp
echo "xserver-xorg-core" >> safe-packages.tmp
echo "xserver-xorg-input-all" >> safe-packages.tmp
echo "xserver-xorg-input-evdev" >> safe-packages.tmp
echo "xserver-xorg-input-synaptics" >> safe-packages.tmp
echo "xserver-xorg-input-vmmouse" >> safe-packages.tmp
echo "xserver-xorg-input-wacom" >> safe-packages.tmp
echo "xserver-xorg-video-all" >> safe-packages.tmp
echo "xserver-xorg-video-amdgpu" >> safe-packages.tmp
echo "xserver-xorg-video-ati" >> safe-packages.tmp
echo "xserver-xorg-video-fbdev" >> safe-packages.tmp
echo "xserver-xorg-video-intel" >> safe-packages.tmp
echo "xserver-xorg-video-nouveau" >> safe-packages.tmp
echo "xserver-xorg-video-qxl" >> safe-packages.tmp
echo "xserver-xorg-video-radeon" >> safe-packages.tmp
echo "xserver-xorg-video-vesa" >> safe-packages.tmp
echo "xserver-xorg-video-vmware" >> safe-packages.tmp
echo "xterm" >> safe-packages.tmp
echo "xul-ext-ubufox" >> safe-packages.tmp
echo "xz-utils" >> safe-packages.tmp
echo "yelp" >> safe-packages.tmp
echo "yelp-xsl" >> safe-packages.tmp
echo "zeitgeist-core" >> safe-packages.tmp
echo "zeitgeist-datahub" >> safe-packages.tmp
echo "zenity" >> safe-packages.tmp
echo "zenity-common" >> safe-packages.tmp
echo "zerofree" >> safe-packages.tmp
echo "zip" >> safe-packages.tmp
echo "zlib1g" >> safe-packages.tmp
echo "account-plugin-aim" >> safe-packages.tmp
echo "account-plugin-jabber" >> safe-packages.tmp
echo "account-plugin-salut" >> safe-packages.tmp
echo "account-plugin-twitter" >> safe-packages.tmp
echo "account-plugin-yahoo" >> safe-packages.tmp
echo "activity-log-manager-control-center" >> safe-packages.tmp
echo "apt-xapian-index" >> safe-packages.tmp
echo "bluez-alsa" >> safe-packages.tmp
echo "brasero" >> safe-packages.tmp
echo "brasero-cdrkit" >> safe-packages.tmp
echo "brasero-common" >> safe-packages.tmp
echo "checkbox-ng" >> safe-packages.tmp
echo "checkbox-ng-service" >> safe-packages.tmp
echo "cpp-4.8" >> safe-packages.tmp
echo "deja-dup-backend-gvfs" >> safe-packages.tmp
echo "dialog" >> safe-packages.tmp
echo "dmsetup" >> safe-packages.tmp
echo "duplicity" >> safe-packages.tmp
echo "dvd+rw-tools" >> safe-packages.tmp
echo "empathy" >> safe-packages.tmp
echo "empathy-common" >> safe-packages.tmp
echo "folks-common" >> safe-packages.tmp
echo "fonts-droid" >> safe-packages.tmp
echo "friends" >> safe-packages.tmp
echo "friends-dispatcher" >> safe-packages.tmp
echo "friends-facebook" >> safe-packages.tmp
echo "friends-twitter" >> safe-packages.tmp
echo "gcc-4.8" >> safe-packages.tmp
echo "gcc-4.8-base" >> safe-packages.tmp
echo "gcc-4.9-base" >> safe-packages.tmp
echo "gir1.2-ebook-1.2" >> safe-packages.tmp
echo "gir1.2-ebookcontacts-1.2" >> safe-packages.tmp
echo "gir1.2-edataserver-1.2" >> safe-packages.tmp
echo "gir1.2-gmenu-3.0" >> safe-packages.tmp
echo "gir1.2-gnomebluetooth-1.0" >> safe-packages.tmp
echo "gir1.2-javascriptcoregtk-3.0" >> safe-packages.tmp
echo "gir1.2-messagingmenu-1.0" >> safe-packages.tmp
echo "gir1.2-networkmanager-1.0" >> safe-packages.tmp
echo "gir1.2-vte-2.90" >> safe-packages.tmp
echo "gir1.2-webkit-3.0" >> safe-packages.tmp
echo "gnome-contacts" >> safe-packages.tmp
echo "gnome-control-center-shared-data" >> safe-packages.tmp
echo "gnome-icon-theme-symbolic" >> safe-packages.tmp
echo "gnomine" >> safe-packages.tmp
echo "growisofs" >> safe-packages.tmp
echo "gstreamer0.10-alsa" >> safe-packages.tmp
echo "gstreamer0.10-nice" >> safe-packages.tmp
echo "gstreamer0.10-plugins-base" >> safe-packages.tmp
echo "gstreamer0.10-plugins-base-apps" >> safe-packages.tmp
echo "gstreamer0.10-plugins-good" >> safe-packages.tmp
echo "gstreamer0.10-pulseaudio" >> safe-packages.tmp
echo "gstreamer0.10-tools" >> safe-packages.tmp
echo "gstreamer0.10-x" >> safe-packages.tmp
echo "gstreamer1.0-clutter" >> safe-packages.tmp
echo "gstreamer1.0-nice" >> safe-packages.tmp
echo "gtk3-engines-unico" >> safe-packages.tmp
echo "ibus-pinyin" >> safe-packages.tmp
echo "iproute" >> safe-packages.tmp
echo "landscape-client-ui-install" >> safe-packages.tmp
echo "libapt-inst1.5" >> safe-packages.tmp
echo "libapt-pkg4.12" >> safe-packages.tmp
echo "libarchive-extract-perl" >> safe-packages.tmp
echo "libasan0" >> safe-packages.tmp
echo "libasprintf0c2" >> safe-packages.tmp
echo "libatkmm-1.6-1" >> safe-packages.tmp
echo "libautodie-perl" >> safe-packages.tmp
echo "libavahi-gobject0" >> safe-packages.tmp
echo "libbind9-90" >> safe-packages.tmp
echo "libbit-vector-perl" >> safe-packages.tmp
echo "libboost-date-time1.54.0" >> safe-packages.tmp
echo "libboost-system1.54.0" >> safe-packages.tmp
echo "libbrasero-media3-1" >> safe-packages.tmp
echo "libburn4" >> safe-packages.tmp
echo "libcairomm-1.0-1" >> safe-packages.tmp
echo "libcamel-1.2-45" >> safe-packages.tmp
echo "libcarp-clan-perl" >> safe-packages.tmp
echo "libcdr-0.0-0" >> safe-packages.tmp
echo "libcheese-gtk23" >> safe-packages.tmp
echo "libcheese7" >> safe-packages.tmp
echo "libcloog-isl4" >> safe-packages.tmp
echo "libclucene-contribs1" >> safe-packages.tmp
echo "libclucene-core1" >> safe-packages.tmp
echo "libclutter-gst-2.0-0" >> safe-packages.tmp
echo "libcmis-0.4-4" >> safe-packages.tmp
echo "libcogl-pango15" >> safe-packages.tmp
echo "libcogl15" >> safe-packages.tmp
echo "libcolamd2.8.0" >> safe-packages.tmp
echo "libcolord1" >> safe-packages.tmp
echo "libcolorhug1" >> safe-packages.tmp
echo "libcolumbus1" >> safe-packages.tmp
echo "libcrypt-passwdmd5-perl" >> safe-packages.tmp
echo "libdate-calc-perl" >> safe-packages.tmp
echo "libdate-calc-xs-perl" >> safe-packages.tmp
echo "libdns100" >> safe-packages.tmp
echo "libebackend-1.2-7" >> safe-packages.tmp
echo "libebook-1.2-14" >> safe-packages.tmp
echo "libebook-contacts-1.2-0" >> safe-packages.tmp
echo "libecal-1.2-16" >> safe-packages.tmp
echo "libedata-book-1.2-20" >> safe-packages.tmp
echo "libedata-cal-1.2-23" >> safe-packages.tmp
echo "libedataserver-1.2-18" >> safe-packages.tmp
echo "libegl1-mesa-lts-xenial" >> safe-packages.tmp
echo "libelfg0" >> safe-packages.tmp
echo "libexiv2-12" >> safe-packages.tmp
echo "libfarstream-0.1-0" >> safe-packages.tmp
echo "libfarstream-0.2-2" >> safe-packages.tmp
echo "libfolks-eds25" >> safe-packages.tmp
echo "libfolks-telepathy25" >> safe-packages.tmp
echo "libfolks25" >> safe-packages.tmp
echo "libfreerdp1" >> safe-packages.tmp
echo "libfriends0" >> safe-packages.tmp
echo "libfs6" >> safe-packages.tmp
echo "libgbm1-lts-xenial" >> safe-packages.tmp
echo "libgcc-4.8-dev" >> safe-packages.tmp
echo "libgcrypt11" >> safe-packages.tmp
echo "libgdata13" >> safe-packages.tmp
echo "libgee2" >> safe-packages.tmp
echo "libgl1-mesa-dri-lts-xenial" >> safe-packages.tmp
echo "libgl1-mesa-glx-lts-xenial" >> safe-packages.tmp
echo "libglapi-mesa-lts-xenial" >> safe-packages.tmp
echo "libgles1-mesa-lts-xenial" >> safe-packages.tmp
echo "libgles2-mesa-lts-xenial" >> safe-packages.tmp
echo "libglew1.10" >> safe-packages.tmp
echo "libglewmx1.10" >> safe-packages.tmp
echo "libglibmm-2.4-1c2a" >> safe-packages.tmp
echo "libgnome-bluetooth11" >> safe-packages.tmp
echo "libgnome-control-center1" >> safe-packages.tmp
echo "libgnome-desktop-3-7" >> safe-packages.tmp
echo "libgnutls26" >> safe-packages.tmp
echo "libgphoto2-port10" >> safe-packages.tmp
echo "libgrip0" >> safe-packages.tmp
echo "libgssdp-1.0-3" >> safe-packages.tmp
echo "libgstreamer-plugins-base0.10-0" >> safe-packages.tmp
echo "libgstreamer0.10-0" >> safe-packages.tmp
echo "libgtkmm-2.4-1c2a" >> safe-packages.tmp
echo "libgtkmm-3.0-1" >> safe-packages.tmp
echo "libgtop2-7" >> safe-packages.tmp
echo "libgupnp-1.0-4" >> safe-packages.tmp
echo "libgupnp-igd-1.0-4" >> safe-packages.tmp
echo "libical1" >> safe-packages.tmp
echo "libicu52" >> safe-packages.tmp
echo "libimobiledevice4" >> safe-packages.tmp
echo "libisc95" >> safe-packages.tmp
echo "libisccc90" >> safe-packages.tmp
echo "libisccfg90" >> safe-packages.tmp
echo "libisl10" >> safe-packages.tmp
echo "libisofs6" >> safe-packages.tmp
echo "libjavascriptcoregtk-3.0-0" >> safe-packages.tmp
echo "libjson0" >> safe-packages.tmp
echo "libjte1" >> safe-packages.tmp
echo "libllvm3.8v4" >> safe-packages.tmp
echo "liblockfile-bin" >> safe-packages.tmp
echo "liblockfile1" >> safe-packages.tmp
echo "liblog-message-simple-perl" >> safe-packages.tmp
echo "liblouis2" >> safe-packages.tmp
echo "liblwres90" >> safe-packages.tmp
echo "libmbim-glib0" >> safe-packages.tmp
echo "libmeanwhile1" >> safe-packages.tmp
echo "libmetacity-private0a" >> safe-packages.tmp
echo "libminiupnpc8" >> safe-packages.tmp
echo "libmission-control-plugins0" >> safe-packages.tmp
echo "libmodule-pluggable-perl" >> safe-packages.tmp
echo "libmspub-0.0-0" >> safe-packages.tmp
echo "libnettle4" >> safe-packages.tmp
echo "libnice10" >> safe-packages.tmp
echo "libnl-route-3-200" >> safe-packages.tmp
echo "libopencc1" >> safe-packages.tmp
echo "libopenobex1" >> safe-packages.tmp
echo "liborcus-0.6-0" >> safe-packages.tmp
echo "libpam-cap" >> safe-packages.tmp
echo "libpango1.0-0" >> safe-packages.tmp
echo "libpangomm-1.4-1" >> safe-packages.tmp
echo "libpangox-1.0-0" >> safe-packages.tmp
echo "libparted0debian1" >> safe-packages.tmp
echo "libperl5.18" >> safe-packages.tmp
echo "libplist1" >> safe-packages.tmp
echo "libplymouth2" >> safe-packages.tmp
echo "libpocketsphinx1" >> safe-packages.tmp
echo "libpod-latex-perl" >> safe-packages.tmp
echo "libpoppler44" >> safe-packages.tmp
echo "libprocps3" >> safe-packages.tmp
echo "libprotobuf8" >> safe-packages.tmp
echo "libproxy1" >> safe-packages.tmp
echo "libpurple-bin" >> safe-packages.tmp
echo "libpurple0" >> safe-packages.tmp
echo "libpython3.4" >> safe-packages.tmp
echo "libpython3.4-minimal" >> safe-packages.tmp
echo "libpython3.4-stdlib" >> safe-packages.tmp
echo "libpyzy-1.0-0" >> safe-packages.tmp
echo "libqmi-glib0" >> safe-packages.tmp
echo "libqpdf13" >> safe-packages.tmp
echo "libqt4-designer" >> safe-packages.tmp
echo "libqt4-help" >> safe-packages.tmp
echo "libqt4-opengl" >> safe-packages.tmp
echo "libqt4-scripttools" >> safe-packages.tmp
echo "libqt4-svg" >> safe-packages.tmp
echo "libqt4-test" >> safe-packages.tmp
echo "libqt5qml-graphicaleffects" >> safe-packages.tmp
echo "libqt5sensors5" >> safe-packages.tmp
echo "libqt5webkit5-qmlwebkitplugin" >> safe-packages.tmp
echo "libqtassistantclient4" >> safe-packages.tmp
echo "libqtwebkit4" >> safe-packages.tmp
echo "libraw9" >> safe-packages.tmp
echo "libreadline5" >> safe-packages.tmp
echo "libreoffice-presentation-minimizer" >> safe-packages.tmp
echo "libreoffice-style-human" >> safe-packages.tmp
echo "librhythmbox-core8" >> safe-packages.tmp
echo "librsync1" >> safe-packages.tmp
echo "librtmp0" >> safe-packages.tmp
echo "libsigc++-2.0-0c2a" >> safe-packages.tmp
echo "libsphinxbase1" >> safe-packages.tmp
echo "libsub-identify-perl" >> safe-packages.tmp
echo "libsystemd-daemon0" >> safe-packages.tmp
echo "libsystemd-journal0" >> safe-packages.tmp
echo "libsystemd-login0" >> safe-packages.tmp
echo "libt1-5" >> safe-packages.tmp
echo "libtag1-vanilla" >> safe-packages.tmp
echo "libtag1c2a" >> safe-packages.tmp
echo "libtelepathy-farstream3" >> safe-packages.tmp
echo "libtelepathy-logger3" >> safe-packages.tmp
echo "libterm-ui-perl" >> safe-packages.tmp
echo "libtext-soundex-perl" >> safe-packages.tmp
echo "libthumbnailer0" >> safe-packages.tmp
echo "libufe-xidgetter0" >> safe-packages.tmp
echo "libunityvoice1" >> safe-packages.tmp
echo "libupower-glib1" >> safe-packages.tmp
echo "libusbmuxd2" >> safe-packages.tmp
echo "libvisio-0.0-0" >> safe-packages.tmp
echo "libvisual-0.4-plugins" >> safe-packages.tmp
echo "libvncserver0" >> safe-packages.tmp
echo "libvpx1" >> safe-packages.tmp
echo "libvte-2.90-9" >> safe-packages.tmp
echo "libvte-2.90-common" >> safe-packages.tmp
echo "libwayland-egl1-mesa-lts-xenial" >> safe-packages.tmp
echo "libwebkitgtk-3.0-0" >> safe-packages.tmp
echo "libwebkitgtk-3.0-common" >> safe-packages.tmp
echo "libwnck-common" >> safe-packages.tmp
echo "libwnck22" >> safe-packages.tmp
echo "libwpd-0.9-9" >> safe-packages.tmp
echo "libwpg-0.2-2" >> safe-packages.tmp
echo "libwps-0.2-2" >> safe-packages.tmp
echo "libxapian22" >> safe-packages.tmp
echo "libxatracker2-lts-xenial" >> safe-packages.tmp
echo "libxcb-util0" >> safe-packages.tmp
echo "libxp6" >> safe-packages.tmp
echo "libxtables10" >> safe-packages.tmp
echo "libzephyr4" >> safe-packages.tmp
echo "linux-generic-lts-xenial" >> safe-packages.tmp
echo "linux-headers-4.4.0-109" >> safe-packages.tmp
echo "linux-headers-4.4.0-109-generic" >> safe-packages.tmp
echo "linux-headers-4.4.0-53" >> safe-packages.tmp
echo "linux-headers-4.4.0-53-generic" >> safe-packages.tmp
echo "linux-headers-4.4.0-59" >> safe-packages.tmp
echo "linux-headers-4.4.0-59-generic" >> safe-packages.tmp
echo "linux-headers-generic-lts-xenial" >> safe-packages.tmp
echo "linux-image-4.4.0-109-generic" >> safe-packages.tmp
echo "linux-image-4.4.0-53-generic" >> safe-packages.tmp
echo "linux-image-4.4.0-59-generic" >> safe-packages.tmp
echo "linux-image-extra-4.4.0-109-generic" >> safe-packages.tmp
echo "linux-image-extra-4.4.0-53-generic" >> safe-packages.tmp
echo "linux-image-extra-4.4.0-59-generic" >> safe-packages.tmp
echo "linux-image-generic-lts-xenial" >> safe-packages.tmp
echo "lockfile-progs" >> safe-packages.tmp
echo "mcp-account-manager-uoa" >> safe-packages.tmp
echo "module-init-tools" >> safe-packages.tmp
echo "myspell-en-au" >> safe-packages.tmp
echo "myspell-en-gb" >> safe-packages.tmp
echo "myspell-en-za" >> safe-packages.tmp
echo "nautilus-sendto-empathy" >> safe-packages.tmp
echo "ntpdate" >> safe-packages.tmp
echo "obex-data-server" >> safe-packages.tmp
echo "obexd-client" >> safe-packages.tmp
echo "oneconf" >> safe-packages.tmp
echo "oneconf-common" >> safe-packages.tmp
echo "overlay-scrollbar-gtk3" >> safe-packages.tmp
echo "perl-modules" >> safe-packages.tmp
echo "python-apt" >> safe-packages.tmp
echo "python-aptdaemon" >> safe-packages.tmp
echo "python-aptdaemon.gtk3widgets" >> safe-packages.tmp
echo "python-cairo" >> safe-packages.tmp
echo "python-chardet" >> safe-packages.tmp
echo "python-commandnotfound" >> safe-packages.tmp
echo "python-crypto" >> safe-packages.tmp
echo "python-cups" >> safe-packages.tmp
echo "python-cupshelpers" >> safe-packages.tmp
echo "python-dbus" >> safe-packages.tmp
echo "python-dbus-dev" >> safe-packages.tmp
echo "python-debian" >> safe-packages.tmp
echo "python-debtagshw" >> safe-packages.tmp
echo "python-defer" >> safe-packages.tmp
echo "python-dirspec" >> safe-packages.tmp
echo "python-gconf" >> safe-packages.tmp
echo "python-gdbm" >> safe-packages.tmp
echo "python-gi" >> safe-packages.tmp
echo "python-gi-cairo" >> safe-packages.tmp
echo "python-gnomekeyring" >> safe-packages.tmp
echo "python-gobject" >> safe-packages.tmp
echo "python-gobject-2" >> safe-packages.tmp
echo "python-gtk2" >> safe-packages.tmp
echo "python-httplib2" >> safe-packages.tmp
echo "python-ibus" >> safe-packages.tmp
echo "python-imaging" >> safe-packages.tmp
echo "python-ldb" >> safe-packages.tmp
echo "python-libxml2" >> safe-packages.tmp
echo "python-lockfile" >> safe-packages.tmp
echo "python-lxml" >> safe-packages.tmp
echo "python-notify" >> safe-packages.tmp
echo "python-oauthlib" >> safe-packages.tmp
echo "python-oneconf" >> safe-packages.tmp
echo "python-openssl" >> safe-packages.tmp
echo "python-pam" >> safe-packages.tmp
echo "python-pexpect" >> safe-packages.tmp
echo "python-pil" >> safe-packages.tmp
echo "python-piston-mini-client" >> safe-packages.tmp
echo "python-pkg-resources" >> safe-packages.tmp
echo "python-qt4" >> safe-packages.tmp
echo "python-qt4-dbus" >> safe-packages.tmp
echo "python-renderpm" >> safe-packages.tmp
echo "python-reportlab" >> safe-packages.tmp
echo "python-reportlab-accel" >> safe-packages.tmp
echo "python-requests" >> safe-packages.tmp
echo "python-samba" >> safe-packages.tmp
echo "python-serial" >> safe-packages.tmp
echo "python-sip" >> safe-packages.tmp
echo "python-six" >> safe-packages.tmp
echo "python-smbc" >> safe-packages.tmp
echo "python-tdb" >> safe-packages.tmp
echo "python-twisted-bin" >> safe-packages.tmp
echo "python-twisted-core" >> safe-packages.tmp
echo "python-twisted-web" >> safe-packages.tmp
echo "python-ubuntu-sso-client" >> safe-packages.tmp
echo "python-urllib3" >> safe-packages.tmp
echo "python-xapian" >> safe-packages.tmp
echo "python-xdg" >> safe-packages.tmp
echo "python-zeitgeist" >> safe-packages.tmp
echo "python-zope.interface" >> safe-packages.tmp
echo "python3-checkbox-ng" >> safe-packages.tmp
echo "python3-crypto" >> safe-packages.tmp
echo "python3-oneconf" >> safe-packages.tmp
echo "python3-piston-mini-client" >> safe-packages.tmp
echo "python3.4" >> safe-packages.tmp
echo "python3.4-minimal" >> safe-packages.tmp
echo "qtdeclarative5-dialogs-plugin" >> safe-packages.tmp
echo "qtdeclarative5-localstorage-plugin" >> safe-packages.tmp
echo "qtdeclarative5-privatewidgets-plugin" >> safe-packages.tmp
echo "qtdeclarative5-qtfeedback-plugin" >> safe-packages.tmp
echo "qtdeclarative5-ubuntu-ui-extras-browser-plugin" >> safe-packages.tmp
echo "qtdeclarative5-ubuntu-ui-extras-browser-plugin-assets" >> safe-packages.tmp
echo "qtdeclarative5-window-plugin" >> safe-packages.tmp
echo "rhythmbox-mozilla" >> safe-packages.tmp
echo "rhythmbox-plugin-cdrecorder" >> safe-packages.tmp
echo "rhythmbox-plugin-magnatune" >> safe-packages.tmp
echo "samba-common" >> safe-packages.tmp
echo "samba-common-bin" >> safe-packages.tmp
echo "smbclient" >> safe-packages.tmp
echo "software-center" >> safe-packages.tmp
echo "software-center-aptdaemon-plugins" >> safe-packages.tmp
echo "sphinx-voxforge-hmm-en" >> safe-packages.tmp
echo "sphinx-voxforge-lm-en" >> safe-packages.tmp
echo "ssh-askpass-gnome" >> safe-packages.tmp
echo "systemd-services" >> safe-packages.tmp
echo "systemd-shim" >> safe-packages.tmp
echo "telepathy-gabble" >> safe-packages.tmp
echo "telepathy-haze" >> safe-packages.tmp
echo "telepathy-idle" >> safe-packages.tmp
echo "telepathy-indicator" >> safe-packages.tmp
echo "telepathy-logger" >> safe-packages.tmp
echo "telepathy-mission-control-5" >> safe-packages.tmp
echo "telepathy-salut" >> safe-packages.tmp
echo "totem-mozilla" >> safe-packages.tmp
echo "ttf-indic-fonts-core" >> safe-packages.tmp
echo "ttf-punjabi-fonts" >> safe-packages.tmp
echo "ubuntu-extras-keyring" >> safe-packages.tmp
echo "ubuntu-sso-client" >> safe-packages.tmp
echo "ubuntu-sso-client-qt" >> safe-packages.tmp
echo "ubuntu-wallpapers-trusty" >> safe-packages.tmp
echo "ubuntuone-client-data" >> safe-packages.tmp
echo "unity-lens-friends" >> safe-packages.tmp
echo "unity-scope-audacious" >> safe-packages.tmp
echo "unity-scope-clementine" >> safe-packages.tmp
echo "unity-scope-gmusicbrowser" >> safe-packages.tmp
echo "unity-scope-gourmet" >> safe-packages.tmp
echo "unity-scope-guayadeque" >> safe-packages.tmp
echo "unity-scope-musicstores" >> safe-packages.tmp
echo "unity-scope-musique" >> safe-packages.tmp
echo "unity-voice-service" >> safe-packages.tmp
echo "webaccounts-extension-common" >> safe-packages.tmp
echo "wodim" >> safe-packages.tmp
echo "x11-xfs-utils" >> safe-packages.tmp
echo "xfonts-mathml" >> safe-packages.tmp
echo "xserver-xorg-core-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-input-all-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-input-evdev-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-input-synaptics-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-input-vmmouse-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-input-wacom-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-all-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-amdgpu-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-ati-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-cirrus-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-fbdev-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-intel-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-mach64-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-mga-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-neomagic-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-nouveau-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-openchrome-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-qxl-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-r128-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-radeon-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-savage-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-siliconmotion-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-sisusb-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-tdfx-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-trident-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-vesa-lts-xenial" >> safe-packages.tmp
echo "xserver-xorg-video-vmware-lts-xenial" >> safe-packages.tmp
echo "xul-ext-unity" >> safe-packages.tmp
echo "xul-ext-webaccounts" >> safe-packages.tmp
echo "xul-ext-websites-integration" >> safe-packages.tmp
echo "zeitgeist" >> safe-packages.tmp
echo "ubuntu-standard" >> safe-packages.tmp
echo "gufw" >> safe-packages.tmp
echo "libqmi-glib5" >> safe-packages.tmp
echo "python-netifaces" >> safe-packages.tmp




echo "Press enter to begin editing installed packages..."
read continue
for pkg in `sudo apt list --installed | cut -d '/' -f 1`; do
  if [ "$pkg" != "" ]; then
    safe="false"
    for entry in `cat safe-packages.tmp`; do
      if [ "$pkg" == "$entry"  ]; then
        safe="true"
        break
      fi
    done
    if [ "$safe" == "false" ]; then
      sudo echo "Is $pkg a valid package? (y/n): "
      read valid
      if [ "$valid" != "n" ]; then
        echo "Insuring $pkg is updated and dependancies are installed..."
        sudo apt-get install -y $pkg
      else
        echo "Uninstalling $pkg..."
        sudo apt-get purge -y $pkg
      fi
    fi
  fi
done


# Secure Root
echo "Securing root account..."
sudo dpkg-statoverride --update --add root sudo 4750 /bin/su
sudo cp /etc/securetty /etc/securetty.old
sudo truncate -s 0 /etc/securetty

#Dissable root and guest account login
sudo passwd -l root
sudo passwd -l guest

#LightDM configuration Block (For Ubuntu)
#sudo cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.old
#sudo cp /etc/lightdm/users.conf /etc/lightdm/users.old
echo "Configuring LightDM..."
#Dissable Auto-login
sudo echo "[SeatDefaults]" | sudo tee /etc/lightdm/lightdm.tmp
sudo echo "autlogin-guest=false" | sudo tee -a /etc/lightdm/lightdm.tmp
sudo echo "autologin-user-timeout=0" | sudo tee -a /etc/lightdm/lightdm.tmp
sudo echo "autologin-user=" | sudo tee -a /etc/lightdm/lightdm.tmp
sudo echo "autologin-session=lightdm-autologin" | sudo tee -a /etc/lightdm/lightdm.tmp
#Secure Lightdm in general
sudo echo "greeter-hide-users=true" | sudo tee -a /etc/lightdm/lightdm.tmp
sudo echo "greeter-show-manual-login=true" | sudo tee -a /etc/lightdm/lightdm.tmp
#Dissable Guest account
sudo echo "allow-guest=false" | sudo tee -a /etc/lightdm/lightdm.tmp
#Unhide users
sudo echo "[UserList]" | sudo tee /etc/lightdm/users.tmp
sudo echo "minimum-uid=500" | sudo tee -a /etc/lightdm/users.tmp
sudo echo "hidden-users=" | sudo tee -a /etc/lightdm/users.tmp
sudo echo "hidden-shells=/bin/false /usr/sbin/nologin" | sudo tee -a /etc/lightdm/users.tmp
sudo mv -f /etc/lightdm/lightdm.tmp /etc/lightdm/lightdm.conf
sudo mv -f /etc/lightdm/users.tmp /etc/lightdm/users.conf

#GDM configureatoin Block (For Debian)
sudo cp /etc/gdm3/daemon.conf /etc/gdm3/daemon.old
sudo echo "[daemon]" | sudo tee /etc/gdm3/daemon.tmp
sudo echo "AutomaticLoginEnable=false" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "AutomaticLogin=" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "TimedLoginEnable=false" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "TimedLogin=" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "TimedLoginDelay=10" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo " [security]" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "[xdmcp]" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo " [greeter]" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "IncludeAll=true" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "[chooser]" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "[debug]" | sudo tee -a /etc/gdm3/daemon.tmp
sudo echo "Enable=true" | sudo tee -a /etc/gdm3/daemon.tmp
sudo cp -f /etc/gdm3/daemon.tmp /etc/gdm3/daemon


#Clear Hosts file
echo "Clearing hosts file..."
sudo echo 127.0.0.1	localhost | sudo tee /etc/hosts
sudo echo 127.0.1.1	$hostname  | sudo tee -a /etc/hosts
if [ "$ipv6_allowed" == "y" ]; then
  sudo echo ::1     ip6-localhost ip6-loopback | sudo tee -a /etc/hosts
  sudo echo fe00::0 ip6-localnet | sudo tee -a /etc/hosts
  sudo echo ff00::0 ip6-mcastprefix | sudo tee -a /etc/hosts
  sudo echo ff02::1 ip6-allnodes | sudo tee -a /etc/hosts
  sudo echo ff02::2 ip6-allrouters | sudo tee -a /etc/hosts
else
  #Dissable IPv6 if not needed
  sudo sed -i -e 's/alias net-pf-10 ipv6/alias net-pf-10 off /g' /etc/modprobe.d/aliases
  sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
fi


#Prevent IP Spoofing
sudo sudo echo "order bind, hosts" | sudo tee -a /etc/host.conf
sudo sudo echo "nospoof on" | sudo tee -a /etc/host.conf


#Configure /etc/login.defs
sudo cp /etc/login.defs /etc/login.old
sudo echo "MAIL_DIR            /var/mail" | sudo tee /etc/login.tmp
sudo echo "FAILLOG_ENAB        yes" | sudo tee -a /etc/login.tmp
sudo echo "LOG_UNKFAIL_ENAB    yes" | sudo tee -a /etc/login.tmp
sudo echo "LOG_OK_LOGINS       yes" | sudo tee -a /etc/login.tmp
sudo echo "SYSLOG_SU_ENAB      yes" | sudo tee -a /etc/login.tmp
sudo echo "SYSLOG_SG_ENAB      yes" | sudo tee -a /etc/login.tmp
sudo echo "SULOG_FILE          /var/log/sulog" | sudo tee -a /etc/login.tmp
sudo echo "FTMP_FILE           /var/log/btmp" | sudo tee -a /etc/login.tmp
sudo echo "HUSHLOGIN_FILE      /etc/hushlogins" | sudo tee -a /etc/login.tmp
sudo echo "ENV_SUPATH          PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" | sudo tee -a /etc/login.tmp
sudo echo "ENV_PATH            PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games" | sudo tee -a /etc/login.tmp
sudo echo "TTYGROUP            tty" | sudo tee -a /etc/login.tmp
sudo echo "TTYPERM             0600" | sudo tee -a /etc/login.tmp
sudo echo "ERASECHAR           0177" | sudo tee -a /etc/login.tmp
sudo echo "KILLCHAR            025" | sudo tee -a /etc/login.tmp
sudo echo "UMASK               077" | sudo tee -a /etc/login.tmp
sudo echo "PASS_MAX_DAYS       30" | sudo tee -a /etc/login.tmp
sudo echo "PASS_MIN_DAYS       10" | sudo tee -a /etc/login.tmp
sudo echo "PASS_WARN_AGE       14" | sudo tee -a /etc/login.tmp
sudo echo "UID_MIN             1000" | sudo tee -a /etc/login.tmp
sudo echo "UID_MAX             60000" | sudo tee -a /etc/login.tmp
sudo echo "SYS_UID_MIN         100" | sudo tee -a /etc/login.tmp
sudo echo "SYS_UID_MAX         999" | sudo tee -a /etc/login.tmp
sudo echo "GID_MIN             1000" | sudo tee -a /etc/login.tmp
sudo echo "GID_MAX             60000" | sudo tee -a /etc/login.tmp
sudo echo "SYS_GID_MIN         100" | sudo tee -a /etc/login.tmp
sudo echo "SYS_GID_MAX         999" | sudo tee -a /etc/login.tmp
sudo echo "LOGIN_RETRIES       6" | sudo tee -a /etc/login.tmp
sudo echo "LOGIN_TIMEOUT       30" | sudo tee -a /etc/login.tmp
sudo echo "CHFN_RESTRICT       rwh" | sudo tee -a /etc/login.tmp
sudo echo "DEFAULT_HOME        no" | sudo tee -a /etc/login.tmp
sudo echo "USERDEL_CMD         /usr/sbin/userdel_local" | sudo tee -a /etc/login.tmp
sudo echo "USERGROUPS_ENAB     yes" | sudo tee -a /etc/login.tmp
sudo echo "ENCRYPT_METHOD      SHA512" | sudo tee -a /etc/login.tmp
sudo echo "SHA_CRYPT_MIN_ROUNDS  10000" | sudo tee -a /etc/login.tmp
sudo echo "SHA_CRYPT_MAX_ROUNDS  50000" | sudo tee -a /etc/login.tmp
sudo cp -f /etc/login.tmp /etc/login.defs



##*********PAM Security Block*************

#accountsservice
#sudo cp /etc/pam.d/accountsservice /etc/pam.d/accountsservice.old
sudo echo "password  substack  common-password" | sudo tee /etc/pam.d/accountsservice.tmp
sudo echo "password  required pam_pin.so" | sudo tee -a /etc/pam.d/accountsservice.tmp
sudo mv -f /etc/pam.d/accountsservice.tmp /etc/pam.d/accountsservice

#chfn
#sudo cp /etc/pam.d/chfn /etc/pam.d/chfn.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/chfn.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/chfn.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/chfn.tmp
sudo mv -f /etc/pam.d/chfn.tmp /etc/pam.d/chfn

#chpasswd
#sudo cp /etc/pam.d/chpasswd /etc/pam.d/chpasswd.old
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/chpasswd.tmp
sudo mv -f /etc/pam.d/chpasswd.tmp /etc/pam.d/chpasswd

#chsh
#sudo cp /etc/pam.d/chsh /etc/pam.d/chsh.old
sudo echo "auth       required   pam_shells.so" | sudo tee /etc/pam.d/chsh.tmp
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/chsh.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/chsh.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/chsh.tmp
sudo mv -f /etc/pam.d/chsh.tmp /etc/pam.d/chsh

#common-account
#sudo cp /etc/pam.d/common-account /etc/pam.d/common-account.old
sudo echo "account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so" | sudo tee /etc/pam.d/common-account.tmp
sudo echo "account	requisite			pam_deny.so" | sudo tee -a /etc/pam.d/common-account.tmp
sudo echo "account	required			pam_permit.so" | sudo tee -a /etc/pam.d/common-account.tmp
sudo mv -f /etc/pam.d/common-account.tmp /etc/pam.d/common-account

#common-auth
#sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.old
sudo echo "auth required pam_tally2.so deny=6 onerr=fail unlock_time=1800 audit even_deny_root_account silent" | sudo tee /etc/pam.d/common-auth.tmp
sudo echo "auth  [success=1 default=ignore]	pam_unix.so nullok_secure" | sudo tee -a /etc/pam.d/common-auth.tmp
sudo echo "auth	requisite			pam_deny.so" | sudo tee -a /etc/pam.d/common-auth.tmp
sudo echo "auth	required			pam_permit.so" | sudo tee -a /etc/pam.d/common-auth.tmp
sudo echo "auth	optional			pam_cap.so" | sudo tee -a /etc/pam.d/common-auth.tmp
sudo mv -f /etc/pam.d/common-auth.tmp /etc/pam.d/common-auth

#common-password  -  Set maximum user password age and complexity requirements
#sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.old
sudo echo "password  requisite     pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1" | sudo tee /etc/pam.d/common-password.tmp
sudo echo "password  requisite     pam_pwhistory.so  use_authtok remember=5 enforce_for_root" | sudo tee -a /etc/pam.d/common-password.tmp
sudo echo "password	[success=1 default=ignore]     pam_unix.so obscure use_authtok sha512 shadow" | sudo tee -a /etc/pam.d/common-password.tmp
sudo echo "password	requisite			pam_deny.so" | sudo tee -a /etc/pam.d/common-password.tmp
sudo echo "password	required			pam_permit.so" | sudo tee -a /etc/pam.d/common-password.tmp
sudo echo "password	optional	    pam_gnome_keyring.so" | sudo tee -a /etc/pam.d/common-password.tmp
sudo mv -f /etc/pam.d/common-password.tmp /etc/pam.d/common-password

#common-session
#sudo cp /etc/pam.d/common-session /etc/pam.d/common-session.old
sudo echo "session	[default=1]			pam_permit.so" | sudo tee /etc/pam.d/common-session.tmp
sudo echo "session	requisite			pam_deny.so" | sudo tee -a /etc/pam.d/common-session.tmp
sudo echo "session	required			pam_permit.so" | sudo tee -a /etc/pam.d/common-session.tmp
sudo echo "session	required	pam_unix.so" | sudo tee -a /etc/pam.d/common-session.tmp
sudo echo "session	optional	pam_systemd.so" | sudo tee -a /etc/pam.d/common-session.tmp
sudo echo "session optional pam_umask.so" | sudo tee -a /etc/pam.d/common-session.tmp
sudo mv -f /etc/pam.d/common-session.tmp /etc/pam.d/common-session

#common-session-noninteractive
#sudo cp /etc/pam.d/common-session-noninteractive /etc/pam.d/common-session-noninteractive.old
sudo echo "session	[default=1]			pam_permit.so" | sudo tee /etc/pam.d/common-session-noninteractive.tmp
sudo echo "session	requisite			pam_deny.so" | sudo tee -a /etc/pam.d/common-session-noninteractive.tmp
sudo echo "session	required			pam_permit.so" | sudo tee -a /etc/pam.d/common-session-noninteractive.tmp
sudo echo "session	required	pam_unix.so" | sudo tee -a /etc/pam.d/common-session-noninteractive.tmp
sudo mv -f /etc/pam.d/common-session-noninteractive.tmp /etc/pam.d/common-session-noninteractive

#cron
#sudo cp /etc/pam.d/cron /etc/pam.d/cron.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/cron.tmp
sudo echo "session required     pam_loginuid.so" | sudo tee -a /etc/pam.d/cron.tmp
sudo echo "session required   pam_env.so" | sudo tee -a /etc/pam.d/cron.tmp
sudo echo "session required   pam_env.so envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/cron.tmp
sudo echo "@include common-session-noninteractive " | sudo tee -a /etc/pam.d/cron.tmp
sudo echo "session required   pam_limits.so" | sudo tee -a /etc/pam.d/cron.tmp
sudo mv -f /etc/pam.d/cron.tmp /etc/pam.d/cron

#cups-dameon
#sudo cp /etc/pam.d/cups-dameon /etc/pam.d/cups-dameon.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/cups-dameon.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/cups-dameon.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/cups-dameon.tmp
sudo mv -f /etc/pam.d/cups-dameon.tmp /etc/pam.d/cups-dameon

#gnome-screensaver
#sudo cp /etc/pam.d/gnome-screensaver /etc/pam.d/gnome-screensaver.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/gnome-screensaver.tmp
sudo echo "auth  required pam_gnome_keyring.so" | sudo tee -a /etc/pam.d/gnome-screensaver.tmp
sudo mv -f /etc/pam.d/gnome-screensaver.tmp /etc/pam.d/gnome-screensaver

#lightdm
#sudo cp /etc/pam.d/lightdm /etc/pam.d/lightdm.old
sudo echo "auth    requisite       pam_nologin.so" | sudo tee /etc/pam.d/lightdm.tmp
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "auth    optional        pam_gnome_keyring.so" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "auth    optional        pam_kwallet.so" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session required        pam_limits.so" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session optional        pam_gnome_keyring.so auto_start" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session optional        pam_kwallet.so auto_start" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session required        pam_env.so readenv=1" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "session required        pam_env.so readenv=1 user_readenv=1 envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo echo "@include common-password" | sudo tee -a /etc/pam.d/lightdm.tmp
sudo mv -f /etc/pam.d/lightdm.tmp /etc/pam.d/lightdm

#lightdm-autologin
#sudo cp /etc/pam.d/lightdm-autologin /etc/pam.d/lightdm-autologin.old
sudo echo "auth    requisite       pam_nologin.so" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "auth    required        pam_permit.so" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "session required        pam_limits.so" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "session required        pam_env.so readenv=1" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "session required        pam_env.so readenv=1 user_readenv=1 envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo echo "@include common-password" | sudo tee -a /etc/pam.d/lightdm-autologin.tmp
sudo mv -f /etc/pam.d/lightdm-autologin.tmp /etc/pam.d/lightdm-autologin

#lightdm-greeter
#sudo cp /etc/pam.d/lightdm-greeter /etc/pam.d/lightdm-greeter.old
sudo echo "auth    required        pam_permit.so" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "auth    optional        pam_gnome_keyring.so" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "auth    optional        pam_kwallet.so" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session required        pam_limits.so" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session optional        pam_gnome_keyring.so auto_start" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session optional        pam_kwallet.so auto_start" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session required        pam_env.so readenv=1" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo echo "session required        pam_env.so readenv=1 user_readenv=1 envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/lightdm-greeter.tmp
sudo mv -f /etc/pam.d/lightdm-greeter.tmp /etc/pam.d/lightdm-greeter

#login
#sudo cp /etc/pam.d/login /etc/pam.d/login.old
sudo echo "auth       optional   pam_faildelay.so  delay=3000000" | sudo tee /etc/pam.d/login.tmp
sudo echo "auth [success=ok new_authtok_reqd=ok ignore=ignore user_unknown=bad default=die] pam_securetty.so" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "auth       requisite  pam_nologin.so" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session   required   pam_env.so readenv=1" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session   equired   pam_env.so readenv=1 envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "auth       optional   pam_group.so" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session    required   pam_limits.so" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session    optional   pam_lastlog.so" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session    optional   pam_motd.so  motd=/run/motd.dynamic noupdate" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session    optional   pam_motd.so" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session    optional   pam_mail.so standard" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "@include common-password" | sudo tee -a /etc/pam.d/login.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open" | sudo tee -a /etc/pam.d/login.tmp
sudo mv -f /etc/pam.d/login.tmp /etc/pam.d/login


#newusers
#sudo cp /etc/pam.d/newusers /etc/pam.d/newusers.old
sudo echo "@include common-password" | sudo tee /etc/pam.d/newusers.tmp
sudo mv -f /etc/pam.d/newusers.tmp /etc/pam.d/newusers

#other
#sudo cp /etc/pam.d/other /etc/pam.d/other.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/other.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/other.tmp
sudo echo "@include common-password" | sudo tee -a /etc/pam.d/other.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/other.tmp
sudo mv -f /etc/pam.d/other.tmp /etc/pam.d/other

#passwd
#sudo cp /etc/pam.d/passwd /etc/pam.d/passwd.old
sudo echo "@include common-password" | sudo tee /etc/pam.d/other.tmp
sudo mv -f /etc/pam.d/other.tmp /etc/pam.d/other

#polkit-1
#sudo cp /etc/pam.d/polkit-1 /etc/pam.d/polkit-1.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/polkit-1
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/polkit-1
sudo echo "@include common-password" | sudo tee -a /etc/pam.d/polkit-1
sudo echo "session       required   pam_env.so readenv=1 user_readenv=0" | sudo tee -a /etc/pam.d/polkit-1
sudo echo "session       required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0" | sudo tee -a /etc/pam.d/polkit-1
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/polkit-1
sudo mv -f /etc/pam.d/polkit-1.tmp /etc/pam.d/polkit-1

#ppp
#sudo cp /etc/pam.d/ppp /etc/pam.d/ppp.old
sudo echo "auth	required	pam_nologin.so" | sudo tee /etc/pam.d/ppp.tmp
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/ppp.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/ppp.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/ppp.tmp
sudo mv -f /etc/pam.d/ppp.tmp /etc/pam.d/ppp

#samba
#sudo cp /etc/pam.d/samba /etc/pam.d/samba.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/samba.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/samba.tmp
sudo echo "@include common-session-noninteractive" | sudo tee -a /etc/pam.d/samba.tmp
sudo mv -f /etc/pam.d/samba.tmp /etc/pam.d/samba

#sshd
#sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.old
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/sshd.temp
sudo echo "account    required     pam_nologin.so" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/sshd.temp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close" | sudo tee -a /etc/pam.d/sshd.temp
sudo echo "session    required     pam_loginuid.so" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "session    optional     pam_keyinit.so force revoke" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/sshd.temp
sudo echo "session    optional     pam_motd.so  motd=/run/motd.dynamic noupdate" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "session    optional     pam_motd.so " | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "session    optional     pam_mail.so standard noenv " | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "session    required     pam_limits.so" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "session    required     pam_env.so session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open" | sudo tee -a /etc/pam.d/sshd.tmp
sudo echo "@include common-password" | sudo tee -a /etc/pam.d/sshd.tmp
sudo mv -f /etc/pam.d/sshd.tmp /etc/pam.d/sshd

#su
#sudo cp /etc/pam.d/su /etc/pam.d/su.old
sudo echo "auth       sufficient pam_rootok.so" | sudo tee -a /etc/pam.d/su.tmp
sudo echo "session       required   pam_env.so readenv=1" | sudo tee -a /etc/pam.d/su.tmp
sudo echo "session       required   pam_env.so readenv=1 envfile=/etc/default/locale" | sudo tee -a /etc/pam.d/su.tmp
sudo echo "session    optional   pam_mail.so nopen" | sudo tee -a /etc/pam.d/su.tmp
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/su.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/su.tmp
sudo echo "@include common-session" | sudo tee -a /etc/pam.d/su.tmp
sudo mv -f /etc/pam.d/su.tmp /etc/pam.d/su

#sudo
#sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.old
sudo echo "auth       required   pam_env.so readenv=1 user_readenv=0" | sudo tee -a /etc/pam.d/sudo.tmp
sudo echo "auth       required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0" | sudo tee -a /etc/pam.d/sudo.tmp
sudo echo "@include common-auth" | sudo tee -a /etc/pam.d/sudo.tmp
sudo echo "@include common-account" | sudo tee -a /etc/pam.d/sudo.tmp
sudo echo "@include common-session-noninteractive" | sudo tee -a /etc/pam.d/sudo.tmp
sudo mv -f /etc/pam.d/sudo.tmp /etc/pam.d/sudo

#unity
#sudo cp /etc/pam.d/unity /etc/pam.d/unity.old
sudo echo "@include common-auth" | sudo tee /etc/pam.d/unity.tmp
sudo echo "auth optional pam_gnome_keyring.so" | sudo tee -a /etc/pam.d/unity.tmp
sudo mv -f /etc/pam.d/unity.tmp /etc/pam.d/unity


#Secure Shared Memory
sudo sed -i -e 's/none     /run/shm     tmpfs.*/none     /run/shm     tmpfs     defaults,ro     0     0/g' /etc/fstab
sudo mount -o remount /dev/shm


#Secure critical file permissions
sudo chown root:root /etc/fstab
sudo chown root:root /etc/passwd
sudo chown root:root /etc/shadow
sudo chown root:root /etc/group

sudo chmod 0644 /etc/fstab
sudo chmod 644 /etc/passwd
sudo chmod 644 /etc/group
sudo chmod 400 /etc/shadow


#/bin/rm -f /etc/cron.deny /etc/at.deny
echo root >/etc/cron.allow
echo root >/etc/at.allow
/bin/chown root:root /etc/cron.allow /etc/at.allow
/bin/chmod 400 cron.allow /etc/at.allow

if [ "$apache_allowed" == "y" ]; then
  sudo chown root:root /etc/apache
  sudo chown root:root /usr/sbin/*http*
  sudo chmod 755 /etc/apache
  sudo chmod 755 /usr/sbin/*http*
fi




#**********Server Configuration Block*******************

#Apache Configuration
if [ "$apache_allowed" == "y" ]; then
  sudo apt-get install -y apache2 libapache2-modsecurity
  
  sudo mv /etc/modsecurity/modsecurity.conf{-recommended,}
  
  sudo echo "Mutex file:${APACHE_LOCK_DIR} default" | sudo tee /etc/apache2/apache2.tmp
  sudo echo "PidFile ${APACHE_PID_FILE}" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "Timeout 60" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "KeepAlive On" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "MaxKeepAliveRequests 100" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "KeepAliveTimeout 5" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "User ${APACHE_RUN_USER}" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "Group ${APACHE_RUN_GROUP}" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "HostnameLookups Off" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "ServerTokens Prod" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "ServerSignature Off" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "FileETag None" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "TraceEnable off" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "Header always append X-Frame-Options SAMEORIGIN" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "Header set X-XSS-Protection “1; mode=block”" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "ErrorLog ${APACHE_LOG_DIR}/error.log" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "LogLevel warn" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "IncludeOptional mods-enabled/*.load" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "IncludeOptional mods-enabled/*.conf" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "Include ports.conf" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "<Directory /| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Options -FollowSymLinks -Indexes -Includes" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	AllowOverride None" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	<LimitExcept GET POST HEAD| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Require all denied" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "</Directory| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "<Directory /usr/share| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Options -Indexes -Includes" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	AllowOverride None" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	<LimitExcept GET POST HEAD| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Require all granted" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "</Directory| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "<Directory /var/www/| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Options -Indexes -Includes -FollowSymLinks" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	AllowOverride None" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	<LimitExcept GET POST HEAD| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Require all granted" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "</Directory| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "AccessFileName .htaccess" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "<FilesMatch "^\.ht"| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "	Require all denied" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "</FilesMatch| sudo tee" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "LogFormat "%v:%p %h %l %u %t \"%r\" %| sudo tees %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "LogFormat "%h %l %u %t \"%r\" %| sudo tees %O \"%{Referer}i\" \"%{User-Agent}i\"" combined" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "LogFormat "%h %l %u %t \"%r\" %| sudo tees %O" common" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "LogFormat "%{Referer}i -| sudo tee %U" referer" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "LogFormat "%{User-agent}i" agent" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "IncludeOptional conf-enabled/*.conf" | sudo tee -a /etc/apache2/apache2.tmp
  sudo echo "IncludeOptional sites-enabled/*.conf" | sudo tee -a /etc/apache2/apache2.tmp
  sudo mv -f /etc/apache2/apache2.tmp /etc/apache2/apache2.conf
  
  sudo echo "Listen 80" | sudo tee /etc/apache2/ports.tmp
  sudo echo "" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "<IfModule ssl_module| sudo tee" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "        Listen 443" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "</IfModule| sudo tee" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "<IfModule mod_gnutls.c| sudo tee" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "        Listen 443" | sudo tee -a /etc/apache2/ports.tmp
  sudo echo "</IfModule| sudo tee" | sudo tee -a /etc/apache2/ports.tmp
  sudo mv -f /etc/apache2/ports.tmp /etec/apache2/ports.conf
  
  sudo echo "unset HOME" | sudo tee /etc/apache2/envvars.tmp
  sudo echo "if [ "${APACHE_CONFDIR##/etc/apache2-}" != "${APACHE_CONFDIR}" ] ; then" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "        SUFFIX="-${APACHE_CONFDIR##/etc/apache2-}"" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "else" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "        SUFFIX=" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "fi" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export APACHE_RUN_USER=www-data" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export APACHE_RUN_GROUP=www-data" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export APACHE_PID_FILE=/var/run/apache2$SUFFIX/apache2.pid" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export APACHE_RUN_DIR=/var/run/apache2$SUFFIX" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export APACHE_LOCK_DIR=/var/lock/apache2$SUFFIX" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export APACHE_LOG_DIR=/var/log/apache2$SUFFIX" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export LANG=C" | sudo tee -a /etc/apache2/envvars.tmp
  sudo echo "export LANG" | sudo tee -a /etc/apache2/envvars.tmp
  sudo mv -f /etc/apache2/envvars.tmp /etc/apache2/envvars
  
  sudo echo "SecRuleEngine On" | sudo tee /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRequestBodyAccess On" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRule REQUEST_HEADERS:Content-Type "text/xml" \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRequestBodyLimit 13107200" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRequestBodyNoFilesLimit 131072" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRequestBodyInMemoryLimit 131072" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRequestBodyLimitAction Reject" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRule REQBODY_ERROR "!@eq 0" \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo ""id:'200001', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRule MULTIPART_STRICT_ERROR "!@eq 0" \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo ""id:'200002',phase:2,t:none,log,deny,status:44, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "msg:'Multipart request body failed strict validation: \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "PE %{REQBODY_PROCESSOR_ERROR}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "BQ %{MULTIPART_BOUNDARY_QUOTED}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "BW %{MULTIPART_BOUNDARY_WHITESPACE}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "DB %{MULTIPART_DATA_BEFORE}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "DA %{MULTIPART_DATA_AFTER}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "HF %{MULTIPART_HEADER_FOLDING}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "LF %{MULTIPART_LF_LINE}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SM %{MULTIPART_MISSING_SEMICOLON}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "IQ %{MULTIPART_INVALID_QUOTING}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "IP %{MULTIPART_INVALID_PART}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "IH %{MULTIPART_INVALID_HEADER_FOLDING}, \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo ""id:'200003',phase:2,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecPcreMatchLimit 1000" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecPcreMatchLimitRecursion 1000" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecRule TX:/^MSC_/ "!@streq 0" \" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "        "id:'200004',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecResponseBodyAccess On" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecResponseBodyMimeType text/plain text/html text/xml" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecResponseBodyLimit 524288" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecResponseBodyLimitAction ProcessPartial" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecTmpDir /tmp/" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecDataDir /tmp/" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecAuditEngine RelevantOnly" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecAuditLogRelevantStatus \"^(?:5|4(?!04))\"" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecAuditLogParts ABIJDEFHZ" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecAuditLogType Serial" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecAuditLog /var/log/apache2/modsec_audit.log" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecArgumentSeparator &" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecCookieFormat 0" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo echo "SecUnicodeMapFile unicode.mapping 20127" | sudo tee -a /etc/modsecurity/modsecurity.tmp
  sudo mv -f /etc/modsecurity/modsecurity.tmp /etc/modesecurity/modsecurity.conf
  
  sudo service apache2 reload

fi

if [ "$php_allowed" == "y" ]; then
  sudo add-apt-repository -y ppa:ondrej/php
  sudo apt-get update -y
  sudo apt-get install -y php7.0
  
  if [ "$mysql_allowed" == "y" ]; then
    sudo apt-get install -y php7.0-mysql
  fi
    
  sudo echo "[PHP]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  
  sudo echo "safe_mode = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "display_errors = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "register_globals = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "allow_url_fopen = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "allow_url_include = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cookie_httponly = 1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  
  sudo echo "engine = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "short_open_tag = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "precision = 14" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "output_buffering = 4096" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "zlib.output_compression = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "implicit_flush = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "unserialize_callback_func =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "serialize_precision = 17" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority," | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "disable_classes =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "zend.enable_gc = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "expose_php = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "max_execution_time = 30" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "max_input_time = 60" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "memory_limit = 128M" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "display_errors = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "display_startup_errors = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "log_errors = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "log_errors_max_len = 1024" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ignore_repeated_errors = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ignore_repeated_source = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "report_memleaks = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "track_errors = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "html_errors = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "variables_order = "GPCS"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "request_order = "GP"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "register_argc_argv = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "auto_globals_jit = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "post_max_size = 8M" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "auto_prepend_file =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "auto_append_file =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "default_mimetype = "text/html"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "default_charset = "UTF-8"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "doc_root =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "user_dir =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "enable_dl = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "file_uploads = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "upload_max_filesize = 2M" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "max_file_uploads = 20" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "allow_url_fopen = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "allow_url_include = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "default_socket_timeout = 60" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[CLI Server]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "cli_server.color = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Date]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[filter]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[iconv]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[intl]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[sqlite3]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Pcre]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Pdo]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Pdo_mysql]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pdo_mysql.cache_size = 2000" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pdo_mysql.default_socket=" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Phar]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[mail function]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "SMTP = localhost" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "smtp_port = 25" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mail.add_x_header = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[SQL]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "sql.safe_mode = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[ODBC]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "odbc.allow_persistent = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "odbc.check_persistent = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "odbc.max_persistent = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "odbc.max_links = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "odbc.defaultlrl = 4096" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "odbc.defaultbinmode = 1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Interbase]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ibase.allow_persistent = 1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ibase.max_persistent = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ibase.max_links = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ibase.timestampformat = "%Y-%m-%d %H:%M:%S"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ibase.dateformat = "%Y-%m-%d"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ibase.timeformat = "%H:%M:%S"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[MySQLi]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.max_persistent = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.allow_persistent = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.max_links = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.cache_size = 2000" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.default_port = 3306" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.default_socket =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.default_host =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.default_user =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.default_pw =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqli.reconnect = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[mysqlnd]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqlnd.collect_statistics = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "mysqlnd.collect_memory_statistics = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[OCI8]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[PostgreSQL]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pgsql.allow_persistent = On" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pgsql.auto_reset_persistent = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pgsql.max_persistent = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pgsql.max_links = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pgsql.ignore_notice = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "pgsql.log_notice = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[bcmath]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "bcmath.scale = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[browscap]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Session]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.save_handler = files" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.use_strict_mode = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.use_cookies = 1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.use_only_cookies = 1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.name = PHPSESSID" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.auto_start = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cookie_lifetime = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cookie_path = /" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cookie_domain =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cookie_httponly =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.serialize_handler = php" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.gc_probability = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.gc_divisor = 1000" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.gc_maxlifetime = 1440" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.referer_check =" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cache_limiter = nocache" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.cache_expire = 180" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.use_trans_sid = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.hash_function = 0" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "session.hash_bits_per_character = 5" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "url_rewriter.tags = "a=href,area=href,frame=src,input=src,form=fakeentry"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Assertion]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "zend.assertions = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[COM]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[mbstring]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[gd]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[exif]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[Tidy]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "tidy.clean_output = Off" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[soap]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "soap.wsdl_cache_enabled=1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "soap.wsdl_cache_dir="/tmp"" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "soap.wsdl_cache_ttl=86400" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "soap.wsdl_cache_limit = 5" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[sysvshm]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[ldap]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "ldap.max_links = -1" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[mcrypt]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[dba]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[opcache]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[curl]" | sudo tee -a /etc/php7.0/apache2/php.tmp
  sudo echo "[openssl]" | sudo tee -a /etc/php7.0/apache2/php.tmp

  sudo mv -f /etc/php7.0/apache2/php.tmp /etc/php7.0/apache2/php.ini
  
fi

if [ "$mysql_allowed" == "y" ]; then
  
  sudo apt-get install -y mysql-server
  
  echo "Running mySQL Secure Installation, please configure carefully, press enter to continue..."
  read continue
  sudo mysql_secure_installation
  
fi



#Disable unrequired services
#SNMP
sudo service snmpd stop
sudo echo manual | sudo tee /etc/init/snmpd.override
sudo service snmp stop
sudo echo manual | sudo tee /etc/init/snmp.override
#FTP, TFTP, and VSFTP
if [ "$ftp_server" == "y" ]; then
  sudo apt-get install -y vsftpd
  sudo service vsftp start
  sudo echo automatic | sudo tee /etc/init/vsftp.override
  sudo service vsftpd start
  sudo echo automatic | sudo tee /etc/init/vsftpd.override
  
  sudo cp /etc/vsftpd.conf /etc/vsftpd.old
  sudo sudo echo "listen=YES" | sudo tee /etc/vsftpd.tmp
  sudo sudo echo "listen_ipv6=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "anonymous_enable=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "local_enable=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "write_enable=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "anon_upload_enable=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "anon_mkdir_write_enable=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "dirmessage_enable=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "use_localtime=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "xferlog_enable=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "connect_from_port_20=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "chown_updloads=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "chown_username=nobody" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "async_abor_enable=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "ASCII_upload_enable=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "ASCII_download_enable=NO" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "chroot_local_user=YES" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "secure_chroot_dir=/var/run/vsftpd/empty" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "pam_service_name=vsftpd" | sudo tee -a /etc/vsftpd.tmp
  sudo sudo echo "rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem" | sudo tee -a /etc/vsftpd.tmp
  sudo echo "rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.kay" | sudo tee -a /etc/vsftpd.tmp
  sudo cp /etc/vsftpd.tmp /etc/vsftpd.conf
else
  sudo service tftpd stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/tftpd.override
  sudo service ftpd stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/ftpd.override
  sudo service vsftpd stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/vsftpd.override
  sudo apt-get purge -y vsftpd ftp &> /dev/null
fi
if [ "$ftp_client" == "y" ]; then
  sudo apt-get install -y filezilla
  sudo service tftp start &> /dev/null
  sudo echo manual | sudo tee /etc/init/tftp.override
  sudo service ftp stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/ftp.override
  sudo service vsftp stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/vsftp.override
else
  sudo service tftp stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/tftp.override
  sudo service ftp stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/ftp.override
  sudo service vsftp stop &> /dev/null
  sudo echo manual | sudo tee /etc/init/vsftp.override
  sudo apt-get purge -y filezilla &> /dev/null
fi
#Telnet
sudo service telnet stop &> /dev/null
sudo echo manual | sudo tee /etc/init/telnet.override
#rLogin
sudo service rlogin stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rlogin.override
#rExec
sudo service rexec stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rexec.override
sudo service rexec stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rexec.override
#Automount
sudo service automount stop &> /dev/null
sudo echo manual | sudo tee /etc/init/automount.override
#Name Server
sudo service named stop &> /dev/null
sudo echo manual | sudo tee /etc/init/named.override
#rSH (remote shell)
sudo service rsh stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rsh.override
#finger
sudo service finger stop &> /dev/null
sudo echo manual | sudo tee /etc/init/finger.override
#netdump
sudo service netdump stop &> /dev/null
sudo echo manual | sudo tee /etc/init/netdump.override
#nfs
sudo service nfs stop &> /dev/null
sudo echo manual | sudo tee /etc/init/nfs.override
sudo service nfs-kernel-server stop &> /dev/null
sudo echo manual | sudo tee /etc/init/nfs-kernel-server.override
sudo apt-get purge -y nfs-kernel-server nfs-common portmap &> /dev/null
#rwhod
sudo service rwhod stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rwhod.override
#yppasswdd
sudo service yppasswdd stop &> /dev/null
sudo echo manual | sudo tee /etc/init/yppasswdd.override
#ypserv
sudo service ypserv stop &> /dev/null
sudo echo manual | sudo tee /etc/init/ypserv.override
#ypxfrd
sudo service ypxfrd stop &> /dev/null
sudo echo manual | sudo tee /etc/init/ypxfrd.override
#rsh
sudo service rsh stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rsh.override
#portmap
sudo service portmap stop &> /dev/null
sudo echo manual | sudo tee /etc/init/portmap.override



#echo "acpid" > default-services.tmp
#echo "apparmor" >> default-services.tmp
#echo "avahi-daemon" >> default-services.tmp
#echo "bluetooth" >> default-services.tmp
#echo "cron" >> default-services.tmp
#echo "cups" >> default-services.tmp
#echo "cups-browsed" >> default-services.tmp
#echo "friendly-recovery" >> default-services.tmp
#echo "kerneloops" >> default-services.tmp
#echo "resolvconf" >> default-services.tmp
#echo "rsyslog" >> default-services.tmp
#echo "saned" >> default-services.tmp
#echo "udev" >> default-services.tmp
#echo "unattended-upgrades" >> default-services.tmp
#echo "friendly-recovery" >> default-services.tmp

#>safe-services.tmp
#echo "acpid" >> safe-services.tmp
#echo "anacron" >> safe-services.tmp
#echo "apparmor" >> safe-services.tmp
#echo "apport" >> safe-services.tmp
#echo "auditd" >> safe-services.tmp
#echo "avahi-daemon" >> safe-services.tmp
#echo "bluetooth" >> safe-services.tmp
#echo "brltty" >> safe-services.tmp
#echo "clamav-freshclam" >> safe-services.tmp
#echo "console-setup" >> safe-services.tmp
#echo "cron" >> safe-services.tmp
#echo "cups" >> safe-services.tmp
#echo "cups-browsed" >> safe-services.tmp
#echo "dbus" >> safe-services.tmp
#echo "dns-clean" >> safe-services.tmp
#echo "grub-common" >> safe-services.tmp
#echo "irqbalance" >> safe-services.tmp
#echo "kerneloops" >> safe-services.tmp
#echo "killprocs" >> safe-services.tmp
#echo "kmod" >> safe-services.tmp
#echo "lightdm" >> safe-services.tmp
#echo "networking" >> safe-services.tmp
#echo "ondemand" >> safe-services.tmp
#echo "open-vm-tools" >> safe-services.tmp
#echo "postfix" >> safe-services.tmp
#echo "pppd-dns" >> safe-services.tmp
#echo "procps" >> safe-services.tmp
#echo "pulseaudio" >> safe-services.tmp
#echo "rc.local" >> safe-services.tmp
#echo "resolvconf" >> safe-services.tmp
#echo "rsync" >> safe-services.tmp
#echo "rsyslog" >> safe-services.tmp
#echo "saned" >> safe-services.tmp
#echo "sendsigs" >> safe-services.tmp
#echo "speech-dispatcher" >> safe-services.tmp
#echo "thermald" >> safe-services.tmp
#echo "udev" >> safe-services.tmp
#echo "umountfs" >> safe-services.tmp
#echo "umountnfs.sh" >> safe-services.tmp
#echo "umountroot" >> safe-services.tmp
#echo "unattended-upgrades" >> safe-services.tmp
#echo "urandom" >> safe-services.tmp

#echo "friendly-recovery" > ignore-services.tmp
#echo "x11-common" >> ignore-services.tmp
#echo "open-vm-tools" >> ignore-services.tmp
#echo "killprocs" >> ignore-services.tmp
#echo "sudo" >> ignore-services.tmp


##Service Loop
#sudo service --status-all > services.tmp 2>&1
#for service in `cat services.tmp | cut -d ']' -f 2 | sed 's/  //'` ; do
#  if [ "$service" != "" ]; then
#    safe="false"
#    default="false"
#    ignore="false"
#    for entry in `cat ignore-services.tmp`; do
#      if [ "$service" == "$entry" ]; then
#        ignore="true"
#        break
#      fi
#    done
#    for entry in `cat default-services.tmp`; do
#      if [ "$service" == "$entry" ]; then
#        safe="true"
#        default="true"
#        break
#      fi
#    done
#    for entry in `cat safe-services.tmp`; do
#      if [ "$service" == "$entry" ]; then
#        safe="true"
#        break
#      fi
#    done
#    if [ "$ignore" == "false" ]; then
#      if [ "$safe" == "false" ]; then
#        echo "Is $service a valid service? (y/n): "
#        read $valid
#        if [ "$valid" != "n" ]; then
#          sudo service $service start &> /dev/null
#          sudo update-rc.d $service enable &> /dev/null
#          sudo echo "start on runlevel [2345]" | sudo tee /etc/init/$service.override
#          sudo echo "respawn" | sudo tee /etc/init/$service.override
#          sudo systemctl enable $service.service &> /dev/null
#          sudo systemctl start $service.service &> /dev/null
#        else
#          sudo service $service stop &> /dev/null
#          sudo update-rc.d $service disable &> /dev/null
#          sudo echo "" | sudo tee /etc/init/$service.override
#          sudo systemctl disable $service.service &> /dev/null
#          sudo systemctl stop $service.service &> /dev/null
#        fi
#      else
#        if [ "$default" == "true" ]; then
#          sudo service $service start &> /dev/null
#          sudo update-rc.d $service enable &> /dev/null
#          sudo echo "start on runlevel [2345]" | sudo tee /etc/init/$service.override
#          sudo echo "respawn" | sudo tee /etc/init/$service.override
#          sudo systemctl enable $service.service &> /dev/null
#          sudo systemctl start $service.service &> /dev/null
#        else
#          sudo service $service start &> /dev/null
#          sudo update-rc.d $service enable &> /dev/null
#          sudo echo "start on runlevel [2345]" | sudo tee /etc/init/$service.override
#          sudo echo "respawn" | sudo tee /etc/init/$service.override
#          sudo systemctl enable $service.service &> /dev/null
#          sudo systemctl start $service.service &> /dev/null
#        fi
#      fi
#    fi
#  fi
#done

##Enable Required Services
#sudo service sudo start &> /dev/null
#sudo update-rc.d sudo enable &> /dev/null
#sudo echo "start on runlevel [2345]" | sudo tee /etc/init/sudo.override
#sudo echo "respawn" | sudo tee /etc/init/$service.override
#sudo systemctl enable sudo.service &> /dev/null
#sudo systemctl start sudo.service &> /dev/null

#sudo systemctl daemon-reload
#echo "Services secured"


#Default Ports
#>default-ports.tmp
#echo "tcp 0 0 Ubuntu-14-test-V:domain *:* LISTEN 1059/dnsmasq " >> default-ports.tmp
#echo "tcp 0 0 localhost:ipp *:* LISTEN 3388/cupsd " >> default-ports.tmp
#echo "tcp6 0 0 localhost:ipp [::]:* LISTEN 3388/cupsd " >> default-ports.tmp
#echo "udp 0 0 *:ipp *:* 695/cups-browsed" >> default-ports.tmp
#echo "udp 0 0 *:56148 *:* 966/dhclient " >> default-ports.tmp
#echo "udp 0 0 *:42203 *:* 567/avahi-daemon: r" >> default-ports.tmp
#echo "udp 0 0 *:mdns *:* 567/avahi-daemon: r" >> default-ports.tmp
#echo "udp 0 0 *:61164 *:* - " >> default-ports.tmp
#echo "udp 0 0 Ubuntu-14-test-V:domain *:* 1059/dnsmasq " >> default-ports.tmp
#echo "udp 0 0 *:bootpc *:* 966/dhclient " >> default-ports.tmp
#echo "udp6 0 0 [::]:14920 [::]:* 966/dhclient " >> default-ports.tmp
#echo "udp6 0 0 [::]:mdns [::]:* 567/avahi-daemon: r" >> default-ports.tmp
#echo "udp6 0 0 [::]:32983 [::]:* 567/avahi-daemon: r" >> default-ports.tmp


#echo "Press enter to begin editing listening ports..."
#read continue
##Secure Listening Ports
#sudo netstat -pl | grep -B 999999 'Active UNIX domain sockets' | grep -v 'Active UNIX domain sockets' | grep -v 'Active Internet connections' | grep -v 'Proto Recv-Q' | tr -s ' ' > listening.tmp
#sudo netstat -pl --numeric-ports --numeric-hosts --numeric-users | grep -B 999999 'Active UNIX domain sockets' | grep -v 'Active UNIX domain sockets' | grep -v 'Active Internet connections' | grep -v 'Proto Recv-Q' | tr -s ' ' > listening-numeric.tmp
#line=0
#IFS=$'\n'
#for net in `cat listening.tmp` ; do
#  ((line++))
#  safe="false"
#  for entry in `cat default-ports.tmp`; do
#    if [ "$net" == "$entry" ]; then
#      safe="true"
#      break
#    fi
#  done
#  if [ "$safe" == "false" ]; then
#    pname=`echo $net | cut -d ' ' -f 4 | cut -d ':' -f 2`
#    port=`sed -n "$line p" listening-numeric.tmp | cut -d ' ' -f 4 | cut -d ':' -f 2`
#    pid=`echo $net | rev | cut -d ' ' -f 2 | rev | cut -d '/' -f 1`
#    process=`echo $net | rev | cut -d ' ' -f 2 | rev | cut -d '/' -f 2`
#    ppid=`sudo ps -o ppid= -p 1106 | rev | cut -d ' ' -f 1 | rev`
#    parent=`sudo ps -o comm= -p $pid`
#    if [ "$net" != "" ]; then
#      echo "Process $pid ($process) is listening on port $port ($pname).  Is this valid? (y/n): "
#      read valid
#      if [ "$valid" != "n" ]; then
#        echo "Accepting open port $port ($pname) as valid."
#      else
#        sudo kill -$pid &> /dev/null
#        sudo ufw deny $port &> /dev/null
#        sudo ufw deny $pname &> /dev/null
#        sudo service $pname stop
#        sudo update-rc.d $service disable &> /dev/null
#        sudo echo "" | sudo tee /etc/init/$service.override &> /dev/null
#        sudo systemctl disable $service.service &> /dev/null
#        sudo systemctl stop $service.service &> /dev/null
#        echo "Ended process $pid ($process) and closed port $port ($pname)."
#        echo "Parent process is $ppid ($parent).  End this process as well? (y/n): "
#        read endparent
#        if [ "$endparent" == "n" ]; then
#          sudo kill $ppid &> /dev/null
#          echo "Ended parent process $ppid ($parent)."
#        fi
#      fi
#    fi
#  fi
#done
#IFS=$' \t\n'
#echo "Open ports secured"
#echo
#echo
  


#Default Processes
>default-procs.tmp
echo "systemd" >> default-procs.tmp
echo "kthreadd" >> default-procs.tmp
echo "ksoftirqd/0" >> default-procs.tmp
echo "kworker/0:0H" >> default-procs.tmp
echo "rcu_sched" >> default-procs.tmp
echo "rcu_bh" >> default-procs.tmp
echo "migration/0" >> default-procs.tmp
echo "watchdog/0" >> default-procs.tmp
echo "watchdog/1" >> default-procs.tmp
echo "migration/1" >> default-procs.tmp
echo "ksoftirqd/1" >> default-procs.tmp
echo "kworker/1:0" >> default-procs.tmp
echo "kworker/1:0H" >> default-procs.tmp
echo "kdevtmpfs" >> default-procs.tmp
echo "netns" >> default-procs.tmp
echo "perf" >> default-procs.tmp
echo "khungtaskd" >> default-procs.tmp
echo "writeback" >> default-procs.tmp
echo "ksmd" >> default-procs.tmp
echo "khugepaged" >> default-procs.tmp
echo "crypto" >> default-procs.tmp
echo "kintegrityd" >> default-procs.tmp
echo "bioset" >> default-procs.tmp
echo "kblockd" >> default-procs.tmp
echo "ata_sff" >> default-procs.tmp
echo "md" >> default-procs.tmp
echo "devfreq_wq" >> default-procs.tmp
echo "kworker/0:1" >> default-procs.tmp
echo "kworker/1:1" >> default-procs.tmp
echo "kswapd0" >> default-procs.tmp
echo "vmstat" >> default-procs.tmp
echo "fsnotify_mark" >> default-procs.tmp
echo "ecryptfs-kthrea" >> default-procs.tmp
echo "kthrotld" >> default-procs.tmp
echo "acpi_thermal_pm" >> default-procs.tmp
echo "scsi_eh_0" >> default-procs.tmp
echo "scsi_tmf_0" >> default-procs.tmp
echo "scsi_eh_1" >> default-procs.tmp
echo "scsi_tmf_1" >> default-procs.tmp
echo "ipv6_addrconf" >> default-procs.tmp
echo "deferwq" >> default-procs.tmp
echo "charger_manager" >> default-procs.tmp
echo "kworker/0:2" >> default-procs.tmp
echo "mpt_poll_0" >> default-procs.tmp
echo "mpt/0" >> default-procs.tmp
echo "scsi_eh_2" >> default-procs.tmp
echo "scsi_tmf_2" >> default-procs.tmp
echo "scsi_eh_3" >> default-procs.tmp
echo "scsi_tmf_3" >> default-procs.tmp
echo "scsi_eh_4" >> default-procs.tmp
echo "scsi_tmf_4" >> default-procs.tmp
echo "scsi_eh_5" >> default-procs.tmp
echo "scsi_tmf_5" >> default-procs.tmp
echo "scsi_eh_6" >> default-procs.tmp
echo "scsi_tmf_6" >> default-procs.tmp
echo "scsi_eh_7" >> default-procs.tmp
echo "kpsmoused" >> default-procs.tmp
echo "scsi_tmf_7" >> default-procs.tmp
echo "scsi_eh_8" >> default-procs.tmp
echo "scsi_tmf_8" >> default-procs.tmp
echo "scsi_eh_9" >> default-procs.tmp
echo "scsi_tmf_9" >> default-procs.tmp
echo "scsi_eh_10" >> default-procs.tmp
echo "scsi_tmf_10" >> default-procs.tmp
echo "scsi_eh_11" >> default-procs.tmp
echo "scsi_tmf_11" >> default-procs.tmp
echo "scsi_eh_12" >> default-procs.tmp
echo "scsi_tmf_12" >> default-procs.tmp
echo "scsi_eh_13" >> default-procs.tmp
echo "scsi_tmf_13" >> default-procs.tmp
echo "scsi_eh_14" >> default-procs.tmp
echo "scsi_tmf_14" >> default-procs.tmp
echo "scsi_eh_15" >> default-procs.tmp
echo "scsi_tmf_15" >> default-procs.tmp
echo "scsi_eh_16" >> default-procs.tmp
echo "scsi_tmf_16" >> default-procs.tmp
echo "scsi_eh_17" >> default-procs.tmp
echo "scsi_tmf_17" >> default-procs.tmp
echo "scsi_eh_18" >> default-procs.tmp
echo "scsi_tmf_18" >> default-procs.tmp
echo "scsi_eh_19" >> default-procs.tmp
echo "scsi_tmf_19" >> default-procs.tmp
echo "scsi_eh_20" >> default-procs.tmp
echo "scsi_tmf_20" >> default-procs.tmp
echo "scsi_eh_21" >> default-procs.tmp
echo "scsi_tmf_21" >> default-procs.tmp
echo "scsi_eh_22" >> default-procs.tmp
echo "scsi_tmf_22" >> default-procs.tmp
echo "scsi_eh_23" >> default-procs.tmp
echo "scsi_tmf_23" >> default-procs.tmp
echo "scsi_eh_24" >> default-procs.tmp
echo "scsi_tmf_24" >> default-procs.tmp
echo "scsi_eh_25" >> default-procs.tmp
echo "scsi_tmf_25" >> default-procs.tmp
echo "scsi_eh_26" >> default-procs.tmp
echo "scsi_tmf_26" >> default-procs.tmp
echo "scsi_eh_27" >> default-procs.tmp
echo "scsi_tmf_27" >> default-procs.tmp
echo "scsi_eh_28" >> default-procs.tmp
echo "scsi_tmf_28" >> default-procs.tmp
echo "scsi_eh_29" >> default-procs.tmp
echo "scsi_tmf_29" >> default-procs.tmp
echo "scsi_eh_30" >> default-procs.tmp
echo "scsi_tmf_30" >> default-procs.tmp
echo "scsi_eh_31" >> default-procs.tmp
echo "scsi_tmf_31" >> default-procs.tmp
echo "kworker/u4:28" >> default-procs.tmp
echo "kworker/u4:29" >> default-procs.tmp
echo "scsi_eh_32" >> default-procs.tmp
echo "scsi_tmf_32" >> default-procs.tmp
echo "ttm_swap" >> default-procs.tmp
echo "kworker/1:1H" >> default-procs.tmp
echo "jbd2/sda1-8" >> default-procs.tmp
echo "ext4-rsv-conver" >> default-procs.tmp
echo "kworker/0:1H" >> default-procs.tmp
echo "kworker/1:2" >> default-procs.tmp
echo "kauditd" >> default-procs.tmp
echo "systemd-journal" >> default-procs.tmp
echo "vmware-vmblock-" >> default-procs.tmp
echo "systemd-udevd" >> default-procs.tmp
echo "systemd-timesyn" >> default-procs.tmp
echo "auditd" >> default-procs.tmp
echo "cron" >> default-procs.tmp
echo "vmtoolsd" >> default-procs.tmp
echo "anacron" >> default-procs.tmp
echo "rsyslogd" >> default-procs.tmp
echo "avahi-daemon" >> default-procs.tmp
echo "systemd-logind" >> default-procs.tmp
echo "accounts-daemon" >> default-procs.tmp
echo "ModemManager" >> default-procs.tmp
echo "dbus-daemon" >> default-procs.tmp
echo "NetworkManager" >> default-procs.tmp
echo "freshclam" >> default-procs.tmp
echo "acpid" >> default-procs.tmp
echo "snapd" >> default-procs.tmp
echo "polkitd" >> default-procs.tmp
echo "irqbalance" >> default-procs.tmp
echo "lightdm" >> default-procs.tmp
echo "Xorg" >> default-procs.tmp
echo "dhclient" >> default-procs.tmp
echo "dnsmasq" >> default-procs.tmp
echo "whoopsie" >> default-procs.tmp
echo "agetty" >> default-procs.tmp
echo "rtkit-daemon" >> default-procs.tmp
echo "upowerd" >> default-procs.tmp
echo "colord" >> default-procs.tmp
echo "cupsd" >> default-procs.tmp
echo "cups-browsed" >> default-procs.tmp
echo "kworker/1:3" >> default-procs.tmp
echo "(sd-pam)" >> default-procs.tmp
echo "gnome-keyring-d" >> default-procs.tmp
echo "upstart" >> default-procs.tmp
echo "upstart-udev-br" >> default-procs.tmp
echo "window-stack-br" >> default-procs.tmp
echo "upstart-dbus-br" >> default-procs.tmp
echo "upstart-file-br" >> default-procs.tmp
echo "ibus-daemon" >> default-procs.tmp
echo "gvfsd" >> default-procs.tmp
echo "gvfsd-fuse" >> default-procs.tmp
echo "ibus-dconf" >> default-procs.tmp
echo "ibus-ui-gtk3" >> default-procs.tmp
echo "ibus-x11" >> default-procs.tmp
echo "bamfdaemon" >> default-procs.tmp
echo "at-spi-bus-laun" >> default-procs.tmp
echo "at-spi2-registr" >> default-procs.tmp
echo "ibus-engine-sim" >> default-procs.tmp
echo "hud-service" >> default-procs.tmp
echo "unity-settings-" >> default-procs.tmp
echo "gnome-session-b" >> default-procs.tmp
echo "unity-panel-ser" >> default-procs.tmp
echo "kworker/0:0" >> default-procs.tmp
echo "dconf-service" >> default-procs.tmp
echo "indicator-messa" >> default-procs.tmp
echo "indicator-bluet" >> default-procs.tmp
echo "indicator-power" >> default-procs.tmp
echo "indicator-datet" >> default-procs.tmp
echo "indicator-keybo" >> default-procs.tmp
echo "indicator-sound" >> default-procs.tmp
echo "indicator-print" >> default-procs.tmp
echo "indicator-sessi" >> default-procs.tmp
echo "evolution-sourc" >> default-procs.tmp
echo "indicator-appli" >> default-procs.tmp
echo "pulseaudio" >> default-procs.tmp
echo "compiz" >> default-procs.tmp
echo "kworker/u4:0" >> default-procs.tmp
echo "evolution-calen" >> default-procs.tmp
echo "nm-applet" >> default-procs.tmp
echo "gnome-software" >> default-procs.tmp
echo "unity-fallback-" >> default-procs.tmp
echo "polkit-gnome-au" >> default-procs.tmp
echo "nautilus" >> default-procs.tmp
echo "gvfs-udisks2-vo" >> default-procs.tmp
echo "udisksd" >> default-procs.tmp
echo "evolution-addre" >> default-procs.tmp
echo "fwupd" >> default-procs.tmp
echo "gvfs-afc-volume" >> default-procs.tmp
echo "gvfs-goa-volume" >> default-procs.tmp
echo "gvfs-gphoto2-vo" >> default-procs.tmp
echo "gvfs-mtp-volume" >> default-procs.tmp
echo "gvfsd-trash" >> default-procs.tmp
echo "zeitgeist-datah" >> default-procs.tmp
echo "sh" >> default-procs.tmp
echo "zeitgeist-daemo" >> default-procs.tmp
echo "zeitgeist-fts" >> default-procs.tmp
echo "firefox" >> default-procs.tmp
echo "Content" >> default-procs.tmp
echo "update-notifier" >> default-procs.tmp
echo "aptd" >> default-procs.tmp
echo "deja-dup-monito" >> default-procs.tmp
echo "gvfsd-metadata" >> default-procs.tmp
echo "gnome-terminal-" >> default-procs.tmp
echo "bash" >> default-procs.tmp
echo "sudo" >> default-procs.tmp
echo "ps" >> default-procs.tmp
echo "init" >> default-procs.tmp
echo "bluetoothd" >> default-procs.tmp
echo "krfcommd" >> default-procs.tmp
echo "upstart-socket-" >> default-procs.tmp
echo "getty" >> default-procs.tmp
echo "kerneloops" >> default-procs.tmp
echo "upstart-event-b" >> default-procs.tmp
echo "gnome-session" >> default-procs.tmp
echo "notify-osd" >> default-procs.tmp
echo "gconfd-2" >> default-procs.tmp
echo "gvfsd-burn" >> default-procs.tmp
echo "telepathy-indic" >> default-procs.tmp
echo "mission-control" >> default-procs.tmp
echo "cat" >> default-procs.tmp
echo "dbus" >> default-procs.tmp
echo "kworker/u4:2" >> default-procs.tmp
echo "gnome-terminal" >> default-procs.tmp
echo "gnome-pty-helpe" >> default-procs.tmp
echo "kworker/u4:1" >> default-procs.tmp
echo "gedit" >> default-procs.tmp
echo "gpg-agent" >> default-procs.tmp
echo "update-manager" >> default-procs.tmp
echo "python3" >> default-procs.tmp
echo "dbus-launch" >> default-procs.tmp
echo "kworker /0:3" >> default-procs.tmp
echo "xfsalloc" >> default-procs.tmp
echo "xfs_mru_cache" >> default-procs.tmp
echo "jfsIO" >> default-procs.tmp
echo "jfsCommit" >> default-procs.tmp
echo "jfsSync" >> default-procs.tmp



#Secure Running Processes
echo "Press enter to begin editing running processes..."
read continue
IFS=$'\n'
firstline=0
for process in `sudo ps -A` ; do
  if [ "$firstline" == "0" ]; then
    firstline=1
  else
    name=`echo $process | tr -s ' ' | rev | cut -d ' ' -f 1 | rev`
    safe="false"
    for entry in `cat default-procs.tmp`; do
      if [ "$name" == "$entry" ]; then
        safe="true"
        break
      fi
    done
    if [ "$safe" == "false" ]; then
      pid=`echo $process | tr -s ' ' | rev | cut -d ' ' -f 4 | rev`
      runtime=`echo $process | tr -s ' ' | rev | cut -d ' ' -f 2 | rev`
      ppid=`sudo ps -o ppid= -p $pid 2>/dev/null` 
      parent=`sudo ps -o comm= -p $ppid 2>/dev/null`
      if [ "$pid" != "" ]; then
        echo "Is PID $pid ($name, running for $runtime) a valid process? (y/n); "
        read valid
        if [ "$valid" != "n" ]; then
          echo "$name" >> default-procs.tmp
          echo "PID $pid ($name) accapted as valid."
        else
          sudo kill $pid &> /dev/null
          echo "PID $pid ($name) stopped."
          if [ "$ppid" != "" ]; then
            echo "End parent process $pid ($parent)? (y/n): "
            read endparent
            if [ "$endparent" == "n" ]; then
              sudo kill $ppid &> /dev/null
              echo "Parent PID $ppid ($parent) stopped."
            fi
          fi
        fi
      fi
    fi
  fi
done
IFS=$' \t\n'
echo "Running processes secured"
echo
echo




#Misc sudo dconf settings
sudo dconf write /desktop/gnome/crypto/pgp/ascii-armor true
sudo dconf write /desktop/gnome/crypto/pgp/encrypt-to-self true


#Prepare Cronjob log file for later
sudo echo "Cronjobs for all users:" > cronjobs.log


#Begin sudoer file configuration
sudo echo "Defaults        env_reset" | sudo tee /etc/sudoers.tmp
sudo echo "Defaults        mail_badpass" | sudo tee -a /etc/sudoers
sudo echo "Defaults        secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" | sudo tee -a /etc/sudoers.tmp
sudo echo "root    ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.tmp
sudo echo "%sudo    ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.tmp
sudo echo "%admin    ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.tmp


#Default Users
>safe-users.tmp
echo "www-data" >> safe-users.tmp
echo "whoopsie" >> safe-users.tmp
echo "uuidd" >> safe-users.tmp
echo "uucp" >> safe-users.tmp
echo "usbmux" >> safe-users.tmp
echo "systemd-timesync" >> safe-users.tmp
echo "systemd-resolve" >> safe-users.tmp
echo "systemd-network" >> safe-users.tmp
echo "systemd-bus-proxy" >> safe-users.tmp
echo "syslog" >> safe-users.tmp
echo "sys" >> safe-users.tmp
echo "sync" >> safe-users.tmp
echo "speech-dispatcher" >> safe-users.tmp
echo "saned" >> safe-users.tmp
echo "rtkit" >> safe-users.tmp
echo "root" >> safe-users.tmp
echo "pulse" >> safe-users.tmp
echo "proxy" >> safe-users.tmp
echo "postfix" >> safe-users.tmp
echo "nobody" >> safe-users.tmp
echo "news" >> safe-users.tmp
echo "messagebus" >> safe-users.tmp
echo "man" >> safe-users.tmp
echo "mail" >> safe-users.tmp
echo "lp" >> safe-users.tmp
echo "list" >> safe-users.tmp
echo "lightdm" >> safe-users.tmp
echo "kernoops" >> safe-users.tmp
echo "irc" >> safe-users.tmp
echo "hplip" >> safe-users.tmp
echo "gnats" >> safe-users.tmp
echo "games" >> safe-users.tmp
echo "dnsmasq" >> safe-users.tmp
echo "daemon" >> safe-users.tmp
echo "colord" >> safe-users.tmp
echo "clamav" >> safe-users.tmp
echo "bin" >> safe-users.tmp
echo "backup" >> safe-users.tmp
echo "avahi-autoipd" >> safe-users.tmp
echo "avahi" >> safe-users.tmp
echo "_apt" >> safe-users.tmp
echo "libuuid" >> safe-users.tmp
echo "postdrop" >> safe-users.tmp
echo "uuid" >> safe-users.tmp



>/etc/passwd.tmp
sudo cp /etc/passwd /etc/passwd.old

clear
echo "Press enter to begin editing user accounts..."
read continue
for usr in `sudo cut -d: -f 1 /etc/passwd | sort -r`; do
  if [ "$usr" != "" ]; then
    safe="false"
    for entry in `cat safe-users.tmp`; do
      if [ "$usr" == "$entry" ]; then
        safe="true"
        break
      fi
    done
    uid=`sudo cat /etc/passwd | grep ^$usr: | cut -d ':' -f 3`
    gid=`sudo cat /etc/passwd | grep ^$usr: | cut -d ':' -f 4`
    name=`sudo cat /etc/passwd | grep ^$usr: | cut -d ':' -f 5`
    homedir=`sudo cat /etc/passwd | grep ^$usr: | cut -d ':' -f 6`
    usrshell=`sudo cat /etc/passwd | grep ^$usr: | cut -d ':' -f 7`
    if [ "$safe" == "false" ]; then
      sudo echo "Is $usr a valid user account? (Or skip) (y/n/s): "
      read valid
      if [ "$valid" != "s" ]; then
        if [ "$valid" != "n" ]; then
          sudo echo "Is $usr an administrator? (y/n): "
          read admin
          if [ "$admin" == "y" ]; then
            echo "Giving $usr sudoer priviliges."
            sudo adduser $usr sudo > /dev/null 2>&1
            sudo gpasswd -a $usr sudo > /dev/null 2>&1
            sudo echo "$usr    ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.tmp
          else
            sudo deluser $usr sudo > /dev/null 2>&1
            sudo echo $usr >> /etc/cron.deny
            sudo gpasswd -d $usr sudo > /dev/null 2>&1
            sudo echo "$usr    NONE=(NONE:NONE) NONE" | sudo tee -a /etc/sudoers.tmp
          fi
          echo "Assigning $usr secure password."
          sudo passwd -u $usr
          sudo echo -e "$password\n$password" | (passwd $usr) > /dev/null 2>&1
          sudo chage -E -1 -m 5 -M 60 -I 10 -W 14 $usr > /dev/null 2>&1
          sudo crontab -u $usr -l >> cronjobs.log
          #Secures home directory so only the user may access and use their files.
          sudo su $usr chmod 700 /home/$usr > /dev/null 2>&1
          #sudo chmod 0 $usr:$usr 700 /home/$usr > /dev/null 2>&1
          homedir="/home/$usr"
          usrshell="/bin/bash"
          echo "$usr:x:$uid:$gid:$name:$homedir:$usrshell" | sudo tee -a /etc/passwd.tmp
          
          echo "$usr" >> safe-groups-users.tmp
        else
          echo "Deleting user and user's files."
          sudo passwd -l $usr > /dev/null 2>&1
          sudo cronjob -u $usr -r > /dev/null 2>&1
          sudo deluser --remove-home $usr > /dev/null 2>&1
        fi
      else
        sudo echo -e "$password\n$password" | (passwd $usr)
        sudo crontab -u $usr -l >> cronjobs.log
        sudo echo "$usr    ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.tmp
        sudo adduser $usr sudo > /dev/null 2>&1
        sudo gpasswd -a $usr sudo > /dev/null 2>&1
        
        homedir="/home/$usr"
        usrshell="/bin/bash"
        echo "$usr:x:$uid:$gid:$name:$homedir:$usrshell" | sudo tee -a /etc/passwd.tmp
        
        echo "$usr" >> safe-groups-users.tmp
      fi
    else
      sudo crontab -u $usr -l >> cronjobs.log
      echo "$usr:x:$uid:$gid:$name:$homedir:$usrshell" | sudo tee -a /etc/passwd.tmp
    fi
  fi
done

#Change root shell
sudo sed -ie 's/root:x:0:0:root:\/root:.*/root:x:0:0:root:\/root:\/usr\/sbin\/nologin/g' /etc/passwd.tmp

#Finish up config files
sudo echo "#includedir /etc/sudoers.d" | sudo tee -a /etc/sudoers.tmp
sudo mv -f /etc/sudoers.tmp /etc/sudoers
sudo mv -f /etc/passwd.tmp /etc/passwd
echo "User configuration complete."


#Configure Groups
echo "root" > safe-groups.tmp
echo "www-data" >> safe-groups.tmp
echo "whoopsie" >> safe-groups.tmp
echo "voice" >> safe-groups.tmp
echo "video" >> safe-groups.tmp
echo "uuidd" >> safe-groups.tmp
echo "uucp" >> safe-groups.tmp
echo "utmp" >> safe-groups.tmp
echo "users" >> safe-groups.tmp
echo "tty" >> safe-groups.tmp
echo "tape" >> safe-groups.tmp
echo "systemd-timesync" >> safe-groups.tmp
echo "systemd-resolve" >> safe-groups.tmp
echo "systemd-network" >> safe-groups.tmp
echo "systemd-journal" >> safe-groups.tmp
echo "systemd-bus-proxy" >> safe-groups.tmp
echo "syslog" >> safe-groups.tmp
echo "sys" >> safe-groups.tmp
echo "sudo" >> safe-groups.tmp
echo "staff" >> safe-groups.tmp
echo "ssl-cert" >> safe-groups.tmp
echo "ssh" >> safe-groups.tmp
echo "src" >> safe-groups.tmp
echo "shadow" >> safe-groups.tmp
echo "scanner" >> safe-groups.tmp
echo "sasl" >> safe-groups.tmp
echo "saned" >> safe-groups.tmp
echo "sambashare" >> safe-groups.tmp
echo "rtkit" >> safe-groups.tmp
echo "pulse-access" >> safe-groups.tmp
echo "pulse" >> safe-groups.tmp
echo "proxy" >> safe-groups.tmp
echo "postfix" >> safe-groups.tmp
echo "postdrop" >> safe-groups.tmp
echo "plugdev" >> safe-groups.tmp
echo "operator" >> safe-groups.tmp
echo "nopasswdlogin" >> safe-groups.tmp
echo "nogroup" >> safe-groups.tmp
echo "news" >> safe-groups.tmp
echo "netdev" >> safe-groups.tmp
echo "mlocate" >> safe-groups.tmp
echo "messagebus" >> safe-groups.tmp
echo "man" >> safe-groups.tmp
echo "mail" >> safe-groups.tmp
echo "lpadmin" >> safe-groups.tmp
echo "lp" >> safe-groups.tmp
echo "list" >> safe-groups.tmp
echo "lightdm" >> safe-groups.tmp
echo "kmem" >> safe-groups.tmp
echo "irc" >> safe-groups.tmp
echo "input" >> safe-groups.tmp
echo "gnats" >> safe-groups.tmp
echo "games" >> safe-groups.tmp
echo "floppy" >> safe-groups.tmp
echo "fax" >> safe-groups.tmp
echo "disk" >> safe-groups.tmp
echo "dip" >> safe-groups.tmp
echo "dialout" >> safe-groups.tmp
echo "daemon" >> safe-groups.tmp
echo "crontab" >> safe-groups.tmp
echo "colord" >> safe-groups.tmp
echo "clamav" >> safe-groups.tmp
echo "cdrom" >> safe-groups.tmp
echo "bluetooth" >> safe-groups.tmp
echo "bin" >> safe-groups.tmp
echo "backup" >> safe-groups.tmp
echo "avahi-autoipd" >> safe-groups.tmp
echo "avahi" >> safe-groups.tmp
echo "audio" >> safe-groups.tmp
echo "adm" >> safe-groups.tmp
echo "libuuid" >> safe-groups.tmp
echo "fuse" >> safe-groups.tmp
echo "utempter" >> safe-groups.tmp
echo "epmd" >> safe-groups.tmp
echo "redsocks" >> safe-groups.tmp
echo "i2c" >> safe-groups.tmp
echo "ntp" >> safe-groups.tmp
echo "stunnel4" >> safe-groups.tmp
echo "sslh" >> safe-groups.tmp
echo "arpwatch" >> safe-groups.tmp
echo "kismet" >> safe-groups.tmp
echo "inetsim" >> safe-groups.tmp
echo "kpadmins" >> safe-groups.tmp
echo "dradis" >> safe-groups.tmp
echo "xrdp" >> safe-groups.tmp
echo "rdma" >> safe-groups.tmp
echo "gluster" >> safe-groups.tmp
#echo "sudo" >> safe-groups.tmp



>/etc/group.tmp
sudo cp /etc/passwd /etc/group.old

echo "Press enter to begin editing groups..."
read continue
for line in `cat /etc/group`; do
  group=`echo $line | cut -d ':' -f 1`
  gid=`echo $line | cut -d ':' -f 3`
  currentMembers=`echo $line | cut -d ':' -f 4`
  if [ "$group" != "" ]; then
    safe=false
    check=false
    usergroup=false
    validGroup=y
    validMember=y
    members=""
    for entry in `cat safe-groups.tmp`; do
      if [ "$group" == "$entry" ]; then
        safe=true
        break
      fi
    done
    for entry in `cat safe-groups-users.tmp`; do
      if [ "$group" == "$entry" ]; then
        safe=true
        usergroup=true
        break
      fi
    done
    if [ "$safe" == "false" ]; then
      sudo echo "Is $group a valid group? (y/n):"
      read validGroup
      if [ "$validGroup" != "n" ]; then
        echo "$group approved as valid group."
        for member in `echo $currentMembers | sed 's/,/\n/g'`; do
          sudo echo "Is $member supposed to be a member of $group? (y/n):"
          read validMember
          if [ "$validMember" != "n" ]; then
            if [ "$members" == "" ]; then
              members=$member
            else
              members=`echo $members,$member`
            fi
            echo "$member approved as member of $group."
          else
            sudo deluser $member $group
            sudo gpasswd -d $member $group
            echo "$member removed from $group group"
          fi
        done
        echo "$group:x:$gid:$members" >> /etc/group.tmp
      else
        sudo groupdel $group
        echo "$group removed."
      fi
    else
      if [ "$usergroup" == "true" ]; then
        echo "$group:x:$gid:$group" >> /etc/group.tmp
      else
        echo "$group:x:$gid:$currentMembers" >> /etc/group.tmp
      fi
    fi
  fi
done

sudo mv -f /etc/group.tmp /etc/group

#Require password for all logins
sudo gpasswd nopasswdlogin -M ''


#Clear iptables firewall
sudo iptables --flush

#Configure UFW
sudo ufw enable
sudo ufw reset
sudo ufw logging
sudo sed -i -e 's/-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT/-A ufw-before-input -p icmp --icmp-type destination-unreachable -j DROP/g'  /etc/ufw/before.rules
sudo sed -i -e 's/-A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT/-A ufw-before-input -p icmp --icmp-type source-quench -j DROP/g'  /etc/ufw/before.rules
sudo sed -i -e 's/-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT/-A ufw-before-input -p icmp --icmp-type time-exceeded -j DROP/g'  /etc/ufw/before.rules
sudo sed -i -e 's/-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT/-A ufw-before-input -p icmp --icmp-type parameter-problem -j DROP/g'  /etc/ufw/before.rules
sudo sed -i -e 's/-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/-A ufw-before-input -p icmp --icmp-type echo-request -j DROP/g'  /etc/ufw/before.rules
sudo ufw reload
sudo ufw enable

#Dissable unneeded services
if [ "$ssh_allowed" == "y" ]; then
  sudo apt-get install -y openssh-server
  sudo /etc/init.d/ssh start
  sudo service ssh start
  sudo ufw allow 22
  sudo apt-get install -y fail2ban
  sudo /etc/init.d/fail2ban start
  sudo service fail2ban start
else
  sudo apt-get purge -y openssh-server
  sudo ufw deny 22
  sudo rm -f /etc/ssh/sshd_conf
  sudo apt-get purge -y fail2ban
fi
if [ "$rdp_allowed" == "y" ]; then
  sudo ufw allow 3389
  sudo dconf write /desktop/gnome/remote-access/enabled true
else
  sudo ufw deny 3389
  sudo dconf write /desktop/gnome/remote-access/enabled false
fi

#RDP Block
sudo dconf write /desktop/gnome/remote_access/prompt-enabled true
sudo dconf write /desktop/gnome/remote_access/lock-screen-on-disconnect true
sudo dconf write /desktop/gnome/remote_access/notify-on-connect true
sudo dconf write /desktop/gnome/remote_access/require-encryption true
sudo dconf write /desktop/gnome/remote_access/authentication-methods vnc
sudo dconf write /desktop/gnome/remote_access/use-upnp false

#SSH Block
sudo echo "AUTHORIZED USE ONLY.  UNAUTHORIZED USERS WILL BE PROSICUTED.  IF YOU ARE NOT AUTHORIZED TO ACCESS THIS SYSTEM, LOG OFF IMMIDIATLY." | sudo tee /etc/issue
echo "Version 2" | sudo tee /etc/ssh/sshd_conf.tmp
echo "Port 22" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AddressFamily any" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "ListenAddress 0.0.0.0" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "ListenAddress ::" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "RekeyLimit default none" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "SyslogFacility AUTH" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "LogLevel INFO" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "LoginGraceTime 120" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "HostKey " | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "ServerKeyBits 2048" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "KeyRegenerationInterval 300" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "StrictModes yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "MaxAuthTries 6" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "MaxSessions 10" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PubkeyAuthentication no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AuthorizedPrincipalsFile none" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AuthorizedKeysCommand none" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AuthorizedKeysCommandUser nobody" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "HostbasedAuthentication no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "HostbasedAuthentication no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "IgnoreUserKnownHosts yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "IgnoreRhosts yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PasswordAuthentication yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "UsePAM yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AllowAgentForwarding no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AllowTcpForwarding no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "GatewayPorts no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "X11Forwarding no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PermitTTY no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PrintMotd no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PrintLastLog no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "TCPKeepAlive no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "UseLogin yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PermitUserEnvironment no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "Compression delayed" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "ClientAliveInterval 300" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "ClientAliveCountMax 3" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "UseDNS no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PidFile /var/run/sshd.pid" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "MaxStartups 10:30:100" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "PermitTunnel no" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "ChrootDirectory none" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "VersionAddendum none" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "UsePrivilegeSeparation yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "VerifyReverseMapping yes" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "Banner /etc/issue" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "AcceptEnv LANG LC_*" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "Subsystem sftp internal-sftp" | sudo tee -a /etc/ssh/sshd_conf.tmp
echo "start on filesystem or runlevel [2345]" | sudo tee -a /etc/ssh/sshd_conf.tmp

sudo cp /etc/ssh/sshd_conf /etc/ssh/sshd_conf.old
sudo mv -f /etc/ssh/sshd_conf.tmp /etc/ssh/sshd_conf

if [ "$ssh_allowed" == "y" ]; then
  sudo service ssh restart
fi

#Change login banner
sudo echo "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" | sudo tee /etc/issue
sudo echo "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" | sudo tee /etc/issue.net
sudo echo "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" | sudo tee /etc/motd


#Media File Finder Block
echo "Finding user's media files..."

# Updates file database and scans all files and indexes file locations for said file types
sudo updatedb
sudo touch mediafiles.log
sudo find /home -regex .*.mp3 > mediafiles.log
sudo find /home -regex .*.mp4 >> mediafiles.log
sudo find /home -regex .*.jpg >> mediafiles.log
sudo find /home -regex .*.jpeg >> mediafiles.log
sudo find /home -regex .*.png >> mediafiles.log
sudo find /home -regex .*.bmp >> mediafiles.log
sudo find /home -regex .*.ac3 >> mediafiles.log
sudo find /home -regex .*.aac >> mediafiles.log
sudo find /home -regex .*.flac >> mediafiles.log
sudo find /home -regex .*.m4a >> mediafiles.log
sudo find /home -regex .*.midi >> mediafiles.log
sudo find /home -regex .*.vqf >> mediafiles.log
sudo find /home -regex .*.m3u >> mediafiles.log
sudo find /home -regex .*.m4p >> mediafiles.log
sudo find /home -regex .*.mp3 >> mediafiles.log
sudo find /home -regex .*.mp2 >> mediafiles.log
sudo find /home -regex .*.mpeg >> mediafiles.log
sudo find /home -regex .*.wav >> mediafiles.log
sudo find /home -regex .*.aup >> mediafiles.log
sudo find /home -regex .*.wma >> mediafiles.log
sudo find /home -regex .*.wav >> mediafiles.log
sudo find /home -regex .*.ogg >> mediafiles.log
sudo find /home -regex .*.gif >> mediafiles.log
sudo find /home -regex .*.avi >> mediafiles.log
sudo find /home -regex .*.m1v >> mediafiles.log
sudo find /home -regex .*.m2v >> mediafiles.log
sudo find /home -regex .*.flv >> mediafiles.log
sudo find /home -regex .*.mov >> mediafiles.log
sudo find /home -regex .*.mng >> mediafiles.log
sudo find /home -regex .*.umx >> mediafiles.log
sudo find /home -regex .*.gcf >> mediafiles.log
sudo find /home -regex .*.map >> mediafiles.log
sudo find /home -regex .*.exe >> mediafiles.log
echo "Opening list of all media files found."
echo "Take note and then close file to delete them."
sudo gedit mediafiles.log
echo "Press enter to delete all files..."
read $done

while IFS= read -r mediafile; do
  rm "$mediafile"
done < mediafiles.log
echo "All media files deleted."

clear
#echo "Opening a list of all cron jobs, please take note and then close gedit..."
#sudo gedit cronjobs.log

clear
#echo "Displaying list of all manually installed packages..."
#sudo comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) > installed-packages.txt
#sudo gedit installed-packages.txt
echo "Displaying list of commands executed to install packages...(this is actaully important)"
(zcat $(ls -tr /var/log/apt/history.log*.gz); cat /var/log/apt/history.log) 2>/dev/null | egrep '^(Start-Date:|Commandline:)' | grep -v aptdaemon | egrep -B1 '^Commandline:' > install-commands.txt
#sudo gedit install-commands.txt

clear
echo "Scanning system with ClamAV, this will take several minutes..."
sudo clamscan -r -i --remove --exclude-dir="^/sys" /

echo "Auditing system with lynis and recording results in log file.  This will take several minutes..."
sudo lynis -c -Q > lynis-log.txt

echo "Script complete.  Please follow the following checklist to configure additional security, and press enter after each step is completed."
echo ""
echo ""
echo " 1) Re-read the README"
read continue
echo " 2) Finish any tasks required by README (Create new users/groups, install software, etc.)"
read continue
echo " 3) Open Firefox, click on the menu button in the top right corner, click on the question mark at the bottom of the menu, and allow firefox to update.  Once firefox restarts, keep checking for updates until it says that firefox is up to date."
read continue
echo " 4) Open Firefox, click on the menu button in the top right corner, click on \"Options\", and ensure the following options are set:"
echo "      a) Enable \"Always check if Firefox is your default browser\""
read continue
echo "      b) When Firefox starts - Show your home page"
read continue
echo "      c) Homepage - www.google.com"
read continue
echo "      d) Downloads - Save files to Downloads"
read continue
echo "      e) Applications - Make sure all lines are set to \"Always Ask\""
read continue
echo "      f) Updates"
echo "          a) Click \"Check for Updates\" - If updates are downloaded, restart Firefox and repeat until it says Firefox is up to date"
read continue
echo "          b) Enable \"Use a background service to install updates\""
read continue
echo "          c) Enable \"Automatically update search engines\""
read continue
echo "          d) Set \"Allow Firefox to Automatically install updates\""
read continue
echo "      g) Enable \"Use recommended performance settings\""
read continue
echo "      h) Network Prox (Click \"Settings\")"
read continue
echo "          a) Select \"Use system proxy settings\" and click \"OK\""
read continue
echo "      i) Search (Click the search icon on the left sidebar)"
read continue
echo "          a) Set the default search engine to Google"
read continue
echo "          b) Remove all search engines from the list except for Google"
read continue
echo "      j) Security (Click the lock icon on the left sidebar)"
read continue
echo "          a) Disable \"Remember logins and passwords for websites\""
read continue
echo "          b) Disable \"Use a master password\""
read continue
echo "          c) Click \"Saved Logins", click "Remove All\" if there are any entries, then \"Save Changes\""
read continue
echo "          d) Set History to \"Never remember history\", and restart firefox.  Return to the security settings menu."
read continue
echo "          e) Cached Web Content - Click \"Clear Now\""
read continue
echo "          f) Disable \"Override automatic cache management\""
read continue
echo "          g) Site Data - Click "Clear All Data""
read continue
echo "          h) Set Tracking Protection to \"Always\""
read continue
echo "          i) Click "Exceptions", click \"Remove All Websites\" if there are any entries, then \"Save Changes\""
read continue
echo "          j) Set \"Send Websites \'Do Not Track\' signals\" to \"Always\""
read continue
echo "          k) In the \"Permissions\" section, go through all the sections, clicking \"Settings\", \"Remove All Websites\", and \"Save Changes\""
read continue
echo "          l) Enable \"Block pop-up windows\""
read continue
echo "          m) Enable \"Warn you when websites try to install add-ons\""
read continue
echo "          n) For both of the two options above, click \"Exceptions\" and remove any exceptions."
read continue
echo "          o) Enable \"Prevent accessability services from accessing your browser\""
read continue
echo "          p) Enable \"Block dangerous and deceptive content\""
read continue
echo "          q) Enable \"Block dangerous downloads\""
read continue
echo "          r) Enable \"Warn you about unwanted and uncommon software\""
read continue
echo "          s) In \"Certificates\", select \"Ask you every time\""
read continue
echo "          t) Enable \"Query OCSP responder servers to confirm the current validity of certificates\""
read continue
echo "          u) Click \"View Certificates\", and delete any entries in the \"Your Certificates\", \"People\", and \"Others\" sections"
read continue
echo " 5) Write down the username for the account you are currently logged into (as per the README)"
read continue
echo " 6) Read through the lynis report located at lynis-log.txt, and perform any relevant recommended actions, press enter to open the file..."
read continue
sudo gedit lynis-log.txt
echo "  Press enter to continue..."
read continue
echo " 7) Read through the apt-get report located at install-commands.txt and look specifically for any malicious or unnecessary programs installed prior to the competition date, press enter to open the file..."
read continue
sudo gedit install-commands.txt
echo "  Press enter to continue..."
read continue
echo " 8) Read through the list of cronjobs located at cronjobs.log and remove any that aren't required using the command crontab -e, press enter to open the file..."
read continue
sudo gedit cronjobs.log
echo "  Press enter to continue..."
if [ "$mysql_allowed" == "y" ]; then
  echo " 8.5) If mySQL is allowed, check the current users and set their passwords using these commands:"
  echo "   a. mysql -u root -p"
  echo "   b. SELECT User, Host, Password FROM mysql.user; -- Lists all users"
  echo "   c. DROP USER username; -- Delete user"
  echo "   d. CREATE USER username; -- Create user"
  echo "   e. ALTER USER 'username'@'localhost' IDENTIFIED BY 'newpassword'; -- Sets password for user"
  echo "Press enter to continue..."
  read continue
fi
echo " 9) Re-read the README"
read continue
echo " 10) Reboot"
echo ""
echo "  ---END OF INSTRUCTIONS---"
read continue
























