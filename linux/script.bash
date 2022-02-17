#!/bin/bash




echo "Starting Linux Script"

password="D0gsD0gsD0gs!!!!"
echo Our password is $password

#Create script log file (for debuging)
echo "Linux Script Log File" > script-log.log


##### Running critical security commands

# Secure Root
echo "Securing root account..."
sudo dpkg-statoverride --update --add root sudo 4750 /bin/su
sudo cp /etc/securetty /etc/securetty.old
sudo truncate -s 0 /etc/securetty

#Dissable root and guest account login
sudo passwd -l root
sudo passwd -l guest

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


#Change login banner
sudo echo "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" | sudo tee /etc/issue
sudo echo "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" | sudo tee /etc/issue.net
sudo echo "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" | sudo tee /etc/motd




#### Configure special services

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