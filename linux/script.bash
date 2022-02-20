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
echo root > /etc/cron.allow
echo root > /etc/at.allow
sudo chown root:root /etc/cron.allow /etc/at.allow
sudo chmod 400 /etc/cron.allow /etc/at.allow



#Telnet
sudo service telnet stop &> /dev/null
sudo echo manual | sudo tee /etc/init/telnet.override &> /dev/null
#rLogin
sudo service rlogin stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rlogin.override &> /dev/null
#rExec
sudo service rexec stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rexec.override &> /dev/null
sudo service rexec stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rexec.override &> /dev/null
#Automount
sudo service automount stop &> /dev/null
sudo echo manual | sudo tee /etc/init/automount.override &> /dev/null
#Name Server
sudo service named stop &> /dev/null
sudo echo manual | sudo tee /etc/init/named.override &> /dev/null
#rSH (remote shell)
sudo service rsh stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rsh.override &> /dev/null
#finger
sudo service finger stop &> /dev/null
sudo echo manual | sudo tee /etc/init/finger.override &> /dev/null
#netdump
sudo service netdump stop &> /dev/null
sudo echo manual | sudo tee /etc/init/netdump.override &> /dev/null
#nfs
sudo service nfs stop &> /dev/null
sudo echo manual | sudo tee /etc/init/nfs.override &> /dev/null
sudo service nfs-kernel-server stop &> /dev/null
sudo echo manual | sudo tee /etc/init/nfs-kernel-server.override &> /dev/null
sudo apt-get purge -y nfs-kernel-server nfs-common portmap &> /dev/null
#rwhod
sudo service rwhod stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rwhod.override &> /dev/null
#yppasswdd
sudo service yppasswdd stop &> /dev/null
sudo echo manual | sudo tee /etc/init/yppasswdd.override &> /dev/null
#ypserv
sudo service ypserv stop &> /dev/null
sudo echo manual | sudo tee /etc/init/ypserv.override &> /dev/null
#ypxfrd
sudo service ypxfrd stop &> /dev/null
sudo echo manual | sudo tee /etc/init/ypxfrd.override &> /dev/null
#rsh
sudo service rsh stop &> /dev/null
sudo echo manual | sudo tee /etc/init/rsh.override &> /dev/null
#portmap
sudo service portmap stop &> /dev/null
sudo echo manual | sudo tee /etc/init/portmap.override &> /dev/null


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
echo "tss" >> safe-users.tmp
echo "tcpdump" >> safe-users.tmp
echo "systemd-coredump" >> safe-users.tmp
echo "pollinate" >> safe-users.tmp
echo "nm-openvpn" >> safe-users.tmp
echo "lxd" >> safe-users.tmp
echo "landscape" >> safe-users.tmp
echo "gnome-initial-setup" >> safe-users.tmp
echo "geoclue" >> safe-users.tmp
echo "gdm" >> safe-users.tmp
echo "cups-pk-helper" >> safe-users.tmp





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
          sudo echo -e "$password\n$password" | (sudo passwd $usr) > /dev/null 2>&1
          sudo chage -E -1 -m 5 -M 60 -I 10 -W 14 $usr > /dev/null 2>&1
          sudo crontab -u $usr -l >> cronjobs.log 2>&1
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
        sudo crontab -u $usr -l >> cronjobs.log 2>/dev/null
        sudo echo "$usr    ALL=(ALL:ALL) ALL" | sudo tee -a /etc/sudoers.tmp
        sudo adduser $usr sudo > /dev/null 2>&1
        sudo gpasswd -a $usr sudo > /dev/null 2>&1
        
        homedir="/home/$usr"
        usrshell="/bin/bash"
        echo "$usr:x:$uid:$gid:$name:$homedir:$usrshell" | sudo tee -a /etc/passwd.tmp
        
        echo "$usr" >> safe-groups-users.tmp
      fi
    else
      sudo crontab -u $usr -l >> cronjobs.log2>/dev/null
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
echo "kvm" >> safe-groups.tmp
echo "render" >> safe-groups.tmp
echo "tss" >> safe-groups.tmp
echo "tcpdump" >> safe-groups.tmp
echo "landscape" >> safe-groups.tmp
echo "lxd" >> safe-groups.tmp
echo "systemd-coredump" >> safe-groups.tmp
echo "nm-openvpn" >> safe-groups.tmp
echo "geoclue" >> safe-groups.tmp
echo "gdm" >> safe-groups.tmp
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

if [ "$ssh_allowed" == "y" ]; then
  sudo cp /etc/ssh/sshd_conf /etc/ssh/sshd_conf.old
  sudo mv -f /etc/ssh/sshd_conf.tmp /etc/ssh/sshd_conf
  sudo service ssh restart
fi
