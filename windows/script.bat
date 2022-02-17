
@echo off
setlocal enabledelayedexpansion enableextensions
cls

::Open script fullscreen
mode con: cols=150 lines=10000
if not "%1"=="max" start /MAX cmd /c %0 max & exit/b

::Variable Assignments

set our_password=D0gsD0gsD0gs!!!!

echo Our password is %our_password%
echo|set/p=%our_password%|clip
echo Password copied to clipboard


::Detect current version of Windows
for /f "tokens=4-5 delims=. " %%i in ('ver') do set version=%%i.%%j

set windows7=n
set windows81=n
set windows2016=n

if /I "!version!"=="6.1" (
    set windows7=y
    echo Windows 7 Detected
) else (
    if /I "!version!"=="6.3" (
        set windows81=y
        echo Windows 8.1 Detected
    ) else (
        if /I "!version!"=="10.0" (
            set windows2016=y
            echo Windows 2016 Detected
        )
    )
)



::Check to make sure script is being run with Administrator priviliges
net sessions > NUL
if not %errorlevel%==0 (
	echo You are not running this script as Administrator, so it will not work properly.
	echo Please close the command prompt window, right click on its icon, select 'Run as Administrator', and run the script again.
	echo It is possible that this is a false alarm, if so, you may press enter and continue the script.
	pause
)



echo Script starting...
echo.
echo Please answer the following questions according to the README.
echo If the README does not specifically state that a certain program or service is required,
echo then answer "n" to that question.
echo.
echo.

set /p allowRDP=Is Remote Desktop Required? (y/n^)
set /p allowIIS=Is IIS (Internet Information Services) Web Server required? (y/n^)
set /p allowDC=Is Active Directory Domain Controller required? (y/n^)

::Create GodMode Shortcut in C drive
mkdir C:\GodMode
mkdir C:\GodMode\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C} > NUL

::Enable Windows Auto Update
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UseWUServer /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UseWUServer /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UseWUServer /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForDownloadLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForDownloadLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForDownloadLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForInstallLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForInstallLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForInstallLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiOrEulaLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiOrEulaLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiOrEulaLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ForcedReboot /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ForcedReboot /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ForcedReboot /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UseWUServer /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UseWUServer /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UseWUServer /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v RescheduleWaitTime /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ElevateNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForDownloadLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForDownloadLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForDownloadLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForInstallLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForInstallLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableForInstallLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiOrEulaLogin /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiOrEulaLogin /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v UpdatesAvailableWithUiOrEulaLogin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ForcedReboot /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ForcedReboot /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsUpdate\Auto Update" /v ForcedReboot /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f


net start wuauserv > NUL
sc config wuauserv start= auto > NUL
echo Update Configured.

::Update Windows
C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate

::Setup Windows Defender and begin scan
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RestoreDefaults
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Quarantine" /v PurgeItemsAfterDelay /t REG_DWORD /d 30 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Quarantine" /v PurgeItemsAfterDelay /t REG_DWORD /d 30 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Quarantine" /v PurgeItemsAfterDelay /t REG_DWORD /d 30 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Scan" /v DisableRemovableDriveScanning /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Scan" /v DisableRemovableDriveScanning /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Scan" /v DisableRemovableDriveScanning /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Scan" /v DisableRestorePoint /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Scan" /v DisableRestorePoint /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Scan" /v DisableRestorePoint /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Scan" /v MeasureBootEnabled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Scan" /v MeasureBootEnabled /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Scan" /v MeasureBootEnabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Scan" /v SFCState /t REG_DWORD /d 7 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Scan" /v SFCState /t REG_DWORD /d 7 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Scan" /v SFCState /t REG_DWORD /d 7 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Scan" /v CheckForSignaturesBeforeRunningScan /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Scan" /v CheckForSignaturesBeforeRunningScan /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Scan" /v CheckForSignaturesBeforeRunningScan /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\Signiture Updates" /v DisableDefaultSigs /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\Signiture Updates" /v DisableDefaultSigs /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\Signiture Updates" /v DisableDefaultSigs /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Defender\UX Configuration" /v DisablePrivacyMode /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Defender\UX Configuration" /v DisablePrivacyMode /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Windows Defender\UX Configuration" /v DisablePrivacyMode /t REG_DWORD /d 0 /f
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan 2

::Disable default accounts
net user Administrator /active:NO > NUL
net user Guest /active:NO > NUL
net user DefaultAccount /active:NO > NUL
net user defaultaccount0 /active:NO > NUL
echo Default accounts dissabled.

::Remove saved credentials
cmdkey.exe /list > "creds.tmp"
findstr.exe Target "creds.tmp" > "tokens.tmp"
for /F "tokens=1,2 delims= " %%g in (tokens.tmp) do cmdkey.exe /delete:%%g

::Set best practice Windows account settings
net accounts /forcelogoff:60 /minpwlen:8 /maxpwage:30 /minpwage:10 /lockoutthreshold:6 /lockoutwindow:30 /lockoutduration:30 /uniquepw:6 > NUL

::Change name of default Administrator and Guest accounts
wmic useraccount where name='Administrator' call rename name='RandomUser'
wmic useraccount where name='Guest' call rename name='AnotherUser'
wmic useraccount where name='DefaultAccount' call rename name='AnotherUser2'
wmic useraccount where name='defaultaccount0' call rename name='AnotherUser3'

::Use secedit.exe to secure Windows account settings
echo [Unicode] > security-policy.inf
echo Unicode=yes >> security-policy.inf
echo [System Access] >> security-policy.inf
echo MinimumPasswordAge = 10 >> security-policy.inf
echo MaximumPasswordAge = 30 >> security-policy.inf
echo MinimumPasswordLength = 8 >> security-policy.inf
echo PasswordComplexity = 1 >> security-policy.inf
echo PasswordHistorySize = 10 >> security-policy.inf
echo LockoutBadCount = 6 >> security-policy.inf
echo ResetLockoutCount = 30 >> security-policy.inf
echo LockoutDuration = 30 >> security-policy.inf
echo RequireLogonToChangePassword = 0 >> security-policy.inf
echo ForceLogoffWhenHourExpire = 1 >> security-policy.inf
echo NewAdministratorName = "RandomUser" >> security-policy.inf
echo NewGuestName = "AnotherUser" >> security-policy.inf
echo ClearTextPassword = 0 >> security-policy.inf
echo LSAAnonymousNameLookup = 0 >> security-policy.inf
echo EnableAdminAccount = 0 >> security-policy.inf
echo EnableGuestAccount = 0 >> security-policy.inf
echo [Event Audit] >> security-policy.inf
echo AuditSystemEvents = 3 >> security-policy.inf
echo AuditLogonEvents = 3 >> security-policy.inf
echo AuditObjectAccess = 3 >> security-policy.inf
echo AuditPrivilegeUse = 3 >> security-policy.inf
echo AuditPolicyChange = 3 >> security-policy.inf
echo AuditAccountManage = 3 >> security-policy.inf
echo AuditProcessTracking = 3 >> security-policy.inf
echo AuditDSAccess = 3 >> security-policy.inf
echo AuditAccountLogon = 3 >> security-policy.inf
echo [Registry Values] >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms=1,"1" >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0" >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies=1,"1" >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"10" >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,5 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"0" >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId=4,3 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System"," LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.*** >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,1 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon=4,0 >> security-policy.inf
echo MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures=4,1 >> security-policy.inf
echo MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection=4,2 >> security-policy.inf
echo MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=3,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,536870912 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,536870912 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl=4,/ >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine=7, >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine=7, >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional=7,Posix >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect=4,15 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7, >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7, >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=4,0 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge=4,30 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel=4,1 >> security-policy.inf
echo MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2 >> security-policy.inf
echo [Privilege Rights] >> security-policy.inf
echo SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551 >> security-policy.inf
echo SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551 >> security-policy.inf
echo SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551 >> security-policy.inf
echo SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544 >> security-policy.inf
echo SeCreatePagefilePrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeDebugPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeRemoteShutdownPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeAuditPrivilege = *S-1-5-19,*S-1-5-20 >> security-policy.inf
echo SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544 >> security-policy.inf
echo SeIncreaseBasePriorityPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeLoadDriverPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559 >> security-policy.inf
echo SeServiceLogonRight = *S-1-5-80-0 >> security-policy.inf
echo SeInteractiveLogonRight = *S-1-5-32-545,*S-1-5-32-551,*S-1-5-32-544 >> security-policy.inf
echo SeSecurityPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeSystemEnvironmentPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeProfileSingleProcessPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420 >> security-policy.inf
echo SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20 >> security-policy.inf
echo SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551 >> security-policy.inf
echo SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551 >> security-policy.inf
echo SeTakeOwnershipPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeDenyNetworkLogonRight = Guest >> security-policy.inf
echo SeDenyInteractiveLogonRight = Guest >> security-policy.inf
echo SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545 >> security-policy.inf
echo SeManageVolumePrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555 >> security-policy.inf
echo SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6 >> security-policy.inf
echo SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6 >> security-policy.inf
echo SeIncreaseWorkingSetPrivilege = *S-1-5-32-545 >> security-policy.inf
echo SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545 >> security-policy.inf
echo SeCreateSymbolicLinkPrivilege = *S-1-5-32-544 >> security-policy.inf
echo SeDenyBatchLogonRight = >> security-policy.inf
echo [Version] >> security-policy.inf
echo signature="$CHICAGO$" >> security-policy.inf
echo Revision=1 >> security-policy.inf

secedit.exe /configure /db secedit.sdb /cfg security-policy.inf /quite
del security-policy.inf

echo Account settings secured.


::Clear DNS and host files
ipconfig /flushdns
attrib -r -s C:\Windows\system32\drivers\etc\hosts
attrib -r -s C:\Windows\system32\drivers\etc\lmhosts.sam
echo NUL > C:\Windows\system32\drivers\etc\hosts
echo NUL > C:\Windows\system32\drivers\etc\lmhosts.sam
attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts
attrib +r +s C:\Windows\system32\drivers\etc\lmhosts.sam
echo "loopback                 127" > C:\Windows\system32\drivers\etc\networks
echo "ip         0     IP           # Internet protocol" > C:\Windows\system32\drivers\etc\protocols
echo "icmp       1     ICMP         # Internet control message protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "ggp        3     GGP          # Gateway-gateway protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "tcp        6     TCP          # Transmission control protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "egp        8     EGP          # Exterior gateway protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "pup        12    PUP          # PARC universal packet protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "udp        17    UDP          # User datagram protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "hmp        20    HMP          # Host monitoring protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "xns-idp    22    XNS-IDP      # Xerox NS IDP" >> C:\Windows\system32\drivers\etc\protocols
echo "rdp        27    RDP          # reliable datagram protocol" >> C:\Windows\system32\drivers\etc\protocols
echo "ipv6-route 43    IPv6-Route   # Routing header for IPv6" >> C:\Windows\system32\drivers\etc\protocols
echo "ipv6-frag  44    IPv6-Frag    # Fragment header for IPv6" >> C:\Windows\system32\drivers\etc\protocols
echo "esp        50    ESP          # Encapsulating security payload" >> C:\Windows\system32\drivers\etc\protocols
echo "ah         51    AH           # Authentication header" >> C:\Windows\system32\drivers\etc\protocols
echo "ipv6-icmp  58    IPv6-ICMP    # ICMP for IPv6" >> C:\Windows\system32\drivers\etc\protocols
echo "ipv6-nonxt 59    IPv6-NoNxt   # No next header for IPv6" >> C:\Windows\system32\drivers\etc\protocols
echo "ipv6-opts  60    IPv6-Opts    # Destination options for IPv6" >> C:\Windows\system32\drivers\etc\protocols
echo "rvd        66    RVD          # MIT Remote virtual disk" >> C:\Windows\system32\drivers\etc\protocols
echo Host file flushed.





::Ensure services are disabled
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PlugPlay" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\PlugPlay" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\PlugPlay" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RIP" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LDP" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LDP" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RpcLocator" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\RpcSs" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\RpcSs" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v MiximumPasswordAge /t REG_DWORD /d 15 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v MiximumPasswordAge /t REG_DWORD /d 15 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v MiximumPasswordAge /t REG_DWORD /d 15 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePassword /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePassword /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePassword /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" /v Update /t REG_SZ /d yes /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\Netlogon\Parameters" /v Update /t REG_SZ /d yes /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\Netlogon\Parameters" /v Update /t REG_SZ /d yes /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBIOS" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\NetBIOS" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\NetBIOS" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RemoteAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\RemoteAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\RemoteAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\SharedAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\SharedAccess" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\smphost" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\smphost" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\smphost" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SNMPTRAP" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\SNMPTRAP" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\SNMPTRAP" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SupportAssistAgent" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\SupportAssistAgent" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\SupportAssistAgent" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 2 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 2 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AdjustNullSessionPipes /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AdjustNullSessionPipes /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AdjustNullSessionPipes /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableAuthenticateUserSharing /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableAuthenticateUserSharing /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableAuthenticateUserSharing /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v enableforcedlogoff /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v enableforcedlogoff /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v enableforcedlogoff /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v enablesecuritysigniture /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v enablesecuritysigniture /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v enablesecuritysigniture /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v requiresecuritysigniture /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v requiresecuritysigniture /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v requiresecuritysigniture /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v restrictnullsessaccess /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v restrictnullsessaccess /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v restrictnullsessaccess /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnablePlainTextPassword  /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnablePlainTextPassword  /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnablePlainTextPassword  /t REG_DWORD /d 0 /f
echo Vulnerable Services Disabled



::Enable Firewall ( Reduntant - Making sure it will work on all networks)
netsh advfirewall set currentprofile state on > NUL
netsh advfirewall set domainprofile state on > NUL
netsh advfirewall set privateprofile state on > NUL
netsh advfirewall set publicprofile state on > NUL
netsh advfirewall set allprofiles state on > NUL
echo Firewall enabled.




::Set up Firewall
netsh advfirewall reset
if /I "!allowRDP!"=="Y" (
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no > NUL
) else (
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=yes > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=yes > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=yes > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=yes > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=yes > NUL
	netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=yes > NUL	
)

netsh advfirewall firewall set rule name="Telnet Server" new enable=no > NUL
netsh advfirewall firewall set rule name="netcat" new enable=no > NUL
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No > NUL
echo Firewall set up.




::Enable Do Not Track on all browsers
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
echo Do Not Track enabled.

::Secure RDP
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Remote Assistance" /v CreateEncryptedOnlyTickets /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Remote Assistance" /v CreateEncryptedOnlyTickets /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Remote Assistance" /v CreateEncryptedOnlyTickets /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Remote Assistance" /v MaxTicketExpiry /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Remote Assistance" /v MaxTicketExpiry /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Remote Assistance" /v MaxTicketExpiry /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Remote Assistance" /v MaxTicketExpiryUnits /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Remote Assistance" /v MaxTicketExpiryUnits /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Remote Assistance" /v MaxTicketExpiryUnits /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyChildConnections /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v fDenyChildConnections /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v fDenyChildConnections /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v DelayConMgrTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v DelayConMgrTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v DelayConMgrTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v DeleteTempDirsOnExit /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v DeleteTempDirsOnExit /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v DeleteTempDirsOnExit /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v GlassSessionId /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v GlassSessionId /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v GlassSessionId /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v NotificationTimeOut /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v NotificationTimeOut /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v NotificationTimeOut /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v PerSessionTempDir /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v PerSessionTempDir /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v PerSessionTempDir /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v DeleteTempDirsOnExit /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v DeleteTempDirsOnExit /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v DeleteTempDirsOnExit /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Assitance\Client\1.0\Settings" /v GlobalOnlineAssist /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Assitance\Client\1.0\Settings" /v GlobalOnlineAssist /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Assitance\Client\1.0\Settings" /v GlobalOnlineAssist /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Assitance\Client\1.0\Settings" /v GlobalIMpl /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Assitance\Client\1.0\Settings" /v GlobalIMpl /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Assitance\Client\1.0\Settings" /v GlobalIMpl /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicitedFullControl /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicitedFullControl /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicitedFullControl /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\COM3" /v RemoteAccessEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\COM3" /v RemoteAccessEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\COM3" /v RemoteAccessEnabled /t REG_DWORD /d 0 /f

if /I "!allowRDP!"=="Y" (
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Opening configuration GUI. Select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)" and click apply and close.
	start SystemPropertiesRemote.exe /wait
) else (
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
)

::Enable Auditing
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
echo Auditing enabled.

::Unhide all files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
echo Hidden files exposed.




echo Setting registry settings...

::Set best practice Registry settings
::Restrict CD ROM access
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
:: Automatic Admin logon
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
:: Logon message text
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText /t REG_SZ /d "***NOTICE: IF YOU DO NOT HAVE AUTHORIZATION TO ACCESS THIS System, LOGOFF IMMIDIATLY.  LEGAL ACTION WILL BE TAKEN AGAINST VIOLATORS.***" /f
:: Logon message title bar
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Authorized Use Only" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Authorized Use Only" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Authorized Use Only" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Authorized Use Only" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Authorized Use Only" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d "Authorized Use Only" /f
:: Wipe page file from shutdown
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
:: Block remote access to floppy disks
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
:: Prevent print driver installs 
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
:: Auditing access of Global System Objects
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
:: Auditing Backup and Restore
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
:: Do not display last user on logon
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v dontdisplaylastusername /t REG_DWORD /d 1 /f
:: UAC setting (Prompt on Secure Desktop)
if "n"=="n" (
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
)
:: Enable Installer Detection
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f
:: Undock without logon
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v undockwithoutlogon /t REG_DWORD /d 0 /f
:: Maximum Machine Password Age
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 15 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 15 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 15 /f
:: Disable machine account password changes
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f
:: Require Strong Session Key
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\Netlogon\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f
:: Require Sign/Seal
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
:: Sign Channel
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
:: Seal Channel
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
:: Restrict use of blank passwords to console login only
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
:: Don't disable CTRL+ALT+DEL
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f 
:: Restrict Anonymous Enumeration #1
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f 
:: Restrict Anonymous Enumeration #2
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f 
:: Idle Time Limit - 60 mins
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 60 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 60 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\LanmanServer\Parameters" /v autodisconnect /t REG_DWORD /d 60 /f 
:: Require Security Signature - Disabled pursuant to checklist
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\LanmanServer\Parameters" /v enablesecuritysignature /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\LanmanServer\Parameters" /v enablesecuritysignature /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\LanmanServer\Parameters" /v enablesecuritysignature /t REG_DWORD /d 0 /f 
:: Enable Security Signature
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\LanmanServer\Parameters" /v requiresecuritysignature /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\LanmanServer\Parameters" /v requiresecuritysignature /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\LanmanServer\Parameters" /v requiresecuritysignature /t REG_DWORD /d 0 /f 
:: Disable Domain Credential Storage
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f 
:: Don't Give Anons Everyone Permissions
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
:: SMB Passwords unencrypted to third party?
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
:: Null Session Pipes Cleared
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
:: Remotely accessible registry paths cleared
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "" /f
:: Remotely accessible registry paths and sub-paths cleared
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "" /f
:: Restict anonymous access to named pipes and shares
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f
:: Allow to use Machine ID for NTLM
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 0 /f
:: Smart Screen for IE8
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
:: Smart Screen for IE9+
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 2 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 2 /f
:: Windows Explorer Settings
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\AuthHost\IE Settings\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\AuthHost\IE Settings\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\AuthHost\IE Settings\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\AuthHost\IE Settings\Main" /v DEPOff /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\AuthHost\IE Settings\Main" /v DEPOff /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\AuthHost\IE Settings\Main" /v DEPOff /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f
:: Disable Dump file creation
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
:: Disable Autorun
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\CDROM" /v AutoRun /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Services\CDROM" /v AutoRun /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Services\CDROM" /v AutoRun /t REG_DWORD /d 1 /f
:: Disabled Internet Explorer Password Caching
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
:: Configure Digitally Signed Certificates on Source
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\MSMQ\Parameters\Security" /v SendMsgAuthn /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\MSMQ\Parameters\Security" /v SendMsgAuthn /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\MSMQ\Parameters\Security" /v SendMsgAuthn /t REG_DWORD /d 1 /f
:: Configure Digitally Signed Certificates on Target
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\MSMQ\Parameters\Security" /v RcvOnlyEnhMsgAuthn /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\MSMQ\Parameters\Security" /v RcvOnlyEnhMsgAuthn /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\MSMQ\Parameters\Security" /v RcvOnlyEnhMsgAuthn /t REG_DWORD /d 1 /f
:: Dissable StickyKeys
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
:: Dissable FilterKeys
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\FilterKeys" /v Flags /t REG_SZ /d 122 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\FilterKeys" /v Flags /t REG_SZ /d 122 /f
:: Dissable ToggleKeys
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
:: Restrict Access to the Registry
::reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f
::reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f
::Enable Auto-Repair
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Active Setup" /v DisableRepair /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Active Setup" /v DisableRepair /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\Active Setup" /v DisableRepair /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\Active Setup" /v DisableRepair /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\Active Setup" /v DisableRepair /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\Active Setup" /v DisableRepair /t REG_DWORD /d 0 /f
::Enable Enhanced Storage Devices
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Enhanced Storage Devices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Enhanced Storage Devices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Enhanced Storage Devices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Enhanced Storage Devices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Enhanced Storage Devices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Enhanced Storage Devices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f
::Enable Authentication code for...Something???
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Enhanced Storage Devices\Safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Enhanced Storage Devices\Safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Enhanced Storage Devices\Safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Enhanced Storage Devices\Safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Enhanced Storage Devices\Safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Enhanced Storage Devices\Safer\codeidentifiers" /v authenticodeenabled /t REG_DWORD /d 1 /f
::Dissable Shared Access Connections
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Network\SharedAccessConnection" /v EnableControl /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\System\CurrentControlSet\Control\Network\SharedAccessConnection" /v EnableControl /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\System\CurrentControlSet\Control\Network\SharedAccessConnection" /v EnableControl /t REG_DWORD /d 0 /f
::Disable Picture Passwords
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\System" /v BlockDomainPicturePassword /t REG_DWORD /d 1 /f
::Scan Attachments... not sure which attachments?
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
::Disable install with elevated permission
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
::Disable login before group policy loads
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SynchronousMachineGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SynchronousMachineGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SynchronousMachineGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SynchronousUserGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SynchronousUserGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SynchronousUserGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SynchronousMachineGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SynchronousMachineGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SynchronousMachineGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SynchronousUserGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SynchronousUserGroupPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SynchronousUserGroupPolicy /t REG_DWORD /d 0 /f
::Clear history of recently opened documents on exit
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v ClearRecentDocsOnExit /t REG_DWORD /d 1 /f
::Enable Advanced Tab of System Properties
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v DisableAdvanced /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v DisableAdvanced /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v DisableAdvanced /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections" /v NC_AdvancedSettings /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Network Connections" /v NC_AdvancedSettings /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Network Connections" /v NC_AdvancedSettings /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Task Scheduler5.0" /v DisableAdvanced /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Task Scheduler5.0" /v DisableAdvanced /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Task Scheduler5.0" /v DisableAdvanced /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Network Connections" /v NC_AdvancedSettings /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Network Connections" /v NC_AdvancedSettings /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Network Connections" /v NC_AdvancedSettings /t REG_DWORD /d 1 /f
::Verify all settings are accessible
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoComponents /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoComponents /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v NoComponents /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\ActiveDesktop" /v NoComponents /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\ActiveDesktop" /v NoComponents /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\ActiveDesktop" /v NoComponents /t REG_DWORD /d 0 /f
::Verify Windows Update is not disabled
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoWindowsUpdate /t REG_DWORD /d 0 /f
::Verify the Shut Down button is available
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 0 /f
::Verify ADM Updates are enabled
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy Editor" /v DisableAutoADMUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Group Policy Editor" /v DisableAutoADMUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Group Policy Editor" /v DisableAutoADMUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Group Policy Editor" /v DisableAutoADMUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Group Policy Editor" /v DisableAutoADMUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Group Policy Editor" /v DisableAutoADMUpdate /t REG_DWORD /d 0 /f
::Disable Autoplay
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
::Verify users can change their passwords
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
::Verify Control Panel is enabled
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 0 /f
::Enable IE security prompts for Windows installer scripts
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
::Enable Lock button
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v DisableLockWorkstation /t REG_DWORD /d 0 /f
::Enable Logoff button
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLogoff /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLogoff /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLogoff /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoLogoff /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoLogoff /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoLogoff /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v StartMenuLogOff /t REG_DWORD /d 1 /f
::Verify Patching is enabled
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v DisablePatch /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /v DisablePatch /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Installer" /v DisablePatch /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Installer" /v DisablePatch /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Installer" /v DisablePatch /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Installer" /v DisablePatch /t REG_DWORD /d 0 /f
::Enable reminder baloons
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetCache" /v NoReminders /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\NetCache" /v NoReminders /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\NetCache" /v NoReminders /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\NetCache" /v NoReminders /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\NetCache" /v NoReminders /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\NetCache" /v NoReminders /t REG_DWORD /d 0 /f
::Enable Rollback for Windows Installers
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v DisableRollback /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /v DisableRollback /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Installer" /v DisableRollback /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Installer" /v DisableRollback /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Installer" /v DisableRollback /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Installer" /v DisableRollback /t REG_DWORD /d 0 /f
::Auto encrypt files moved to encrypted folders
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoEncryptOnMove /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoEncryptOnMove /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoEncryptOnMove /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoEncryptOnMove /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoEncryptOnMove /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoEncryptOnMove /t REG_DWORD /d 0 /f
::Do not prompt for alternate user's credentials
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRunasInstallPrompt /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRunasInstallPrompt /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRunasInstallPrompt /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoRunasInstallPrompt /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoRunasInstallPrompt /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoRunasInstallPrompt /t REG_DWORD /d 1 /f
::Disable Active Desktop
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v ForceActiveDesktopOn /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v ForceActiveDesktopOn /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v ForceActiveDesktopOn /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\ActiveDesktop" /v ForceActiveDesktopOn /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\ActiveDesktop" /v ForceActiveDesktopOn /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\ActiveDesktop" /v ForceActiveDesktopOn /t REG_DWORD /d 0 /f
::Disable installation security bypass for non-admin users
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f
::Disable elevated file browsing
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v AllowLockdownBrowse /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Installer" /v AllowLockdownBrowse /t REG_DWORD /d 0 /f
::Enable offline file logging
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetCache" /v EventLoggingLevel /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\NetCache" /v EventLoggingLevel /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\NetCache" /v EventLoggingLevel /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\NetCache" /v EventLoggingLevel /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\NetCache" /v EventLoggingLevel /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\NetCache" /v EventLoggingLevel /t REG_DWORD /d 3 /f
::Unhide various settings
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Directory UI" /v HideDirectoryFolder /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Directory UI" /v HideDirectoryFolder /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Directory UI" /v HideDirectoryFolder /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" /v NoAddPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" /v NoAddPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" /v NoAddPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" /v NoWindowsSetupPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" /v NoWindowsSetupPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" /v NoWindowsSetupPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispAppearancePage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispAppearancePage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispAppearancePage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispBackgroundPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispBackgroundPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispBackgroundPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoRemovePage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoRemovePage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoRemovePage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoHardwareTab /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoHardwareTab /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoHardwareTab /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoInternetIcon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoInternetIcon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoInternetIcon /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoNetHood /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoNetHood /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoNetHood /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispScrSavPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispScrSavPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispScrSavPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispSettingsPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispSettingsPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispSettingsPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v PropertyPages /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v PropertyPages /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Task Scheduler5.0" /v PropertyPages /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Directory UI" /v HideDirectoryFolder /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Directory UI" /v HideDirectoryFolder /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Directory UI" /v HideDirectoryFolder /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Uninstall" /v NoAddPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Uninstall" /v NoAddPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Uninstall" /v NoAddPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Uninstall" /v NoWindowsSetupPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Uninstall" /v NoWindowsSetupPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Uninstall" /v NoWindowsSetupPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispAppearancePage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispAppearancePage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispAppearancePage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispBackgroundPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispBackgroundPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispBackgroundPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoRemovePage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoRemovePage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoRemovePage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoHardwareTab /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoHardwareTab /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoHardwareTab /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoInternetIcon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoInternetIcon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoInternetIcon /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoNetHood /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoNetHood /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoNetHood /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispScrSavPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispScrSavPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispScrSavPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispSettingsPage /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispSettingsPage /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v NoDispSettingsPage /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Task Scheduler5.0" /v PropertyPages /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Task Scheduler5.0" /v PropertyPages /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Task Scheduler5.0" /v PropertyPages /t REG_DWORD /d 0 /f
::Verify Desktop is enabled
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v NoDesktop /t REG_DWORD /d 0 /f
::Only allow approved shell extensions
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v EnforceShellExtensionSecurity /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v EnforceShellExtensionSecurity /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v EnforceShellExtensionSecurity /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v EnforceShellExtensionSecurity /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v EnforceShellExtensionSecurity /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\Explorer" /v EnforceShellExtensionSecurity /t REG_DWORD /d 1 /f
::Password protect the screen saver
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_DWORD /d 1 /f
::Disable asynchronous logon scripts
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v RunLogonScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v RunLogonScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v RunLogonScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v RunLogonScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v RunLogonScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v RunLogonScriptSync /t REG_DWORD /d 0 /f
::::Disable asynchronous startup scripts
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v RunStartupScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v RunStartupScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v RunStartupScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v RunStartupScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v RunStartupScriptSync /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v RunStartupScriptSync /t REG_DWORD /d 0 /f
::Disable startup/shutdown scripts
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MMC\{40B6664F-4972-11D1-A7CA-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{40B6664F-4972-11D1-A7CA-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\MMC\{40B6664F-4972-11D1-A7CA-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f
::Disable logon/logoff scripts
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MMC\{40B66650-4972-11D1-A7CA-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{40B66650-4972-11D1-A7CA-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\MMC\{40B66650-4972-11D1-A7CA-0000F87571E3}" /v Restrict_Run /t REG_DWORD /d 1 /f
::Enable file scanning on startup
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows File Protection" /v SfcScan /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Windows File Protection" /v SfcScan /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Windows File Protection" /v SfcScan /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Windows File Protection" /v SfcScan /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Windows File Protection" /v SfcScan /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows NT\Windows File Protection" /v SfcScan /t REG_DWORD /d 1 /f
::Enable autoupdate for Windows Store
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 4 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 4 /f
::Require Admin credentials when performing elevated actions
if "!windows2016!"=="n" (
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
)
::Block non-admin access to safe mode
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SafeModeBlockNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SafeModeBlockNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v SafeModeBlockNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SafeModeBlockNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SafeModeBlockNonAdmins /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v SafeModeBlockNonAdmins /t REG_DWORD /d 1 /f
::Block admin auto-login
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
::Prompt on secure desktop
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
::Prompt on secure desktop
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f
::Disable PIN password
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\Settings" /v AllowSignInOptions /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\PolicyManager\default\Settings" /v AllowSignInOptions /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\PolicyManager\default\Settings" /v AllowSignInOptions /t REG_DWORD /d 0 /f
::Turn on lsass.exe auditing
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
::Enable LSA protection
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKEY_USERS\.DEFAULT\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
::Show Hidden Files
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Explorer" /v ShowSuperHidden /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Policies\Explorer" /v ShowSuperHidden /t REG_DWORD /d 00000001 /f
reg add "HKEY_USERS\.DEFAULT\SYSTEM\CurrentControlSet\Policies\Explorer" /v ShowSuperHidden /t REG_DWORD /d 00000001 /f
::Automatic Signon on restart
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SYSTEM\CurrentControlSet\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f
::Scan Attachments with antivirus
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SYSTEM\CurrentControlSet\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 3 /f
::Secure Screen Saver
reg add "HKEY_LOCAL_MACHINE\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 60 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 60 /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 60 /f
reg add "HKEY_LOCAL_MACHINE\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\Windows\system32\logon.scr" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\Windows\system32\logon.scr" /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\Windows\system32\logon.scr" /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /t REG_DWORD /d 1 /f
::Block Remote Shutdown
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SYSTEM\CurrentControlSet\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
::Enable Change Password
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableChangePassword /t REG_DWORD /d 0 /f
::Windows Installer Logging
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v Logging /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /v Logging /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Installer" /v Logging /t REG_DWORD /d 1 /f
::Disable RIP Routing
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MMC\{C2FE4504-D6C2-11D0-A37B-00C04FC9DA04}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{C2FE4504-D6C2-11D0-A37B-00C04FC9DA04}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\MMC\{C2FE4504-D6C2-11D0-A37B-00C04FC9DA04}" /v Restrict_Run /t REG_DWORD /d 1 /f
::Disable Routing
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MMC\{DAB1A262-4FD7-11D1-842C-00C04FB6C218}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{DAB1A262-4FD7-11D1-842C-00C04FB6C218}" /v Restrict_Run /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\MMC\{DAB1A262-4FD7-11D1-842C-00C04FB6C218}" /v Restrict_Run /t REG_DWORD /d 1 /f
::Enable gpedit
::reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f
::reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f
::reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 0 /f




::Internet Explorer Security Block
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v DisableCachingOfSSLPages /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v DisableCachingOfSSLPages /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v DisableCachingOfSSLPages /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v DisableDNPrompt /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v DisableDNPrompt /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v DisableDNPrompt /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableHttp1_1 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableHttp1_1 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableHttp1_1 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableHTTP2 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableHTTP2 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableHTTP2 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableNegotiate /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableNegotiate /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v EnableNegotiate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v PrivacyAdvanced /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v PrivacyAdvanced /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v PrivacyAdvanced /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v SecureProtocols /t REG_DWORD /d 2688 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v SecureProtocols /t REG_DWORD /d 2688 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v SecureProtocols /t REG_DWORD /d 2688 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnOnBadCertRecving /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnOnBadCertRecving /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnOnBadCertRecving /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f



::Configure Zones
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2301 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2400 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\1" /v 270D /t REG_DWORD /d 3 /f


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2301 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2400 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\2" /v 270D /t REG_DWORD /d 3 /f


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2301 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2400 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\3" /v 270D /t REG_DWORD /d 3 /f


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2301 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2400 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\4" /v 270D /t REG_DWORD /d 3 /f


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1001 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1200 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1206 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1208 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1209 /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 120A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 120B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1405 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1406 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1407 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1408 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1409 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1601 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1604 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1605 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1606 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1607 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1608 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1609 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 160A /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1800 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1802 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1803 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1804 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1805 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1806 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1809 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 180E /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 180F /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A02 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A03 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A04 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A06 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1A10 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1C00 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 1E05 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2000 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2001 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2004 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2007 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2100 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2101 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2102 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2103 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2104 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2115 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2200 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2201 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2300 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2301 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2301 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2400 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2400 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2401 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2402 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2500 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2600 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2702 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2708 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 2709 /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270B /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270C /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270D /t REG_DWORD /d 3 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\Current Version\Internet Settings\Zones\5" /v 270D /t REG_DWORD /d 3 /f

::Enable Java Auto Update
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\JavaSoft\Java Update\Policy" /v EnableJavaUpdate /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\JavaSoft\Java Update\Policy" /v EnableJavaUpdate /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\JavaSoft\Java Update\Policy" /v EnableJavaUpdate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\JavaSoft\Java Update\Policy\jucheck" /v NotifyDownload /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\JavaSoft\Java Update\Policy\jucheck" /v NotifyDownload /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\JavaSoft\Java Update\Policy\jucheck" /v NotifyDownload /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\JavaSoft\Java Update\Policy\jucheck" /v NotifyInstall /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\JavaSoft\Java Update\Policy\jucheck" /v NotifyInstall /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\JavaSoft\Java Update\Policy\jucheck" /v NotifyInstall /t REG_DWORD /d 1 /f



