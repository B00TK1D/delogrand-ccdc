


::Windows Security Script
::Writting by Team Kernel, CyberPatriot IX
::Copyright 2018
::This script is intelectual property of Team Kernel and its members.
::Use of this script by any other CyberPatriot team is prohibited without writen consent from the Team Kernel team captain or coach.
::
::Currently Supported Platforms: Windows 7, Windows 8.1, Windows Server 2008, Windows Server 2008 R2, Windows Server 2012, Windows Server 2016
::Currently Tested Platforms: Windows 8.1


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

::Stop bad services
net stop RemoteRegistry
sc config RemoteRegistry start= disabled
net stop PlugPlay
sc config PlugPlay start= disabled
net stop LDP
sc config LDP start= disabled
net stop RIP
sc config RIP start= disabled
net stop RemoteAccess
sc config RemoteAccess start= disabled
net stop RpcLocator
sc config RpcLocator start= disabled
net stop RpcSs
sc config RpcSs start= disabled



::Start required services
net start EventLog
reg add "HKLM\System\CurrentControlSet\services\EventLog" /v Start /t REG_DWORD /d 2 /f
sc config EventLog start= auto
net start wscsvc
reg add "HKLM\System\CurrentControlSet\services\wscsvc" /v Start /t REG_DWORD /d 2 /f
sc config wscsvc start= auto
net start Wecsvc
reg add "HKLM\System\CurrentControlSet\services\Wecsvc" /v Start /t REG_DWORD /d 2 /f
sc config Wecsvc start= auto
net start WerSvc
reg add "HKLM\System\CurrentControlSet\services\WerSvc" /v Start /t REG_DWORD /d 2 /f
sc config WerSvc start= auto
net start Schedule
reg add "HKLM\System\CurrentControlSet\services\Schedule" /v Start /t REG_DWORD /d 2 /f
sc config Schedule start= auto
net start LanmanServer
reg add "HKLM\System\CurrentControlSet\services\LanmanServer" /v Start /t REG_DWORD /d 2 /f
sc config LanmanServer start= auto
net start WinDefend
reg add "HKLM\System\CurrentControlSet\services\WinDefend" /v Start /t REG_DWORD /d 2 /f
sc config WinDefend start= auto
net start MpsSvc
reg add "HKLM\System\CurrentControlSet\services\MpsSvc" /v Start /t REG_DWORD /d 2 /f
sc config MpsSvc start= auto
net start wuauserv
reg add "HKLM\System\CurrentControlSet\services\wuauserv" /v Start /t REG_DWORD /d 2 /f
sc config wuauserv start= auto
net start gpsvc
reg add "HKLM\System\CurrentControlSet\services\gpsvc" /v Start /t REG_DWORD /d 2 /f
sc config gpsvc start= auto
net start BITS
reg add "HKLM\System\CurrentControlSet\services\BITS" /v Start /t REG_DWORD /d 2 /f
sc config BITS start= auto

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


::Reset File Permissions
echo Resetting file permissions to default...
icacls * /t /q /c /reset > NUL


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



::Set boot security settings
C:\Windows\system32\bcdedit.exe /set nx AlwaysOn > NUL
C:\Windows\system32\bcdedit.exe /set bootlog yes > NUL
C:\Windows\system32\bcdedit.exe /set disableelamdrivers no > NUL
C:\Windows\system32\bcdedit.exe /set forcelegacyplatform no > NUL
C:\Windows\system32\bcdedit.exe /set nointegritychecks off > NUL
C:\Windows\system32\bcdedit.exe /deletevalue bootmenupolicy > NUL
C:\Windows\system32\bcdedit.exe /deletevalue bootstatuspolicy > NUL
C:\Windows\system32\bcdedit.exe /deletevalue bootux > NUL
C:\Windows\system32\bcdedit.exe /deletevalue disabledynamictick > NUL
C:\Windows\system32\bcdedit.exe /deletevalue disableelamdrivers > NUL
C:\Windows\system32\bcdedit.exe /deletevalue forcelegacyplatform > NUL
C:\Windows\system32\bcdedit.exe /deletevalue groupsize > NUL
C:\Windows\system32\bcdedit.exe /deletevalue groupaware > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hal > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorbusparams > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisordebug > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisordebugport > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisordebugtype > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorbaudrate > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorchannel > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorhostip > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorhostport > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisordhcp > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisoriommupolicy > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorlaunchtype > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorloadoptions > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisornumproc > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorrootproc > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorrootprocpernode > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisorusekey > NUL
C:\Windows\system32\bcdedit.exe /deletevalue hypervisoruselargevtlb > NUL
C:\Windows\system32\bcdedit.exe /deletevalue increaseuserva > NUL
C:\Windows\system32\bcdedit.exe /deletevalue kernel > NUL
C:\Windows\system32\bcdedit.exe /deletevalue loadoptions > NUL
C:\Windows\system32\bcdedit.exe /deletevalue maxgroup > NUL
C:\Windows\system32\bcdedit.exe /deletevalue nolowmem > NUL
C:\Windows\system32\bcdedit.exe /deletevalue novesa > NUL
C:\Windows\system32\bcdedit.exe /deletevalue novga > NUL
C:\Windows\system32\bcdedit.exe /deletevalue onecpu > NUL
C:\Windows\system32\bcdedit.exe /deletevalue onetimeadvancedoptions > NUL
C:\Windows\system32\bcdedit.exe /deletevalue pae > NUL
C:\Windows\system32\bcdedit.exe /deletevalue pciexpress > NUL
C:\Windows\system32\bcdedit.exe /deletevalue quietboot > NUL
C:\Windows\system32\bcdedit.exe /deletevalue removememory > NUL
C:\Windows\system32\bcdedit.exe /deletevalue sos > NUL
C:\Windows\system32\bcdedit.exe /deletevalue testsigning > NUL
C:\Windows\system32\bcdedit.exe /deletevalue tpmbootentropy > NUL
C:\Windows\system32\bcdedit.exe /deletevalue truncatememory > NUL
C:\Windows\system32\bcdedit.exe /deletevalue tscsyncpolicy > NUL
C:\Windows\system32\bcdedit.exe /deletevalue usefirmwarepcisettings > NUL
C:\Windows\system32\bcdedit.exe /deletevalue useplatformclock > NUL
C:\Windows\system32\bcdedit.exe /deletevalue uselegacyapicmode > NUL
C:\Windows\system32\bcdedit.exe /deletevalue useplatformtick > NUL
C:\Windows\system32\bcdedit.exe /deletevalue vga > NUL
C:\Windows\system32\bcdedit.exe /deletevalue xsavedisable > NUL
C:\Windows\system32\bcdedit.exe /deletevalue x2apicpolicy > NUL
echo Boot settings secured


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





::Prepare file of default scheduled tasks for later
echo \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319>default-tasks.tmp
echo \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64>>default-tasks.tmp
echo \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical>>default-tasks.tmp
echo \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical>>default-tasks.tmp
echo \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)>>default-tasks.tmp
echo \Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)>>default-tasks.tmp
echo \Microsoft\Windows\AppID\EDP Policy Manager>>default-tasks.tmp
echo \Microsoft\Windows\AppID\PolicyConverter>>default-tasks.tmp
echo \Microsoft\Windows\AppID\SmartScreenSpecific>>default-tasks.tmp
echo \Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck>>default-tasks.tmp
echo \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser>>default-tasks.tmp
echo \Microsoft\Windows\Application Experience\ProgramDataUpdater>>default-tasks.tmp
echo \Microsoft\Windows\Application Experience\StartupAppTask>>default-tasks.tmp
echo \Microsoft\Windows\ApplicationData\appuriverifierdaily>>default-tasks.tmp
echo \Microsoft\Windows\ApplicationData\appuriverifierinstall>>default-tasks.tmp
echo \Microsoft\Windows\ApplicationData\CleanupTemporaryState>>default-tasks.tmp
echo \Microsoft\Windows\ApplicationData\DsSvcCleanup>>default-tasks.tmp
echo \Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup>>default-tasks.tmp
echo \Microsoft\Windows\Autochk\Proxy>>default-tasks.tmp
echo \Microsoft\Windows\Bluetooth\UninstallDeviceTask>>default-tasks.tmp
echo \Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask>>default-tasks.tmp
echo \Microsoft\Windows\CertificateServicesClient\CryptoPolicyTask>>default-tasks.tmp
echo \Microsoft\Windows\CertificateServicesClient\KeyPreGenTask>>default-tasks.tmp
echo \Microsoft\Windows\CertificateServicesClient\SystemTask>>default-tasks.tmp
echo \Microsoft\Windows\CertificateServicesClient\UserTask>>default-tasks.tmp
echo \Microsoft\Windows\CertificateServicesClient\UserTask-Roam>>default-tasks.tmp
echo \Microsoft\Windows\Chkdsk\ProactiveScan>>default-tasks.tmp
echo \Microsoft\Windows\Clip\License Validation>>default-tasks.tmp
echo \Microsoft\Windows\CloudExperienceHost\CreateObjectTask>>default-tasks.tmp
echo \Microsoft\Windows\Customer Experience Improvement Program\Consolidator>>default-tasks.tmp
echo \Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask>>default-tasks.tmp
echo \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip>>default-tasks.tmp
echo \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan>>default-tasks.tmp
echo \Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery>>default-tasks.tmp
echo \Microsoft\Windows\Defrag\ScheduledDefrag>>default-tasks.tmp
echo \Microsoft\Windows\Device Information\Device>>default-tasks.tmp
echo \Microsoft\Windows\Device Setup\Metadata Refresh>>default-tasks.tmp
echo \Microsoft\Windows\Diagnosis\Scheduled>>default-tasks.tmp
echo \Microsoft\Windows\DiskCleanup\SilentCleanup>>default-tasks.tmp
echo \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector>>default-tasks.tmp
echo \Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver>>default-tasks.tmp
echo \Microsoft\Windows\DiskFootprint\Diagnostics>>default-tasks.tmp
echo \Microsoft\Windows\DiskFootprint\StorageSense>>default-tasks.tmp
echo \Microsoft\Windows\EDP\EDP App Launch Task>>default-tasks.tmp
echo \Microsoft\Windows\EDP\EDP Auth Task>>default-tasks.tmp
echo \Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate>>default-tasks.tmp
echo \Microsoft\Windows\ErrorDetails\ErrorDetailsUpdate>>default-tasks.tmp
echo \Microsoft\Windows\LanguageComponentsInstaller\Installation>>default-tasks.tmp
echo \Microsoft\Windows\LanguageComponentsInstaller\Uninstallation>>default-tasks.tmp
echo \Microsoft\Windows\License Manager\TempSignedLicenseExchange>>default-tasks.tmp
echo \Microsoft\Windows\Location\Notifications>>default-tasks.tmp
echo \Microsoft\Windows\Location\WindowsActionDialog>>default-tasks.tmp
echo \Microsoft\Windows\Maintenance\WinSAT>>default-tasks.tmp
echo \Microsoft\Windows\Maps\MapsToastTask>>default-tasks.tmp
echo \Microsoft\Windows\Maps\MapsUpdateTask>>default-tasks.tmp
echo \Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents>>default-tasks.tmp
echo \Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic>>default-tasks.tmp
echo \Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser>>default-tasks.tmp
echo \Microsoft\Windows\MUI\LPRemove>>default-tasks.tmp
echo \Microsoft\Windows\Multimedia\SystemSoundsService>>default-tasks.tmp
echo \Microsoft\Windows\NetTrace\GatherNetworkInfo>>default-tasks.tmp
echo \Microsoft\Windows\Network Controller\SDN Diagnostics Task>>default-tasks.tmp
echo \Microsoft\Windows\Offline Files\Background Synchronization>>default-tasks.tmp
echo \Microsoft\Windows\Offline Files\Logon Synchronization>>default-tasks.tmp
echo \Microsoft\Windows\PI\Secure-Boot-Update>>default-tasks.tmp
echo \Microsoft\Windows\PI\Sqm-Tasks>>default-tasks.tmp
echo \Microsoft\Windows\PLA\Server Manager Performance Monitor>>default-tasks.tmp
echo \Microsoft\Windows\Plug and Play\Device Install Group Policy>>default-tasks.tmp
echo \Microsoft\Windows\Plug and Play\Device Install Reboot Required>>default-tasks.tmp
echo \Microsoft\Windows\Plug and Play\Plug and Play Cleanup>>default-tasks.tmp
echo \Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers>>default-tasks.tmp
echo \Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem>>default-tasks.tmp
echo \Microsoft\Windows\Ras\MobilityManager>>default-tasks.tmp
echo \Microsoft\Windows\RecoveryEnvironment\VerifyWinRE>>default-tasks.tmp
echo \Microsoft\Windows\Registry\RegIdleBackup>>default-tasks.tmp
echo \Microsoft\Windows\Server Manager\CleanupOldPerfLogs>>default-tasks.tmp
echo \Microsoft\Windows\Server Manager\ServerManager>>default-tasks.tmp
echo \Microsoft\Windows\Servicing\StartComponentCleanup>>default-tasks.tmp
echo \Microsoft\Windows\SettingSync\BackgroundUploadTask>>default-tasks.tmp
echo \Microsoft\Windows\SettingSync\BackupTask>>default-tasks.tmp
echo \Microsoft\Windows\SettingSync\NetworkStateChangeTask>>default-tasks.tmp
echo \Microsoft\Windows\Shell\CreateObjectTask>>default-tasks.tmp
echo \Microsoft\Windows\Shell\IndexerAutomaticMaintenance>>default-tasks.tmp
echo \Microsoft\Windows\Software Inventory Logging\Collection>>default-tasks.tmp
echo \Microsoft\Windows\Software Inventory Logging\Configuration>>default-tasks.tmp
echo \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask>>default-tasks.tmp
echo \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon>>default-tasks.tmp
echo \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork>>default-tasks.tmp
echo \Microsoft\Windows\SpacePort\SpaceAgentTask>>default-tasks.tmp
echo \Microsoft\Windows\SpacePort\SpaceManagerTask>>default-tasks.tmp
echo \Microsoft\Windows\Speech\SpeechModelDownloadTask>>default-tasks.tmp
echo \Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization>>default-tasks.tmp
echo \Microsoft\Windows\Storage Tiers Management\Storage Tiers Optimization>>default-tasks.tmp
echo \Microsoft\Windows\Task Manager\Interactive>>default-tasks.tmp
echo \Microsoft\Windows\TextServicesFramework\MsCtfMonitor>>default-tasks.tmp
echo \Microsoft\Windows\Time Synchronization\ForceSynchronizeTime>>default-tasks.tmp
echo \Microsoft\Windows\Time Zone\SynchronizeTimeZone>>default-tasks.tmp
echo \Microsoft\Windows\TPM\Tpm-HASCertRetr>>default-tasks.tmp
echo \Microsoft\Windows\TPM\Tpm-Maintenance>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\Maintenance Install>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\MusUx_UpdateInterval>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\Policy Install>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\Reboot>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\Refresh Settings>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\Resume On Boot>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\Schedule Scan>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display>>default-tasks.tmp
echo \Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot>>default-tasks.tmp
echo \Microsoft\Windows\UPnP\UPnPHostConfig>>default-tasks.tmp
echo \Microsoft\Windows\User Profile Service\HiveUploadTask>>default-tasks.tmp
echo \Microsoft\Windows\WDI\ResolutionHost>>default-tasks.tmp
echo \Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance>>default-tasks.tmp
echo \Microsoft\Windows\Windows Defender\Windows Defender Cleanup>>default-tasks.tmp
echo \Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan>>default-tasks.tmp
echo \Microsoft\Windows\Windows Defender\Windows Defender Verification>>default-tasks.tmp
echo \Microsoft\Windows\Windows Error Reporting\QueueReporting>>default-tasks.tmp
echo \Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange>>default-tasks.tmp
echo \Microsoft\Windows\WindowsColorSystem\Calibration Loader>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\Automatic App Update>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\Scheduled Start>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\sih>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\sihboot>>default-tasks.tmp
echo \Microsoft\Windows\Wininet\CacheTask>>default-tasks.tmp
echo \Microsoft\Windows\Workplace Join\Automatic-Device-Join>>default-tasks.tmp
echo \Microsoft\XblGameSave\XblGameSaveTask>>default-tasks.tmp
echo \Microsoft\XblGameSave\XblGameSaveTaskLogon>>default-tasks.tmp
echo \OneDrive Standalone Update Task-S-1-5-21-2455100455-2066415649-270607408-1001>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\HandleCommand>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceAccountChange>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceConnectedToNetwork>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceLocationRightsChange>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePeriodic1>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePeriodic24>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePeriodic6>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePolicyChange>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceScreenOnOff>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceSettingChange>>default-tasks.tmp
echo \Microsoft\Windows\DeviceDirectoryClient\RegisterUserDevice>>default-tasks.tmp
echo \Microsoft\Windows\DUSM\dusmtask>>default-tasks.tmp
echo \Microsoft\Windows\Feedback\Siuf\DmClient>>default-tasks.tmp
echo \Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload>>default-tasks.tmp
echo \Microsoft\Windows\File Classification Infrastructure\Property Definition Sync>>default-tasks.tmp
echo \Microsoft\Windows\FileHistory\File History (maintenance mode)>>default-tasks.tmp
echo \Microsoft\Windows\Management\Provisioning\Logon>>default-tasks.tmp
echo \Microsoft\Windows\NlaSvc\WiFiTask>>default-tasks.tmp
echo \Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask>>default-tasks.tmp
echo \Microsoft\Windows\SharedPC\Account Cleanup>>default-tasks.tmp
echo \Microsoft\Windows\Shell\FamilySafetyMonitor>>default-tasks.tmp
echo \Microsoft\Windows\Shell\FamilySafetyMonitorToastTask>>default-tasks.tmp
echo \Microsoft\Windows\Shell\FamilySafetyRefreshTask>>default-tasks.tmp
echo \Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate>>default-tasks.tmp
echo \Microsoft\Windows\Sysmain\HybridDriveCacheRebalance>>default-tasks.tmp
echo \Microsoft\Windows\Sysmain\ResPriStaticDbSync>>default-tasks.tmp
echo \Microsoft\Windows\Sysmain\WsSwapAssessmentTask>>default-tasks.tmp
echo \Microsoft\Windows\SystemRestore\SR>>default-tasks.tmp
echo \Microsoft\Windows\Time Synchronization\SynchronizeTime>>default-tasks.tmp
echo \Microsoft\Windows\WCM\WiFiTask>>default-tasks.tmp
echo \Microsoft\Windows\Windows Media Sharing\UpdateLibrary>>default-tasks.tmp
echo \Microsoft\Windows\WOF\WIM-Hash-Management>>default-tasks.tmp
echo \Microsoft\Windows\WOF\WIM-Hash-Validation>>default-tasks.tmp
echo \Microsoft\Windows\Work Folders\Work Folders Logon Synchronization>>default-tasks.tmp
echo \Microsoft\Windows\Work Folders\Work Folders Maintenance Work>>default-tasks.tmp
echo \Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant>>default-tasks.tmp
echo \Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleCollector>>default-tasks.tmp
echo \Microsoft\Windows\NetworkAccessProtection\NAPStatus UI>>default-tasks.tmp
echo \Microsoft\Windows\PLA\System\ConvertLogEntries>>default-tasks.tmp
echo \Microsoft\Windows\RAC\RACAgent>>default-tasks.tmp
echo \Microsoft\Windows\Tcpip\IpAddressConflict1>>default-tasks.tmp
echo \Microsoft\Windows\Tcpip\IpAddressConflict2>>default-tasks.tmp
echo \Microsoft\Windows\Wired\GatherWiredInfo>>default-tasks.tmp
echo \Microsoft\Windows\Application Experience\AitAgent>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\ActivateWindowsSearch>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\ConfigureInternetTimeService>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\DispatchRecoveryTasks>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\ehDRMInit>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\InstallPlayReady>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\mcupdate>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\MediaCenterRecoveryTask>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\ObjectStoreRecoveryTask>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\OCURActivate>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\OCURDiscovery>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\PBDADiscovery>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\PBDADiscoveryW1>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\PBDADiscoveryW2>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\PeriodicScanRetry>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\PvrRecoveryTask>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\PvrScheduleTask>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\RecordingRestart>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\RegisterSearch>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\ReindexSearchRoot>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\SqlLiteRecoveryTask>>default-tasks.tmp
echo \Microsoft\Windows\Media Center\UpdateRecordPath>>default-tasks.tmp
echo \Microsoft\Windows\MemoryDiagnostic\CorruptionDetector>>default-tasks.tmp
echo \Microsoft\Windows\MemoryDiagnostic\DecompressionFailureDetector>>default-tasks.tmp
echo \Microsoft\Windows\MobilePC\HotStart>>default-tasks.tmp
echo \Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor>>default-tasks.tmp
echo \Microsoft\Windows\RAC\RacTask>>default-tasks.tmp
echo \Microsoft\Windows\Shell\WindowsParentalControls>>default-tasks.tmp
echo \Microsoft\Windows\Shell\WindowsParentalControlsMigration>>default-tasks.tmp
echo \Microsoft\Windows\SideShow\AutoWake>>default-tasks.tmp
echo \Microsoft\Windows\SideShow\GadgetManager>>default-tasks.tmp
echo \Microsoft\Windows\SideShow\SessionAgent>>default-tasks.tmp
echo \Microsoft\Windows\SideShow\SystemDataProviders>>default-tasks.tmp
echo \Microsoft\Windows\Windows Activation Technologies\ValidationTask>>default-tasks.tmp
echo \Microsoft\Windows\Windows Activation Technologies\ValidationTaskDeadline>>default-tasks.tmp
echo \Microsoft\Windows\WindowsBackup\ConfigNotification>>default-tasks.tmp
echo \Microsoft\Windows Defender\MP Scheduled Scan>>default-tasks.tmp
echo \Microsoft\Windows Defender\MpIdleTask>>default-tasks.tmp
echo \Antivirus Emergency Update>>default-tasks.tmp
echo \AVG EUpdate Task>>default-tasks.tmp
echo \CCleaner Update>>default-tasks.tmp
echo \CCleanerSkipUAC>>default-tasks.tmp
echo \Optimize Start Menu Cache Files-S-1-5-21-3419697854-480222728-3549059302-1001>>default-tasks.tmp
echo \AVG\Overseer>>default-tasks.tmp
echo \Microsoft\Windows\Customer Experience Improvement Program\BthSQM>>default-tasks.tmp
echo \Microsoft\Windows\IME\SQM data sender>>default-tasks.tmp
echo \Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler>>default-tasks.tmp
echo \Microsoft\Windows\Shell\FamilySafetyRefresh>>default-tasks.tmp
echo \Microsoft\Windows\SkyDrive\Idle Sync Maintenance Task>>default-tasks.tmp
echo \Microsoft\Windows\SkyDrive\Routine Maintenance Task>>default-tasks.tmp
echo \Microsoft\Windows\TaskScheduler\Idle Maintenance>>default-tasks.tmp
echo \Microsoft\Windows\TaskScheduler\Maintenance Configurator>>default-tasks.tmp
echo \Microsoft\Windows\TaskScheduler\Manual Maintenance>>default-tasks.tmp
echo \Microsoft\Windows\TaskScheduler\Regular Maintenance>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\AUFirmwareInstall>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\AUScheduledInstall>>default-tasks.tmp
echo \Microsoft\Windows\WindowsUpdate\AUSessionConnect>>default-tasks.tmp
echo \Microsoft\Windows\Workplace Join\Automatic-Workplace-Join>>default-tasks.tmp
echo \Microsoft\Windows\WS\Badge Update>>default-tasks.tmp
echo \Microsoft\Windows\WS\License Validation>>default-tasks.tmp
echo \Microsoft\Windows\WS\Sync Licenses>>default-tasks.tmp
echo \Microsoft\Windows\WS\WSRefreshBannedAppsListTask>>default-tasks.tmp
echo \Microsoft\Windows\WS\WSTask>>default-tasks.tmp


::Prepare list of default services for later
echo Application Experience>default-services.tmp
echo Application Information>>default-services.tmp
echo Background Intelligent Transfer Service>>default-services.tmp
echo Base Filtering Engine>>default-services.tmp
echo COM+ Event System>>default-services.tmp
echo COM+ System Application>>default-services.tmp
echo Cryptographic Services>>default-services.tmp
echo DCOM Server Process Launcher>>default-services.tmp
echo Desktop Window Manager Session Manager>>default-services.tmp
echo DHCP Client>>default-services.tmp
echo Diagnostic Policy Service>>default-services.tmp
echo DNS Client>>default-services.tmp
echo Group Policy Client>>default-services.tmp
echo IKE and AuthIP IPsec Keying Modules>>default-services.tmp
echo IP Helper>>default-services.tmp
echo IPsec Policy Agent>>default-services.tmp
echo Network Connections>>default-services.tmp
echo Network Location Awareness>>default-services.tmp
echo Network Store Interface Service>>default-services.tmp
echo Print Spooler>>default-services.tmp
echo Remote Access Connection Manager>>default-services.tmp
echo Remote Procedure Call (RPC)>>default-services.tmp
echo Secondary Logon>>default-services.tmp
echo Secure Socket Tunneling Protocol Service>>default-services.tmp
echo Security Accounts Manager>>default-services.tmp
echo Server>>default-services.tmp
echo Shell Hardware Detection>>default-services.tmp
echo SL UI Notification Service>>default-services.tmp
echo Software Licensing>>default-services.tmp
echo System Event Notification Service>>default-services.tmp
echo Task Scheduler>>default-services.tmp
echo TCP/IP NetBIOS Helper>>default-services.tmp
echo Telephony>>default-services.tmp
echo Terminal Services>>default-services.tmp
echo User Profile Service>>default-services.tmp
echo VMware Alias Manager and Ticket Service>>default-services.tmp
echo VMware CAF Management Agent Service>>default-services.tmp
echo VMware Tools>>default-services.tmp
echo WMI Performance Adapter>>default-services.tmp
echo Workstation>>default-services.tmp
echo AppX Deployment Service (AppXSVC)>>default-services.tmp
echo Background Tasks Infrastructure Service>>default-services.tmp
echo CDPUserSvc_3f015>>default-services.tmp
echo CNG Key Isolation>>default-services.tmp
echo Computer Browser>>default-services.tmp
echo Connected Devices Platform Service>>default-services.tmp
echo Connected User Experiences and Telemetry>>default-services.tmp
echo Contact Data_3f015>>default-services.tmp
echo CoreMessaging>>default-services.tmp
echo Credential Manager>>default-services.tmp
echo Data Sharing Service>>default-services.tmp
echo Delivery Optimization>>default-services.tmp
echo Diagnostic Service Host>>default-services.tmp
echo Geolocation Service>>default-services.tmp
echo Local Session Manager>>default-services.tmp
echo Network Connection Broker>>default-services.tmp
echo Power>>default-services.tmp
echo RPC Endpoint Mapper>>default-services.tmp
echo Security Center>>default-services.tmp
echo State Repository Service>>default-services.tmp
echo Storage Service>>default-services.tmp
echo Superfetch>>default-services.tmp
echo Sync Host_3f015>>default-services.tmp
echo System Events Broker>>default-services.tmp
echo Tile Data model server>>default-services.tmp
echo Time Broker>>default-services.tmp
echo User Data Access_3f015>>default-services.tmp
echo User Data Storage_3f015>>default-services.tmp
echo User Manager>>default-services.tmp
echo User Access Logging Service>>default-services.tmp
echo CDPUserSvc_462c9>>default-services.tmp
echo Sync Host_462c9>>default-services.tmp
echo Diagnostic System Host>>default-services.tmp
echo Diagnostics Tracking Service>>default-services.tmp
echo HomeGroup Provider>>default-services.tmp
echo Microsoft Software Shadow Copy Provider>>default-services.tmp
echo Offline Files>>default-services.tmp
echo Plug and Play>>default-services.tmp
echo Software Protection>>default-services.tmp
echo Volume Shadow Copy>>default-services.tmp
echo Microsoft Storage Spaces SMP>>default-services.tmp
echo AVG Antivirus>>default-services.tmp
echo avgbIDSAgent>>default-services.tmp
echo Device Association Service>>default-services.tmp
echo Malwarebytes Service>>default-services.tmp
echo Network Connected Devices Auto-Setup>>default-services.tmp
echo SPP Notification Service>>default-services.tmp



::Prepare Default Processes for later
echo System Idle Process>default-procs.tmp
echo System>>default-procs.tmp
echo smss.exe>>default-procs.tmp
echo csrss.exe>>default-procs.tmp
echo wininit.exe>>default-procs.tmp
echo winlogon.exe>>default-procs.tmp
echo services.exe>>default-procs.tmp
echo lsass.exe>>default-procs.tmp
echo lsm.exe>>default-procs.tmp
echo svchost.exe>>default-procs.tmp
echo spoolsv.exe>>default-procs.tmp
echo VGAuthService.exe>>default-procs.tmp
echo vmtoolsd.exe>>default-procs.tmp
echo ManagementAgentHost.exe>>default-procs.tmp
echo msdtc.exe>>default-procs.tmp
echo WmiPrvSE.exe>>default-procs.tmp
echo taskhost.exe>>default-procs.tmp
echo sppsvc.exe>>default-procs.tmp
echo SearchIndexer.exe>>default-procs.tmp
echo dwm.exe>>default-procs.tmp
echo explorer.exe>>default-procs.tmp
echo wmpnetwk.exe>>default-procs.tmp
echo TrustedInstaller.exe>>default-procs.tmp
echo VSSVC.exe>>default-procs.tmp
echo firefox.exe>>default-procs.tmp
echo wuauclt.exe>>default-procs.tmp
echo cmd.exe>>default-procs.tmp
echo conhost.exe>>default-procs.tmp
echo tasklist.exe>>default-procs.tmp
echo MsMpEng.exe>>default-procs.tmp
echo dllhost.exe>>default-procs.tmp
echo sihost.exe>>default-procs.tmp
echo taskhostw.exe>>default-procs.tmp
echo RuntimeBroker.exe>>default-procs.tmp
echo ShellExperienceHost.exe>>default-procs.tmp
echo SearchUI.exe>>default-procs.tmp
echo TiWorker.exe>>default-procs.tmp
echo MpCmdRun.exe>>default-procs.tmp
echo DismHost.exe>>default-procs.tmp
echo AVGSvc.exe>>default-procs.tmp
echo dasHost.exe>>default-procs.tmp
echo MBAMService.exe>>default-procs.tmp
echo aswidsagenta.exe>>default-procs.tmp
echo mbamtray.exe>>default-procs.tmp
echo taskhostex.exe>>default-procs.tmp
echo AVGUI.exe>>default-procs.tmp
echo SearchProtocolHost.exe>>default-procs.tmp
echo SearchFilterHost.exe>>default-procs.tmp
echo ApplicationFrameHost.exe>>default-procs.tmp
echo backgroundTaskHost.exe>>default-procs.tmp



::Prepare Default Groups for later
echo Backup Operators>default-groups.tmp
echo Certificate Service DCOM Access>>default-groups.tmp
echo Cryptographic Operators>>default-groups.tmp
echo Event Log Readers>>default-groups.tmp
echo Guests>>default-groups.tmp
echo IIS_IUSRS>>default-groups.tmp
echo Network Configuration Operators>>default-groups.tmp
echo Print Operators>>default-groups.tmp
echo RDS Endpoint Servers>>default-groups.tmp
echo RDS Management Servers>>default-groups.tmp
echo RDS Remote Access Servers>>default-groups.tmp
echo Replicator>>default-groups.tmp
echo System Managed Accounts Group>>default-groups.tmp


::cls

::Delete incorrect accounts
echo.
echo.
echo Press Enter to begin editing users...
pause > NUL
type NUL > C:\del.txt
type NUL > C:\del2.txt
type NUL > C:\usernames.txt
type NUL > C:\usernames2.txt
::cls
net user > C:\usernames.txt
findstr /v "The command completed" C:\usernames.txt > C:\usernames2.txt
for /f "tokens=1,2,3 skip=4" %%i in (C:\usernames2.txt) do echo %%i >> C:\del.txt & echo %%j >> C:\del.txt & echo %%k >> C:\del.txt
findstr /v "echo" C:\del.txt > C:\del2.txt
del C:\usernames.txt C:\usernames2.txt C:\del.txt
for /f "delims==" %%l in (C:\del2.txt) do (
	set isValid=y
	set isAdmin=y
	if not "%%l"=="defaultaccount0  " if not "%%l"=="Guest  " if not "%%l"=="DefaultAccount  " if not "%%l"=="%USERNAME%" if not "%%l"=="Administrator  " if not "%%l"=="ECHO is off." if not "%%l"=="RandomUser " if not "%%l"=="AnotherUser  " if not "%%l"=="AnotherUser2  " if not "%%l"=="AnotherUser3  " (
		set /p isValid=Is this username a valid account: %%l (y/n/s^) 
		if /I not "!isValid!"=="s" (
		    if /I "!isValid!"=="y" (
				net user %%l %our_password% /active:Yes /Y
				net user %%l /Passwordchg:Yes /Y
				net user %%l /Expires:Never /Y
	    		echo User account activated and secure password set.
	    		set /p isAdmin=Is this account an Administrator: %%l (y/n^) 
	    		if /I "!isAdmin!"=="y" (
	    		    net localgroup administrators %%l /add /Y
	    		    echo User granted Administrator rights
	    		) else (
	    		    net localgroup administrators %%l /delete /Y
	    		    echo User denied Administrator rights.
	    		)
    		) else (
    		    net user %%l /delete /Y
    		    echo User account deactivated.
    		)
    	) else (
    	  echo User skipped.
    	)
	)
)
echo User accounts secured.

::Delete unnecessary groups
echo.
echo.
echo Press Enter to begin editing groups...
pause > NUL
type NUL > C:\del.txt
type NUL > C:\del2.txt
type NUL > C:\groups.txt
type NUL > C:\groups2.txt
::cls
net localgroup > C:\groups.txt
findstr /v "The command completed" C:\groups.txt > C:\del.txt
findstr /v "Aliases for" C:\del.txt > C:\del2.txt
findstr /v "\-\-\-\-\-\-\-\-" C:\del2.txt > C:\del.txt
findstr /v "ECHO is off" C:\del.txt > C:\del2.txt
findstr /v "Users" C:\del2.txt > C:\del.txt
del C:\groups.txt C:\groups2.txt C:\del2.txt
for /f "delims=" %%l in (C:\del.txt) do (
	SETLOCAL EnableDelayedExpansion
	set name=%%l
	set name=!name:~1!
	set isValid=y
	set isdefault=n
	for /f "delims=" %%m in (default-groups.tmp) do (
	    if %%m==!name! (
	        set isdefault=y
	    )
	)
	if "!isdefault!"=="n" (
    	set /p isValid=Is this group valid: !name! (y/n^)
    	if /I "!isValid!"=="n" (
    	    net localgroup "!name!" /delete
    	    echo !name! group removed.
        ) else (
        	echo !name! group accepted as valid.
        	net localgroup "!name!" > C:\members.txt
        	findstr /v "The command completed" C:\members.txt > C:\del3.txt
            findstr /v "Members" C:\del3.txt > C:\del4.txt
            findstr /v "\-\-\-\-\-\-\-\-" C:\del4.txt > C:\del3.txt
            findstr /v "ECHO is off" C:\del3.txt > C:\del4.txt
    	    findstr /v "Alias name" C:\del4.txt > C:\del3.txt
    	    findstr /v "Comment" C:\del3.txt > C:\del4.txt
            del C:\del3.txt
            for /f "delims=" %%m in (C:\del4.txt) do (
                set member=%%m
                set isMember=y
                set /p isMember=Is !member! supposed to be a member of !name!? (y/n^)
                if /I "!isMember!"=="n" (
                    net localgroup "!name!" "!member!" /delete
                    echo !member! removed from !name! group
                ) else (
                    echo !member! approved as valid member of !name! group
                )
            )
        )
    )
)
del C:\del2.txt C:\del4.txt
echo Groups secured.



::Delete unapproved shares
echo.
echo.
echo Press Enter to begin editing shares...
pause > NUL
type NUL > C:\del.txt
type NUL > C:\del2.txt
type NUL > C:\del3.txt
type NUL > C:\del4.txt
type NUL > C:\shares.txt
type NUL > C:\shares2.txt
::cls
net share > C:\shares.txt
findstr /v "The command completed" C:\shares.txt > C:\shares2.txt
findstr /v "Share name	Resource" C:\shares2.txt > C:\shares.txt
findstr /v "\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-" C:\shares.txt > C:\shares2.txt
del C:\shares.txt
set couunter=a
for /f "delims= " %%l in (C:\shares2.txt) do (
	set name=%%l
	if not "!name!"=="C$" if not "!name!"=="IPC$" if not "!name!"=="ADMIN$" (
		net share %%l > C:\del3.txt
		findstr "Path" C:\del3.txt > C:\del4.txt
		for /f "tokens=2 delims= " %%m in (C:\del4.txt) do set resource=%%m
		set valid=y
		echo.
		echo.
		set /P valid=Is !name! (Path: !resource!^) a valid share? (y/n^): 
		if /I "!valid!"=="n" (
			net share "!name!" /delete
			echo Share !name! (Path: !resource!^) removed.
		) else (
			echo Share !name! (Path: !resource!^) approved as valid.
		)
	)
)
del C:\del2.txt C:\del3.txt C:\del4.txt 
echo Shares secured.


::Secure Services
echo.
echo.
echo Press Enter to begin editing services...
pause > NUL
type NUL > C:\del.txt
type NUL > C:\del2.txt
type NUL > C:\services.txt
type NUL > C:\services2.txt
::cls
net start > C:\services.txt
findstr /v "The command completed" C:\services.txt > C:\services2.txt
findstr /v "These Windows services" C:\services2.txt > C:\services.txt
findstr /v "ECHO is off" C:\services.txt > C:\services2.txt
del C:\services.txt C:\del.txt
for /f "delims=" %%l in (C:\services2.txt) do (
	if not "%%l"=="ECHO is off." (
		set name=%%l
		set name=!name:~3!
		set isdefault=n
		for /f "delims=" %%m in (default-services.tmp) do (
		    if %%m==!name! (
		        set isdefault=y
		    )
		)
		if "!isdefault!"=="n" (
    		set /p isValid=Is this service required: !name! (y/n^) 
    		if /I "!isValid!"=="n" (
    			net stop "!stop!" > NUL
    			sc stop "!name!" > NUL
    			sc config "!name!" start= disabled > NUL
    			sc delete "!name!" > NUL
    			echo !name! service disabled and deleted.
        	) else (
        	    echo !name! service accepted as valid.
            )
    	)
    )
)
del C:\del2.txt
echo Services secured.


::Remove Unauthorized Programs
echo.
echo.
echo Press Enter to begin editing installed programs...
pause > NUL
echo.
for /f "delims=" %%b in (' reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall ') do (
    reg export "%%b" tmp1.txt /y > NUL
    find "DisplayName" tmp1.txt > tmp2.txt
    set name=
    for /f tokens^=2^ delims^=^=^" %%x in (tmp2.txt) do set name=%%x
    set isValid=y
    set uninstall=echo No uninstaller found.  Attempting to delete files associated with program...
    if not "!name!"=="" if not "!name!"=="Workstation" (
        set /p isValid=Is !name! a valid program? (y/n^)
        if /I "!isValid!"=="n" (
            find "UninstallString" tmp1.txt > tmp3.txt
            for /f tokens^=3^ delims^=^=^" %%x in (tmp3.txt) do set uninstall=%%x
	        set "uninstall=!uninstall:\\=\!"
            for /f "tokens=* delims= " %%a in ("%uninstall%") do set uninstall=%%a
            for /l %%a in (1,1,100) do if "!uninstall:~-1!"=="\" set uninstall=!uninstall:~0,-1!
            !uninstall!
	        echo Program !name! uninstalled and deleted.
        ) else (
            echo !name! accepted as a valid program.
        )
        echo.
        echo.
    )
)
del tmp1.txt tmp2.txt
echo.
echo Programs configuration complete.



::Secure Processes
echo.
echo.
echo Press enter to begin editing processes...
pause > NUL
echo.
tasklist /svc /fo list > procs.tmp
set counter=1
set name=""
set pid=0
for /f "tokens=2 delims=:" %%l in (procs.tmp) do (
	if "!counter!"=="1" (
		set counter=2
		set name=%%l
		set name=!name:~3!
	) else (
		if "!counter!"=="2" (
			set counter=3
			set pid=%%l
			set pid=!pid:~10!
			echo 3 > counter.tmp
		) else (
			if "!counter!"=="3" (
				set counter=1
				set valid=y
				set isdefault=n
                for /f "delims=" %%m in (default-procs.tmp) do (
                    if %%m==!name! (
                        set isdefault=y
                    )
                )
                if "!isdefault!"=="n" (
    				set /P valid=Is !name! (PID: !pid!^) a valid process? (y/n^): 
    				if /I "!valid!"=="n" (
    				    taskkill /PID !pid!
    				    echo Process !name! (PID: !pid!^) ended.
    				) else (
    				    echo !name!>>default-procs.tmp
    				    echo Process !name! (PID: !pid!^) approved as valid.
    				)
    			)
    		)
		)
	)
)


::Secure Scheduled Tasks
echo.
echo.
echo Press enter to begin editing scheduled tasks...
pause > NUL
echo.
schtasks /query /fo list > tasks.tmp
set counter=1
set name=""
set pid=0
for /f "delims=" %%l in (tasks.tmp) do (
	set line=%%l
	set isname=n
	echo !line! > C:\del1.txt
	for /f "tokens=1 delims=:" %%m in (C:\del1.txt) do (
		 if %%m==TaskName (
			set isname=y
		)
	)
	if !isname!==y (
		for /f "tokens=2 delims=:" %%m in (C:\del1.txt) do set name=%%m
		set name=!name:~6,-1!
		set isdefault=n
		for /f "delims=" %%m in (default-tasks.tmp) do (
		    if %%m==!name! (
		        set isdefault=y
		    )
		)
		if "!isdefault!"=="n" (
		    echo Is this task a valid task:
    		    echo !name!
    		    echo.
    		    set isvalid=y
    		    set /P isvalid=Valid? (y/n^):
    		    if "!isvalid!"=="n" (
    			schtasks /delete /tn "!name!" /f
    			echo Task removed.
    		    ) else (
    			echo Task approved.
    		    )
		    echo.
    		)
		
	)
)
echo.
echo Scheduled tasks secured.



::Dissable unsecure Windows features
echo Dissabling unsecure Windows features, this will take a while...
if !allowIIS!==y (
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-WebServerRole > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-WebServer > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-CommonHttpFeatures > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HttpErrors > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HttpRedirect > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ApplicationDevelopment > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-NetFxExtensibility > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-NetFxExtensibility45 > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HealthAndDiagnostics > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HttpLogging > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-LoggingLibraries > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-RequestMonitor > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HttpTracing > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-Security > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-URLAuthorization > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-RequestFiltering > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-IPSecurity > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-Performance > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HttpCompressionDynamic > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-WebServerManagementTools > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ManagementScriptingTools > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-IIS6ManagementCompatibility > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-Metabase > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HostableWebCore > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-StaticContent > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-DefaultDocument > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-DirectoryBrowsing > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-WebDAV > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-WebSockets > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ApplicationInit > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ASPNET > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ASPNET45 > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ASP > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-CGI > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ISAPIExtensions > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ISAPIFilter > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ServerSideIncludes > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-CustomLogging > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-BasicAuthentication > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-HttpCompressionStatic > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ManagementConsole > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-ManagementService > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-WMICompatibility > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-LegacyScripts > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:IIS-LegacySnapIn > NUL
) else (
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WebServerRole > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WebServer > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-CommonHttpFeatures > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HttpErrors > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HttpRedirect > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ApplicationDevelopment > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-NetFxExtensibility > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-NetFxExtensibility45 > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HealthAndDiagnostics > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HttpLogging > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-LoggingLibraries > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-RequestMonitor > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HttpTracing > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-Security > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-URLAuthorization > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-RequestFiltering > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-IPSecurity > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-Performance > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HttpCompressionDynamic > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WebServerManagementTools > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ManagementScriptingTools > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-IIS6ManagementCompatibility > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-Metabase > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HostableWebCore > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-StaticContent > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-DefaultDocument > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-DirectoryBrowsing > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WebDAV > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WebSockets > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ApplicationInit > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ASPNET > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ASPNET45 > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ASP > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-CGI > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ISAPIExtensions > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ISAPIFilter > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ServerSideIncludes > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-CustomLogging > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-BasicAuthentication > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HttpCompressionStatic > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ManagementConsole > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-ManagementService > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WMICompatibility > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-LegacyScripts > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:IIS-LegacySnapIn > NUL

)

if !allowRDP!==y (
    Dism /Quite /Online /Enable-Feature /FeatureName:WindowsPowerShellWebAccess > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:RemoteAccessMgmtTools > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:RemoteAccessPowerShell > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:RemoteAccess > NUL
    Dism /Quite /Online /Enable-Feature /FeatureName:Remote-Desktop-Services > NUL
) else (
    Dism /Quite /Online /Disable-Feature /FeatureName:WindowsPowerShellWebAccess > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessMgmtTools > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessPowerShell > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccess > NUL
    Dism /Quite /Online /Disable-Feature /FeatureName:Remote-Desktop-Services > NUL
)

if !allowDC!==y (
    Dism /Quite /Online /Enable-Feature /FeatureName:DirectoryServices-DomainController > NUL
) else (
    Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-DomainController > NUL
)

Dism /Quite /Online /Disable-Feature /FeatureName:IIS-FTPServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-FTPSvc > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-FTPExtensibility > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TFTP > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetClient > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RasRoutingProtocols > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Web-Application-Proxy > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetworkController > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetServer > NUL




Dism /Quite /Online /Enable-Feature /FeatureName:NetFx4ServerFeatures > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:NetFx4 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetFx4Extended-ASPNET45 > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShellRoot > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:iSCSITargetServer-PowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:PKIClient-PSH-Cmdlets > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:KeyDistributionService-PSH-Cmdlets > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:TlsSessionTicketKey-PSH-Cmdlets > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Tpm-PSH-Cmdlets > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShellV2 > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:WindowsPowerShellWebAccess > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DataCenterBridging-LLDP-Tools > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Server-Psh-Cmdlets > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShellISE > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessMgmtTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessPowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RasServerAdminTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DamgmtTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WSS-Product-Package > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ActiveDirectory-PowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-DomainController > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-ISM-Smtp > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:HostGuardianService-Package > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-AdministrativeCenter > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccess > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RasRoutingProtocols > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Web-Application-Proxy > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RightsManagementServices-Role > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RightsManagementServices > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RMS-Federation > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RightsManagementServices-AdminTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetworkController > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetworkControllerTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-Metabase > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-WMICompatibility > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-LegacyScripts > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-FTPServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-FTPSvc > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-FTPExtensibility > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WAS-WindowsActivationService > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WAS-ProcessModel > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WAS-NetFxEnvironment > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WAS-ConfigurationAPI > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IIS-HostableWebCore > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-Server > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-Triggers > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-ADIntegration > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-HTTP > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-Multicast > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-DCOMProxy > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSMQ-RoutingServer > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:WCF-Services45 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WCF-HTTP-Activation45 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WCF-TCP-Activation45 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WCF-Pipe-Activation45 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WCF-MSMQ-Activation45 > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:WCF-TCP-PortSharing45 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IdentityServer-SecurityTokenService > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ManagementOdata > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DSC-Service > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ADCertificateServicesRole > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:CertificateServices > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:OnlineRevocationServices > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WebEnrollmentServices > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetworkDeviceEnrollmentServices > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:CertificateEnrollmentPolicyServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:CertificateEnrollmentServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IPAMServerFeature > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DeviceHealthAttestationService > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BITSExtensions-AdminPack > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Gateway-UI > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BITSExtensions-Upload > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WCF-HTTP-Activation > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WCF-NonHTTP-Activation > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Smtpsvc-Admin-Update-Name > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Smtpsvc-Service-Update-Name > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WebAccess > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-Web-Services-for-Management-IIS-Extension > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BusScan-ScanServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-InternetPrinting-Server > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RPC-HTTP_Proxy > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Gateway > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices-Database > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices-WidDatabase > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WorkFolders-Server > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FSRM-Infrastructure > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-FCI-Client-Package > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices-RSAT > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices-API > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:UpdateServices-UI > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FSRM-Infrastructure-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-ADAM > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:IPAMClientFeature > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-ServerEssentials-ServerSetup > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:AuthManager > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:ServerCore-WOW64 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-Server-Foundation-Features > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-Server-Role > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-LPDPrintService > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Printing-Client > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Printing-Client-Gui > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:ServerCore-EA-IME-WOW64 > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetFx3ServerFeatures > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetFx3 > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Server-Shell > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Internet-Explorer-Optional-amd64 > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Server-Gui-Mgmt > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Server-Gui-Mgmt_onecore > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:RSAT > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Storage-Replica-AdminPack > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Server-Manager-RSAT-File-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Server-RSAT-SNMP > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DNS-Server-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WINS-Server-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DfsMgmt > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ADCertificateServicesManagementTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:CertificateServicesManagementTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:OnlineRevocationServicesManagementTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RSAT-AD-Tools-Feature > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RSAT-ADDS-Tools-Feature > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-DomainController-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectoryServices-ADAM-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BitLocker-RemoteAdminTool > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BdeAducExtTool > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NPSMMC > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Licensing-UI > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Licensing-Diagnosis-UI > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-Deployment-Services-Admin-Pack > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DHCPServer-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FailoverCluster-Mgmt > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetworkLoadBalancingManagementClient > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NFS-Administration > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:WindowsServerBackupSnapin > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FaxServiceConfigRole > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NPSManagementTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RightsManagementServicesManagementTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Security-SPP-Vmw > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FSRM-Management > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Windows-Defender-Gui > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Offline > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Online > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RSAT-Hyper-V-Tools-Feature > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Management-Clients > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Management-PowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:VmHostAgent > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:HostGuardian > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:AppServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-Deployment-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-Deployment-Services-Deployment-Server > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-Deployment-Services-Transport-Server > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:BitLocker > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Bitlocker-Utilities > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ShieldedVMToolsAdminPack > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BitLocker-NetworkUnlock > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SearchEngine-Server-Package > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:File-Services-Search-Service > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FaxServiceRole > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NPAS-Role > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:OEM-Appliance-OOBE > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServerMediaFoundation > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:MediaPlayback > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:WindowsMediaPlayer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WebDAV-Redirector > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:LegacyComponents > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DirectPlay > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-LPRPortMonitor > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-InternetPrinting-Client > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Printing-AdminTools-Collection > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Windows-Identity-Foundation > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V-Common-Drivers-Package > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Microsoft-Hyper-V-Guest-Integration-Drivers-Package > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Microsoft-Windows-NetFx-VCRedist-Package > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Microsoft-Windows-Printing-PrintToPDFServices-Package > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Microsoft-Windows-Printing-XPSServices-Package > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Microsoft-Windows-Client-EmbeddedExp-Package > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Printing-PrintToPDFServices-Features > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Printing-XPSServices-Features > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MSRDC-Infrastructure > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TelnetClient > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TFTP > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:TIFFIFilter > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:SMB1Protocol > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MultiPoint-Connector > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MultiPoint-Connector-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MultiPoint-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServerManager-Core-RSAT > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServerManager-Core-RSAT-Role-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServerManager-Core-RSAT-Feature-Tools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FailoverCluster-AdminPak > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FailoverCluster-PowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:HardenedFabricEncryptionTask > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServicesForNFS-ServerAndClient > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServerForNFS-Infrastructure > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ClientForNFS-Infrastructure > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SimpleTCP > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:SmbDirect > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Windows-Defender-Features > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Windows-Defender > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:EnhancedStorage > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Microsoft-Windows-GroupPolicy-ServerAdminTools-Update > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RSAT-RDS-Tools-Feature > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:BiometricFramework > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WindowsServerBackup > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DFSR-Infrastructure-ServerEdition > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DNS-Server-Full-Role > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Windows-Internal-Database > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:iSCSITargetStorageProviders > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:BITS > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:LightweightServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MultipathIo > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:NetworkLoadBalancingFullServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Containers > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:PeerDist > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:ServerCore-EA-IME > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DataCenterBridging > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DiskIo-QoS > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Server-Drivers-General > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Server-Drivers-Printers > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SNMP > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WMISnmpProvider > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WindowsStorageManagementService > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SessionDirectory > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SBMgr-UI > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:VolumeActivation-Full-Role > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WirelessNetworking > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Xps-Foundation-Xps-Viewer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SMBBW > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SetupAndBootEventCollection > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RasCMAK > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DFSN-Server > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:DHCPServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FailoverCluster-AutomationServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FailoverCluster-CmdInterface > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FRS-Infrastructure > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FileServerVSSAgent > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:WINSRuntime > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:iSCSITargetServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:iSNS_Service > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:P2P-PnrpOnly > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:QWAVE > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ServerMigration > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SMBHashGeneration > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Licensing > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FailoverCluster-FullServer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:CCFFilter > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Dedup-Core > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:MultiPoint-Role > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:ResumeKeyFilter > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SmbWitness > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:FabricShieldedTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Storage-Replica > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:SoftwareLoadBalancer > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RasRip > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:SearchEngine-Client-Package > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Client-DeviceLockdown > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Client-EmbeddedShellLauncher > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Client-EmbeddedBootExp > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Client-EmbeddedLogon > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Client-KeyboardFilter > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Client-UnifiedWriteFilter > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:FileAndStorage-Services > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:Storage-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:File-Services > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:CoreFileServer > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:ServerCore-Drivers-General > NUL
Dism /Quite /Online /Enable-Feature /FeatureName:ServerCore-Drivers-General-WOW64 > NUL


echo Unsecure Windows features dissabled



::Find and delete media files
echo Searching for media files.
echo Flashing file system to reference file...
:: Flash disk to .log file for reference
dir /b /s "C:\Users" > users.log
dir /b /s "C:\Program Files" > programs.log
dir /b /s "C:\Program Files (x86)" >> programs.log
type NUL > media.log
type NUL > MediaFiles.log
type NUL > readme.log
echo Records created.
echo Finding media files in C:\Users and C:\Documents and Settings...
findstr /i .*\.jpg users.log >> media.log
findstr /i .*\.jpeg users.log >> media.log
findstr /i .*\.ac3 users.log >> media.log
findstr /i .*\.aac users.log >> media.log
findstr /i .*\.aiff users.log >> media.log
findstr /i .*\.flac users.log >> media.log
findstr /i .*\.m4a users.log >> media.log
findstr /i .*\.m4p users.log >> media.log
findstr /i .*\.midi users.log >> media.log
findstr /i .*\.mp2 users.log >> media.log
findstr /i .*\.mp3 users.log >> media.log
findstr /i .*\.mp4 users.log >> media.log
findstr /i .*\.m3u users.log >> media.log
findstr /i .*\.ogg users.log >> media.log
findstr /i .*\.vqf users.log >> media.log
findstr /i .*\.wav users.log >> media.log
findstr /i .*\.wma users.log >> media.log
findstr /i .*\.avi users.log >> media.log
findstr /i .*\.mpeg4 users.log >> media.log
findstr /i .*\.gif users.log >> media.log
findstr /i .*\.png users.log >> media.log
findstr /i .*\.bmp users.log >> media.log

findstr /i /v "windows microsoft cyberpatriot cache appdata" media.log >> MediaFiles.log
C:\WINDOWS\system32\notepad.exe MediaFiles.log
echo "Press enter when you are ready to delete all media files..."
pause
echo Deleting all media files...
for /f "tokens=*" %%A in (MediaFiles.log) do del "%%A"
echo All media files Removed.
echo Searching for README files...
findstr /i "readme" programs.log > readme.log
echo Displaying list of README file locations, take note and then close notepad to continue script...
C:\WINDOWS\system32\notepad.exe readme.log
findstr /i .*\.exe users.log > exe.log
findstr /i .*\.exe programs.log >> exe.log
echo Displaying list of .exe file locations, take note and then close notepad to continue script...
C:\WINDOWS\system32\notepad.exe exe.log
findstr /i .*nmap.* programs.log > suspicious.log
findstr /i .*ploit.* programs.log >> suspicious.log
findstr /i .*cain.* programs.log >> suspicious.log
findstr /i .*keylog.* programs.log >> suspicious.log
findstr /i .*armitage.* programs.log >> suspicious.log
findstr /i .*shellter.* programs.log >> suspicious.log
findstr /i .*crack.* programs.log >> suspicious.log
findstr /i .*ripper.* programs.log >> suspicious.log
findstr /i .*hack.* programs.log >> suspicious.log
findstr /i .*toor.* programs.log >> suspicious.log
findstr /i .*root.* programs.log >> suspicious.log
findstr /i .*virus.* programs.log >> suspicious.log
findstr /i .*nmap.* users.log >> suspicious.log
findstr /i .*ploit.* users.log >> suspicious.log
findstr /i .*cain.* users.log >> suspicious.log
findstr /i .*keylog.* users.log >> suspicious.log
findstr /i .*armitage.* users.log >> suspicious.log
findstr /i .*shellter.* users.log >> suspicious.log
findstr /i .*crack.* users.log >> suspicious.log
findstr /i .*ripper.* users.log >> suspicious.log
findstr /i .*hack.* users.log >> suspicious.log
findstr /i .*toor.* users.log >> suspicious.log
findstr /i .*root.* users.log >> suspicious.log
findstr /i .*virus.* users.log >> suspicious.log
echo Displaying list of suspicious file locations, take note and the close notepad to continue the script...
C:\WINDOWS\system32\notepad.exe suspicious.log


::Download Microsoft Baseline Security Analyzer
bitsadmin /transfer mbsa /download https://download.microsoft.com/download/8/E/1/8E16A4C7-DD28-4368-A83A-282C82FC212A/MBSASetup-x64-EN.msi C:\MBSA.msi
::Download SysInternals
bitsadmin /transfer sysinternals /download https://download.sysinternals.com/files/SysinternalsSuite.zip C:\SysInternals.zip
::Download AVG
bitsadmin /transfer avg-installer /download http://files-download.avg.com/inst/mp/AVG_Protection_Free_1606.exe C:\AVG-Installer.exe
::Download Malwarebytes
bitsadmin /transfer malwarebytes-installer /download https://data-cdn.mbamupdates.com/web/mb3-setup-consumer/mb3-setup-consumer-3.3.1.2183-1.0.262-1.0.3374.exe C:\Malwarebytes-Installer.exe
::Download CCleaner
bitsadmin /transfer malwarebytes-installer /download http://download.ccleaner.com/ccsetup539.exe C:\CCleaner-Installer.exe

::Run MBSA
start C:\MBSA.msi
::Run AVG Installer
start C:\AVG-Installer.exe
::Run Malwarebytes Installer
start C:\Malwarebytes-Installer.exe
::Run CCleaner Insatller
start C:\CCleaner-Installer.exe

echo Script complete!
echo Manually restart is required to apply some changes.  Please restart Windows at some point when you have a chance.
echo.
echo.
echo Checklist for next steps: (Press enter once step is complete.)
echo.
echo 1) Start AVG installation
pause > NUL
echo    a) Start AVG Virus scan of system
pause > NUL
echo.
echo 2) Run MBSA and scan computer (Deselect "Scan for updates" option for speed)
pause > NUL
echo.
echo 3) Re-read README
pause > NUL
echo.
echo 4) Finish any tasks required by README (Create new users/groups, install software, etc.)
pause > NUL
echo.
echo 5) Ensure that all malicious software has been removed (Control Panel > Programs > Uninstall Programs)
pause > NUL
echo.
echo 6) Open Firefox, click on the menu button in the top right corner, click on the question mark at the bottom of the menu, and allow firefox to update.  Once firefox restarts, keep checking for updates until it says that firefox is up to date.
pause > NUL
echo 7) Open Firefox, click on the menu button in the top right corner, click on "Options", and ensure the following options are set:
echo      a) Enable "Always check if Firefox is your default browser"
pause > NUL
echo      b) When Firefox starts - Show your home page
pause > NUL
echo      c) Homepage - www.google.com
pause > NUL
echo      d) Downloads - Save files to Downloads
pause > NUL
echo      e) Applications - Make sure all lines are set to "Always Ask"
pause > NUL
echo      f) Updates
echo          a) Click "Check for Updates" - If updates are downloaded, restart Firefox and repeat until it says Firefox is up to date
pause > NUL
echo          b) Enable "Use a background service to install updates"
pause > NUL
echo          c) Enable "Automatically update search engines"
pause > NUL
echo          d) Set "Allow Firefox to Automatically install updates"
pause > NUL
echo      g) Enable "Use recommended performance settings"
pause > NUL
echo      h) Network Prox (Click "Settings")
pause > NUL
echo          a) Select "Use system proxy settings" and click "OK"
pause > NUL
echo      i) Search (Click the search icon on the left sidebar)
pause > NUL
echo          a) Set the default search engine to Google
pause > NUL
echo          b) Remove all search engines from the list except for Google
pause > NUL
echo      j) Security (Click the lock icon on the left sidebar)
pause > NUL
echo          a) Disable "Remember logins and passwords for websites"
pause > NUL
echo          b) Disable "Use a master password"
pause > NUL
echo          c) Click "Saved Logins", click "Remove All" if there are any entries, then "Save Changes"
pause > NUL
echo          d) Set History to "Never remember history", and restart firefox.  Return to the security settings menu.
pause > NUL
echo          e) Cached Web Content - Click "Clear Now"
pause > NUL
echo          f) Disable "Override automatic cache management"
pause > NUL
echo          g) Site Data - Click "Clear All Data"
pause > NUL
echo          h) Set Tracking Protection to "Always"
pause > NUL
echo          i) Click "Exceptions", click "Remove All Websites" if there are any entries, then "Save Changes"
pause > NUL
echo          j) Set "Send Websites 'Do Not Track' signals" to "Always"
pause > NUL
echo          k) In the "Permissions" section, go through all the sections, clicking "Settings", "Remove All Websites", and "Save Changes"
pause > NUL
echo          l) Enable "Block pop-up windows"
pause > NUL
echo          m) Enable "Warn you when websites try to install add-ons"
pause > NUL
echo          n) For both of the two options above, click "Exceptions" and remove any exceptions.
pause > NUL
echo          o) Enable "Prevent accessability services from accessing your browser"
pause > NUL
echo          p) Enable "Block dangerous and deceptive content"
pause > NUL
echo          q) Enable "Block dangerous downloads"
pause > NUL
echo          r) Enable "Warn you about unwanted and uncommon software"
pause > NUL
echo          s) In "Certificates", select "Ask you every time"
pause > NUL
echo          t) Enable "Query OCSP responder servers to confirm the current validity of certificates"
pause > NUL
echo          u) Click "View Certificates", and delete any entries in the "Your Certificates", "People", and "Others" sections
pause > NUL
echo 8) Secure installed roles and services
echo    a) If you are on a server image, follow these directions, otherwise skip ahead to the desktop instructions:
echo        a) Open the Server Manager (Should be open already, if not click on the icon right next to the windows icon in the bottom left corner^)
pause > NUL
echo        b) In the left-hand list of the Server Manager, click on 'Roles'
pause > NUL
echo        c) If it is not disabled, click on 'Remove Roles' on the right side
pause > NUL
echo        d) Remove any roles that are not specifically required by the README, but do not restart right now
pause > NUL
echo        e) If the README requires you to add any roles, do so using the 'Add Roles' button
pause > NUL
echo    b) If you are on a desktop image, start here
echo        a) Open the Control Panel (Click the Windows icon the bottom left, then click 'Control Panel', or just search for it in Windows 10^)
pause > NUL
echo        b) Click on 'Programs'
pause > NUL
echo        c) Turn Windows features on or off'
pause > NUL
echo        d) Remove any roles that are not specifically required by the README, but do not restart right now
pause > NUL
echo 9) Open up Internet Explorer (Or Edge on Windows 10^)
pause > NUL
echo        a) For Microsoft Edge:
echo            a) Click the '...' button in the top right corner, then click 'Settings', then click 'Advanced Settings'
pause > NUL
echo            b) Ensure 'Block pop-ups' is enabled
pause > NUL
echo            c) Ensure 'Ask me what to do with each download' is enabled
pause > NUL
echo            d) Ensure 'Offer to save passwords' is disabled
echo > NUL
echo            e) Ensure 'Save form entries' is disabled
echo > NUL
echo            f) Ensure 'Send Do Not Track requests' is enabled
echo > NUL
echo            g) At the bottom of the options, ensure that 'Help protect me from malicious sites and downloads with SmartScreen filter' is enabled
pause > NUL
echo        b) Close Microsoft Edge
echo 11) Search for 'mmc' and launch it
pause > NUL
echo        a) In the top left menu of mmc, click 'File', click 'Add/Remove snap-in'
pause > NUL
echo        b) Add the following items by clicking them and then clicking the 'Add' button.  If a dialog box pops up asking anything, just click 'OK' or 'Finish'
pause > NUL
echo            a) Computer Management
pause > NUL
echo            b) Event Viewer
pause > NUL
echo            c) Group Policy Object
pause > NUL
echo            d) Local Users and Groups
pause > NUL
echo            e) Security Configuration
pause > NUL
echo            f) Services
pause > NUL
echo            g) Shared Folders
pause > NUL
echo            h) Task Scheduler
pause > NUL
echo            i) Windows Firewall
pause > NUL
echo        c) Click 'OK' to add snap in's
pause > NUL
echo        d) In the top left menu of mmc, click 'File', click 'Save As', select the 'Desktop', and click 'Save'
pause > NUL
echo        e) Close mmc
pause > NUL
echo 12) Click on the Windows Icon in the bottom right corner, then click on 'Computer', select the 'C' drive from the lefthand menu, right click on the 'SysInternals' zipped folder, select 'Extract All', and select 'OK'
echo 13) Only for Desktop Images (DO NOT RUN ON SERVER IMAGES) -  Click on the Windows Icon in the bottom right corner, then click on 'Computer', select the 'C' drive from the lefthand menu, then open the 'GodMode' folder.  Double click on 'Godmode', and go through the full list of settings, checking everything to make sure that it is secure.
pause > NUL
echo 14) Open up the control panel and search for 'java', then if a Java option is found open it.
pause > NUL
echo    a) Open the 'Update' tab at the top
pause > NUL
echo        a) Ensure 'Check for Updates Automatically' is enabled
pause > NUL
echo        b) Select 'Notify me Before installing'
pause > NUL
echo        c) Click on 'Advanced'
pause > NUL
echo        d) Set 'Frequency' to 'Daily' and click 'Close'
pause > NUL
echo    b) Open the 'Security' tab at the top
pause > NUL
echo        a) Enable 'Enable Java content on the browser'
pause > NUL
echo        b) Set the security level to 'Very High'
pause > NUL
echo    c) Click 'Apply' and then 'OK' to close the configuration window
pause > NUL
echo 15) Click on the Windows Button on the bottom left corner, search for 'gpedit.msc', and run it.
pause > NUL
echo    a) Expand 'Computer Configuration', and then click on 'Administrative Templates'
pause > NUL
echo    b) In the top menu bar, click 'Action', then 'Filter Options...'
pause > NUL
echo    c) Set 'Managed' to 'Any', 'Configured' to 'Yes', 'Commented' to 'Any', and click 'OK'
pause > NUL
echo    d) In the top menu bar, click 'Action', and make sure 'Filter' is 'On'
pause > NUL
echo    e) Under 'Computer Configuration', expand 'Windows Settings', and expand 'Security Settings'
pause > NUL
echo        a) Under 'Account Policies', expand 'Password Policy', and ensure the following settings are set:
pause > NUL
echo            a) Enforce Password History: 5 passwords remembered
echo    f) Under 'Computer Configuration', expand 'Administrative Templates', and click on 'All Settings'
pause > NUL
echo    g) Look over the settings to ensure that all the settings are secure, and then leave this window open for later
pause > NUL
echo 16) Write down the username for the account you are currently logged into (as per the README)
pause > NUL
echo 17) Restart Windows
echo.
echo.
echo.
echo.
echo *****************SCRIPT COMPLETE!*************

::Termination Block
:Terminate
pause







