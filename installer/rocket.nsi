; Rocket Client installer — plain NSIS 3 script (no Tauri bundler involved).
Unicode true

!define APP_NAME "Rocket Client"
!define APP_VER  "1.0.4"
!define APP_PUB  "Rocket Client"
!define APP_EXE  "Rocket Client.exe"

Name "${APP_NAME}"
OutFile "Rocket Client Setup ${APP_VER}.exe"
InstallDir "$PROGRAMFILES64\Rocket Client"
InstallDirRegKey HKLM "Software\RocketClient" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APP_NAME} ${APP_VER}"

!include "MUI2.nsh"

!define MUI_ICON   "..\src-tauri\icons\icon.ico"
!define MUI_UNICON "..\src-tauri\icons\icon.ico"
!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "立即启动 ${APP_NAME}"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "SimpChinese"

VIProductVersion "1.0.4.0"
VIAddVersionKey /LANG=2052 "ProductName"     "${APP_NAME}"
VIAddVersionKey /LANG=2052 "FileDescription" "SSL VPN 客户端"
VIAddVersionKey /LANG=2052 "FileVersion"     "${APP_VER}"
VIAddVersionKey /LANG=2052 "ProductVersion"  "${APP_VER}"
VIAddVersionKey /LANG=2052 "LegalCopyright"  "${APP_PUB}"

Section "安装" SecMain
  SetShellVarContext all
  SetOutPath "$INSTDIR"

  ; A running instance would lock the exe; kill it silently first.
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM "${APP_EXE}"'
  Pop $0
  Sleep 600

  File "payload\${APP_EXE}"
  File "payload\wintun.dll"

  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\RocketClient" "InstallDir" "$INSTDIR"

  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "DisplayName"     "${APP_NAME}"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "DisplayVersion"  "${APP_VER}"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "Publisher"       "${APP_PUB}"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "DisplayIcon"     "$INSTDIR\${APP_EXE}"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "NoRepair" 1

  ; Rough size in KB, shown in 控制面板 → 程序和功能
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient" "EstimatedSize" 4000
SectionEnd

Section "Uninstall"
  SetShellVarContext all

  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM "${APP_EXE}"'
  Pop $0
  Sleep 600

  ; Remove the routes this app may have left behind.
  nsExec::Exec '"$SYSDIR\route.exe" delete 10.0.0.0 mask 255.0.0.0'
  Pop $0
  nsExec::Exec '"$SYSDIR\route.exe" delete 172.16.0.0 mask 255.240.0.0'
  Pop $0
  nsExec::Exec '"$SYSDIR\route.exe" delete 192.0.2.0 mask 255.255.255.0'
  Pop $0

  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  Delete "$DESKTOP\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk"
  Rmdir  "$SMPROGRAMS\${APP_NAME}"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RocketClient"
  DeleteRegKey HKLM "Software\RocketClient"
SectionEnd
