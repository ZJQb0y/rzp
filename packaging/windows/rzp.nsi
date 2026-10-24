; RZP Windows 安装脚本
; 由 package.sh 通过 -D 传入 VERSION / VIVERSION / ARCH / OUTFILE / STAGEDIR 等参数。
; 标签与语言参照独立 Windows 版（package.ps1）保持一致。

Unicode true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "StrFunc.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef VIVERSION
  !define VIVERSION "0.0.0.0"
!endif
!ifndef ARCH
  !define ARCH "x86_64"
!endif
!ifndef PUBLISHER
  !define PUBLISHER "张俊琦"
!endif
!ifndef OUTFILE
  !define OUTFILE "rzp-setup.exe"
!endif
!ifndef STAGEDIR
  !define STAGEDIR "."
!endif

Name "RZP ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "D:\RZP"
InstallDirRegKey HKLM "Software\RZP" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!cd "${STAGEDIR}"

VIProductVersion "${VIVERSION}"
VIAddVersionKey "ProductName" "RZP"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "RZP 压缩工具"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) ${PUBLISHER}"

${StrStr}
${UnStrRep}

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Section "RZP" SecMain
  SetOutPath "$INSTDIR"
  File "rzp.exe"
  File "README.md"
  File "FORMAT.md"
  File "API.md"
  File "LICENSE"

  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "DisplayName" "RZP 压缩工具"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP" "NoRepair" 1

  WriteRegStr HKLM "Software\RZP" "InstallDir" "$INSTDIR"

  ; 关联 .rzp 文件图标（默认图标取 rzp.exe 内嵌图标，索引 0）
  WriteRegStr HKLM "Software\Classes\.rzp" "" "RZP.Archive"
  WriteRegStr HKLM "Software\Classes\RZP.Archive" "" "RZP 压缩档案"
  WriteRegStr HKLM "Software\Classes\RZP.Archive\DefaultIcon" "" '$INSTDIR\rzp.exe,0'
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'

  Call AddToPath

  CreateDirectory "$SMPROGRAMS\RZP"
  CreateShortcut "$SMPROGRAMS\RZP\卸载 RZP.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\RZP\README.lnk" "$INSTDIR\README.md"
SectionEnd

Function AddToPath
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${StrStr} $1 "$0" "$INSTDIR"
  ${If} $1 != ""
    Return
  ${EndIf}
  ${If} $0 == ""
    StrCpy $0 "$INSTDIR"
  ${Else}
    StrCpy $0 "$0;$INSTDIR"
  ${EndIf}
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd

Function un.RemoveFromPath
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${If} $0 == ""
    Return
  ${EndIf}
  ${UnStrRep} $1 "$0" "$INSTDIR;" ""
  ${UnStrRep} $2 "$1" ";$INSTDIR" ""
  ${UnStrRep} $3 "$2" "$INSTDIR" ""
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$3"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
FunctionEnd

Section "Uninstall"
  Call un.RemoveFromPath
  Delete '$INSTDIR\rzp.exe'
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\FORMAT.md"
  Delete "$INSTDIR\API.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\RZP\卸载 RZP.lnk"
  Delete "$SMPROGRAMS\RZP\README.lnk"
  RMDir "$SMPROGRAMS\RZP"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\RZP"
  DeleteRegKey HKLM "Software\RZP"

  ; 清理 .rzp 文件关联（仅在仍指向本 ProgID 时删除 .rzp 键）
  ReadRegStr $0 HKLM "Software\Classes\.rzp" ""
  ${If} $0 == "RZP.Archive"
    DeleteRegKey HKLM "Software\Classes\.rzp"
  ${EndIf}
  DeleteRegKey HKLM "Software\Classes\RZP.Archive"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
SectionEnd
