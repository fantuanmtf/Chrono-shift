!define PRODUCT_NAME "Chrono-shift"
!define PRODUCT_VERSION "8.1"
!define RELEASE_DIR "D:\GitHub\chrono-bin"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${RELEASE_DIR}\Chrono-shift-Setup.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

Section "Install"
    SetOutPath "$INSTDIR"

    ; Main daemon (pure Rust, zero DLL dependencies)
    File "${RELEASE_DIR}\chrono-daemon.exe"

    ; Data directory
    CreateDirectory "$INSTDIR\data"

    ; Shortcuts
    CreateShortCut "$DESKTOP\Chrono-shift.lnk" "$INSTDIR\chrono-daemon.exe"
    WriteUninstaller "$INSTDIR\uninst.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME} ${PRODUCT_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "Publisher" "Chrono-shift Team"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" '"$INSTDIR\uninst.exe"'
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\chrono-daemon.exe"
    Delete "$INSTDIR\uninst.exe"
    RMDir /r "$INSTDIR\data"
    Delete "$DESKTOP\Chrono-shift.lnk"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
SectionEnd
