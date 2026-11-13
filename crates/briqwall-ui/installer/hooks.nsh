; Briqwall installer hooks – included by Tauri's NSIS template.
;
; The UI (briqwall.exe) is the main binary; the firewall service
; (briqwall-service.exe) ships next to it and is registered here.
; WFP filters are persistent, so the machine stays protected while the
; service is briefly stopped during an upgrade.
;
; The installer language follows Windows (German or English); messages here
; pick the matching text at runtime (1031 = German).

!macro BRIQ_DETAIL DE EN
  ${If} $LANGUAGE == 1031
    DetailPrint "${DE}"
  ${Else}
    DetailPrint "${EN}"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Upgrade: stop the running service so its executable can be replaced.
  !insertmacro BRIQ_DETAIL "Firewall-Dienst wird angehalten …" "Stopping firewall service …"
  nsExec::ExecToLog 'net stop briqwall'
  Pop $0

  ; Migration from the previous product name "xWall". Its service is removed,
  ; its rules (C:\ProgramData\xWall) are adopted by Briqwall on first start.
  ${If} ${FileExists} "$PROGRAMFILES64\xWall\xwall-service.exe"
    !insertmacro BRIQ_DETAIL "Vorgängerversion xWall wird ersetzt (Regeln werden übernommen) …" "Replacing previous version xWall (rules are kept) …"
    nsExec::ExecToLog 'taskkill /F /IM xwall-ui.exe'
    Pop $0
    nsExec::ExecToLog '"$PROGRAMFILES64\xWall\xwall-service.exe" uninstall'
    Pop $0
    Delete "$PROGRAMFILES64\xWall\xwall-service.exe"
    Delete "$PROGRAMFILES64\xWall\xwall-ui.exe"
    RMDir "$PROGRAMFILES64\xWall"
    ReadEnvStr $1 "ProgramData"
    Delete "$1\Microsoft\Windows\Start Menu\Programs\xWall.lnk"
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro BRIQ_DETAIL "Firewall-Dienst wird eingerichtet …" "Setting up firewall service …"
  nsExec::ExecToLog '"$INSTDIR\briqwall-service.exe" install'
  Pop $0
  ${If} $0 != 0
    ${If} $LANGUAGE == 1031
      MessageBox MB_ICONEXCLAMATION|MB_OK "Der Firewall-Dienst konnte nicht eingerichtet werden (Code $0).$\r$\nDetails: C:\ProgramData\Briqwall\service.log" /SD IDOK
    ${Else}
      MessageBox MB_ICONEXCLAMATION|MB_OK "The firewall service could not be set up (code $0).$\r$\nDetails: C:\ProgramData\Briqwall\service.log" /SD IDOK
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode = 1
    ; Part of an update: keep service registration and filters.
    nsExec::ExecToLog 'net stop briqwall'
    Pop $0
  ${Else}
    !insertmacro BRIQ_DETAIL "Firewall-Dienst und alle Filter werden entfernt …" "Removing firewall service and all filters …"
    ${If} $DeleteAppDataCheckboxState = 1
      nsExec::ExecToLog '"$INSTDIR\briqwall-service.exe" uninstall --purge'
    ${Else}
      nsExec::ExecToLog '"$INSTDIR\briqwall-service.exe" uninstall'
    ${EndIf}
    Pop $0
    ; Per-user integration of the user running the uninstaller.
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Briqwall"
    DeleteRegKey HKCU "Software\Classes\briqwall"
    DeleteRegKey HKCU "Software\Classes\AppUserModelId\Briqwall.Firewall"
    DeleteRegKey HKCU "Software\Briqwall"
  ${EndIf}
!macroend
