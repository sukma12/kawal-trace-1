; Kawal Trace app version 1.0.1 / internal build 13. Installer is created by the CI workflow.
#ifndef AppExe
  #define AppExe "Kawal-Trace.exe"
#endif
#ifndef AppDir
  #define AppDir "..\build\windows"
#endif
#ifndef AppVersion
  #define AppVersion "1.0.1"
#endif

[Setup]
AppId={{8F3C2B1A-5D4E-4C6B-9A7F-1E2D3C4B5A69}
AppName=Kawal Trace
AppVersion={#AppVersion}
AppPublisher=Kawal Trace
DefaultDirName={autopf}\Kawal Trace
DefaultGroupName=Kawal Trace
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=Kawal-Trace-Setup
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "Buat ikon di Desktop"; GroupDescription: "Ikon tambahan:"

[Files]
Source: "{#AppDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Kawal Trace"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\Kawal Trace"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Jalankan Kawal Trace"; Flags: nowait postinstall skipifsilent
