#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{E2861D19-8C54-47C1-AF53-6D2242946816}
AppName=CipherMesh
AppVersion={#AppVersion}
AppPublisher=Charles Zheng
AppPublisherURL=https://github.com/charleszheng0/ciphermesh
DefaultDirName={localappdata}\Programs\CipherMesh
DefaultGroupName=CipherMesh
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=CipherMesh-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\ciphermesh.exe
SetupLogging=yes

[Files]
Source: "..\..\target\release\ciphermesh.exe"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{userappdata}\CipherMesh\target"

[Icons]
Name: "{group}\CipherMesh"; Filename: "{app}\ciphermesh.exe"; WorkingDir: "{userappdata}\CipherMesh"
Name: "{group}\Uninstall CipherMesh"; Filename: "{uninstallexe}"
Name: "{autodesktop}\CipherMesh"; Filename: "{app}\ciphermesh.exe"; WorkingDir: "{userappdata}\CipherMesh"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\ciphermesh.exe"; Description: "Launch CipherMesh"; WorkingDir: "{userappdata}\CipherMesh"; Flags: nowait postinstall skipifsilent
