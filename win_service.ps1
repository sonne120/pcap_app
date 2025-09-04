# Elevation check (self-elevate if not admin)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}

$svcName = "PacketCaptureService"
$binPath = "C:\repo\cppp\4\pcap_app\serviceApp\Debug\serviceApp.exe"

# If service exists, remove it first
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
  Stop-Service $svcName -ErrorAction SilentlyContinue
  sc.exe delete $svcName | Out-Null
  Start-Sleep -Seconds 1
}

# Install (LocalSystem by default)
New-Service `
  -Name $svcName `
  -BinaryPathName "`"$binPath`"" `
  -DisplayName "Packet Capture Service" `
  -Description "Captures packets using Npcap and forwards snapshots." `
  -StartupType Automatic

# Start and show status
Start-Service $svcName
Get-Service $svcName

# Start
Start-Service PacketCaptureService
Get-Service PacketCaptureService

# Stop + Uninstall
Stop-Service PacketCaptureService -ErrorAction SilentlyContinue
sc.exe delete PacketCaptureService same for admin

# traking data
 powershell -NoProfile -Command "Get-Content 'C:\ProgramData\pcap_app\logs\serviceApp.log' -Tail 50 -Wait"