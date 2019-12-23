Import-Module -Global -Name .\modSysinfo.psm1 -Force

$ErrorActionPreference = 'SilentlyContinue'

$hosts     = Get-HostList
$varPcList = Get-PcList
$varDate   = Get-Date

foreach($ComputerName in $hosts)
{
  if(Test-Connection -ComputerName $ComputerName -Quiet -Count 1)
  {
    # Disk Warning thresholds
    [float] $levelWarn  = 20.0
    # Warn-level in percent.
    [float] $levelAlarm = 10.0
    # Alarm-level in percent.
  
    # Variables
    $varBios            = Get-WmiObject -ComputerName $ComputerName -Class Win32_BIOS
    $varCompSys         = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem
    $varMemory          = Get-WmiObject -ComputerName $ComputerName -Class Win32_PhysicalMemory
    $varCPU             = Get-WmiObject -ComputerName $ComputerName -Class Win32_Processor
    $varOS              = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem
    $varDisks           = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Filter 'DriveType = 3'
    $varIPv4addr        = Get-IPv4Addr -ComputerName $ComputerName
    $varDomainRole      = Get-DomainRole -type $varCompSys.DomainRole
    $varRDPInfo         = Get-RDP -ComputerName $ComputerName
    $varSysDevices      = Get-SysDevices -ComputerName $ComputerName
    $varIsSql           = Test-SqlSvr -ComputerName $ComputerName
    $varIsDell          = Test-Dell -ComputerName $ComputerName
      
    try 
    {
      $varInstalledSw     = Get-InstalledSoftware -ComputerName $ComputerName |
      Where-Object -FilterScript {
        ($_.DisplayName -like 'Microsoft*' -or $_.DisplayName -like '*fax*' -or $_.DisplayName -like '*Backup*' -or $_.DisplayName -like '*Symantec*' -or $_.DisplayName -like '*Allscripts*' -or $_.DisplayName -like '*Misys*' -or $_.DisplayName -like '*Brooktrout*' -or $_.DisplayName -like '*Medflow*') -and ($_.DisplayName -notlike '*KB*' -and $_.DisplayName -notlike '*Update*' -and $_.DisplayName -notlike '*Hotfix*' -and $_.DisplayName -notlike '*C++*' -and $_.DisplayName -notlike '*Visual*' -and $_.DisplayName -notlike '*.Net*')
      } |
      Select-Object -Property DisplayName, Version |
      Sort-Object -Property DisplayName
    }
    catch 
    {
      ('Error gathering software inventory from {1}: Message was {0}' -f $_.Exception.Message, $ComputerName)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error occurred in Line {0}' -f $line)
    }
    if ($varIsDell)
    {
      try
      {
        # Content
        $varPercInfo        = Get-PercInfo -ComputerName $ComputerName
      }
      catch
      {
        ('Error gathering Perc data from {1}: Message was {0}' -f $_.Exception.Message, $ComputerName)
        $line = $_.InvocationInfo.ScriptLineNumber
        ('Error occurred in Line {0}' -f $line)
      }
    }
    else
    {
      $varPercInfo = ('{0} is not a Dell' -f $ComputerName)
    }   
    
    if ($varIsSql)
    {
      try
      {
        # Content
        $varSqlVersion      = Invoke-Sqlcmd2 -ComputerName $ComputerName -Query 'sp_SERVER_INFO' | Select-Object -Property attribute_value -ExcludeProperty attribute_id, attribute_name -ExpandProperty attribute_value -Skip 1 -First 1
        $varDBTotal         = Invoke-Sqlcmd2 -ComputerName $ComputerName -Total | Select-Object -Property UsedSpace -ExpandProperty UsedSpace
        $varSqlDbs          = Invoke-Sqlcmd2 -ComputerName $ComputerName
      }
      catch
      {
        ('Error gathering SQL data from {1}: Message was {0}' -f $_.Exception.Message, $ComputerName)
        $line = $_.InvocationInfo.ScriptLineNumber
        ('Error occurred in Line {0}' -f $line)
      }
    }
          
   
    # Formats
    $fmtDbName          = @{
      label      = 'DB Name'
      alignment  = 'left'
      width      = 30
      Expression = {
        $_.Name
      }
    }
    $fmtDbSize          = @{
      label        = 'Size (GB)'
      alignment    = 'right'
      width        = 20
      Expression   = {
        $_.UsedSpace
      }
      FormatString = 'N0'
    }
    $fmtName            = @{
      label      = 'CPU Name'
      alignment  = 'left'
      width      = 60
      Expression = {
        $_.Name
      }
    }
    $fmtCores           = @{
      label      = 'Cores'
      alignment  = 'right'
      width      = 12
      Expression = {
        $_.NumberOfCores
      }
    }
    $fmtSWName          = @{
      label      = 'Name'
      alignment  = 'left'
      width      = 60
      Expression = {
        $_.DisplayName
      }
    }
    $fmtSWversion       = @{
      label      = 'Version'
      alignment  = 'left'
      width      = 20
      Expression = {
        $_.Version
      }
    }
    $fmtDrive           = @{
      label      = 'Drv'
      alignment  = 'left'
      width      = 3
      Expression = {
        $_.DeviceID
      }
    }
    $fmtVolName         = @{
      label      = 'Vol Name'
      alignment  = 'left'
      width      = 15
      Expression = {
        $_.VolumeName
      }
    }
    $fmtSize            = @{
      label        = 'Size GiB'
      alignment    = 'right'
      width        = 12
      Expression   = {
        $_.Size / 1024/1024/1024
      }
      FormatString = 'N0'
    }
    $fmtMemTag          = @{
      label      = 'Name'
      alignment  = 'left'
      width      = 20
      Expression = {
        $_.Tag
      }
    }
    $fmtMemLoc          = @{
      label      = 'ID/Location'
      alignment  = 'left'
      width      = 15
      Expression = {
        $_.DeviceLocator
      }
    }
    $fmtMemSize         = @{
      label        = 'Size (GiB)'
      alignment    = 'right'
      width        = 30
      Expression   = {
        $_.Capacity/1024/1024/1024
      }
      FormatString = 'N0'
    }
    $fmtFree            = @{
      label        = 'Free GiB'
      alignment    = 'right'
      width        = 12
      Expression   = {
        $_.FreeSpace / 1024/1024/1024
      }
      FormatString = 'N0'
    }
    $fmtPerc            = @{
      label        = 'Free %'
      alignment    = 'right'
      width        = 10
      Expression   = {
        100.0 * $_.FreeSpace / $_.Size
      }
      FormatString = 'N1'
    }
    $fmtMsg             = @{
      label      = 'Message'
      alignment  = 'left'
      width      = 12
      Expression = {
        if (100.0 * $_.FreeSpace / $_.Size -le $levelAlarm) 
        {
          'Alarm !!!'
        }
        elseif (100.0 * $_.FreeSpace / $_.Size -le $levelWarn)  
        {
          'Warning !'
        }
      }
    }
  
    Write-Output -InputObject ('Report Run Date: {0}' -f $varDate) | Out-File -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     SYSTEM IDENTIFICATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Server Name:		' + $varCompSys.Name) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Service Tag:		' + $varBios.SerialNumber) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Manufacturer:		' + $varCompSys.Manufacturer) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Model:			' + $varCompSys.Model) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Domain:			' + $varCompSys.Domain) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('IP Address:		' + $varIPv4addr) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Domain Role:		' + $varDomainRole) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $varRDPInfo | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     SYSTEM PROCESSOR INFORMATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $varCPU |
    Format-Table -Property $fmtName, $fmtCores |
    Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     SYSTEM MEMORY INFORMATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Total Physical Memory:	' + [math]::Round($varCompSys.TotalPhysicalMemory/1024/1024/1024) + ' GB') | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $varMemory |
    Format-Table -Property $fmtMemTag, $fmtMemLoc, $fmtMemSize |
    Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     SYSTEM DEVICES' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $varSysDevices | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     SYSTEM DRIVE SPACE INFORMATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $("Server: {0}`tDrives #: {1}" -f $ComputerName, $varDisks.Count) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $varDisks |
    Format-Table -Property $fmtDrive, $fmtVolName, $fmtSize, $fmtFree, $fmtPerc, $fmtMsg |
    Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     OPERATING SYSTEM INFORMATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('OS:            ' + $varOS.Caption) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Build Number:  ' + $varOS.BuildNumber) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $('Version:       ' + $varOS.Version) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     SQL SERVER INFORMATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    
    if ($varIsSql)
    {
      Write-Output -InputObject $varSqlVersion | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject $('Cumulative Database Size (GB):  {0}' -f $varDBTotal) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject $varSqlDbs |
      Sort-Object -Descending -Property UsedSpace |
      Format-Table -Property $fmtDbName, $fmtDbSize |
      Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    }
    else
    {
      Write-Output -InputObject ('{0} is not running the SQL service or SQL is not installed' -f $ComputerName) | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    }
    
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '     INSTALLED SOFTWARE' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject $varInstalledSw  |
    Format-Table -Property $fmtSWName, $fmtSWversion |
    Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    Write-Output -InputObject '' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    
    if ($varIsDell)
    {
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject '     DELL PERC CONTROLLER AND ARRAY INFORMATION' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject $varPercInfo | Out-File -Append -FilePath .\$ComputerName-sysinfo.txt
    }
  
  }
  else 
  {
    ('{0} is unreachable!' -f $ComputerName)
  }
  
}

Write-Output -InputObject ('Report Run Date: {0}' -f $varDate) | Out-File -FilePath .\Workstation-Report.txt
Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\Workstation-Report.txt
Write-Output -InputObject '     WORKSTATION INFORMATION' | Out-File -Append -FilePath .\Workstation-Report.txt
Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath .\Workstation-Report.txt
Write-Output -InputObject $varPcList | Out-File -Append -FilePath .\Workstation-Report.txt

