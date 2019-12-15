Import-Module -Global -Name .\modSysinfo.psm1 -Force

Set-HostList | Out-File -FilePath .\hosts.txt

$hosts = Get-Content -Path '.\hosts.txt'

foreach($ComputerName in $hosts)
{
  try
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
      $varTapeDrive       = Get-WmiObject -ComputerName $ComputerName -Class Win32_TapeDrive
  
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
          $_.DisplayVersion
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
  
      
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -FilePath .\$ComputerName-sysinfo.txt
      Write-Output -InputObject '     SYSTEM IDENTIFICATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Server Name:		' + $varCompSys.Name) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Service Tag:		' + $varBios.SerialNumber) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Manufacturer:		' + $varCompSys.Manufacturer) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Model:			' + $varCompSys.Model) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Domain:			' + $varCompSys.Domain) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      $varIPv4addr        = Get-IPv4Addr -ErrorAction SilentlyContinue
      Write-Output -InputObject $('IP Address:		' + $varIPv4addr) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      $DomainRole         = Get-DomainRole -type $varCompSys.DomainRole
      Write-Output -InputObject $('Domain Role:		' + $DomainRole) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Get-RDP -ComputerName $ComputerName -ErrorAction SilentlyContinue
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     SYSTEM PROCESSOR INFORMATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $varCPU |
      Format-Table -Property $fmtName, $fmtCores |
      Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     SYSTEM MEMORY INFORMATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Total Physical Memory:	' + [math]::Round($varCompSys.TotalPhysicalMemory/1024/1024/1024) + ' GB') | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $varMemory |
      Format-Table -Property $fmtMemTag, $fmtMemLoc, $fmtMemSize |
      Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     SYSTEM DRIVE SPACE INFORMATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $("Server: {0}`tDrives #: {1}" -f $ComputerName, $varDisks.Count) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $varDisks |
      Format-Table -Property $fmtDrive, $fmtVolName, $fmtSize, $fmtFree, $fmtPerc, $fmtMsg |
      Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Tape Drive:		' + $varTapeDrive.Description) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Get-Faxboard -ComputerName $ComputerName -ErrorAction SilentlyContinue
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     OPERATING SYSTEM INFORMATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('OS:            ' + $varOS.Caption) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Build Number:  ' + $varOS.BuildNumber) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Version:       ' + $varOS.Version) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     SQL SERVER INFORMATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      try
      {
        if (Get-Service -ComputerName $ComputerName |
          Select-Object -Property Status, DisplayName |
          Where-Object -FilterScript {
            ($_.DisplayName -like '*SQL Server (MSSQLSERVER)*') -and ($_.Status -eq 'Running')
        })
        {
          Invoke-Sqlcmd2 -ComputerName $ComputerName -Query 'sp_SERVER_INFO' |
          Select-Object -Property attribute_value -ExcludeProperty attribute_id, attribute_name -ExpandProperty attribute_value -Skip 1 -First 1 |
          Out-File -Append -FilePath $ComputerName-sysinfo.txt
          $varDBTotal = Invoke-Sqlcmd2 -ComputerName $ComputerName -ErrorAction SilentlyContinue -Total | Select-Object -Property UsedSpace -ExpandProperty UsedSpace
          Write-Output -InputObject $('Cumulative Database Size (GB):  {0}' -f $varDBTotal) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
          Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
          Invoke-Sqlcmd2 -ComputerName $ComputerName -ErrorAction SilentlyContinue |
          Sort-Object -Descending -Property UsedSpace |
          Format-Table -Property $fmtDbName, $fmtDbSize |
          Out-File -Append -FilePath $ComputerName-sysinfo.txt
        }
        else
        {
          Write-Output -InputObject ('{0} is not running the SQL service or SQL is not installed' -f $ComputerName) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
        }
      }
      catch
      {
        "Error was $_"
        $line = $_.InvocationInfo.ScriptLineNumber
        "Error was in Line $line"
      }
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     INSTALLED SOFTWARE' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Get-InstalledSoftware -ComputerName $ComputerName -ErrorAction SilentlyContinue | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     DELL PERC CONTROLLER AND ARRAY INFORMATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Get-PercInfo -ComputerName $ComputerName -ErrorAction SilentlyContinue | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Get-PcList -ErrorAction SilentlyContinue | Out-File -FilePath Workstation-List.txt
    }
    else 
    {
      ('{0} is unreachable!' -f $ComputerName)
    }
  }
  catch
  {
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
  }
}
