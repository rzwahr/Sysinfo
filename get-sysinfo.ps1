# Known issues in this script:
# - Getting Get-WmiObject : Access denied : Fixed by adding -Authentication 6, that class requires Packet Privacy (level 6) - see https://docs.microsoft.com/en-us/previous-versions//dd315295(v=technet.10)?redirectedfrom=MSDN

function Set-HostList
{
  $ErrorActionPreference = 'SilentlyContinue'
  $ServerList = @()
  $Servers = @()
  $ServerList = Get-ADComputer -Filter 'OperatingSystem -like "Windows*Server*"'-Properties Name | Select-Object -ExpandProperty Name
  if (Get-Command -Name Get-ADComputer)
  {
    foreach ($Server in $ServerList) 
    {
      if (Test-Connection -ComputerName $Server -Quiet -Count 1)
      {
        if (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Server)
        {
          $Servers = $Servers += $Server
        }
      }
    }
    $Servers
  }
  else
  {
    'Active Directory commands not present, attempting to import Active Directory module.'
    Import-Module -Global -Name Microsoft.ActiveDirectory.Management.dll
  }
}
      
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
      $varBios = Get-WmiObject -ComputerName $ComputerName -Class Win32_BIOS
      $varCompSys = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem
      $varMemory = Get-WmiObject -ComputerName $ComputerName -Class Win32_PhysicalMemory
      $varCPU = Get-WmiObject -ComputerName $ComputerName -Class Win32_Processor
      $varOS = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem
      $varDisks = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Filter 'DriveType = 3'
      $varTapeDrive = Get-WmiObject -ComputerName $ComputerName -Class Win32_TapeDrive
      $varFaxBoard = Get-WmiObject -ComputerName $ComputerName -Class Win32_PnPEntity -Filter "name LIKE 'Brooktrout%'"
      $varTermSvc = Get-WmiObject -ComputerName $ComputerName -Class Win32_TerminalService | Select-Object -ExpandProperty TotalSessions
  
      # Functions
      <# function Get-SQLInfo
          {
          param (
          [parameter(ValueFromPipeline = $true,
          ValueFromPipelineByPropertyName = $true)]
          [string]$ComputerName
          )
        
          PROCESS
          {
          #base of the powershell command
          $PsCommandBase = 'echo . | powershell -ExecutionPolicy Bypass'
  
          # The actual command you want to be passed in to powershell (example)
          # $SqlQuery = "sqlcmd.exe -Q 'SELECT @@version;'`n sqlcmd.exe -Q 'sp_helpdb;'"
          $MyCommand = 'sqlcmd -i C:\sqlNameSize.sql'
  
          # We'll encode the command string to prevent cmd.exe from mangling it
          $encodedcommand = [convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyCommand))
  
          # build the actual full command to send to powershell
          $PsCommand = ("$PsCommandBase -EncodedCommand {0}" -f $encodedcommand)
  
          If ((('{0}' -f $ComputerName) -like "$env:COMPUTERNAME") -and (Get-Service -ComputerName $ComputerName | Where-Object -FilterScript {
          ($_.DisplayName -like '*SQL Server (MSSQLSERVER)*') -and ($_.Status -eq 'Running')
          }))
          {
          Copy-Item -path .\sqlNameSize.sql -destination C:\
          $output = $MyCommand
          Remove-Item -Path c:\sqlNameSize.sql
          }
          elseif (Get-Service -ComputerName $ComputerName |
          Select-Object -Property Status, DisplayName |
          Where-Object -FilterScript {
          ($_.DisplayName -like '*SQL Server (MSSQLSERVER)*') -and ($_.Status -eq 'Running')
          })
          {
          Copy-Item -path .\sqlNameSize.sql -destination \\$ComputerName\c$\
          $output = .\psexec.exe -nobanner -accepteula \\$ComputerName cmd /c $PsCommand
          Remove-Item -Path \\$ComputerName\$c\sqlNameSize.sql
          }
          else
          {
          'This server is either not running sql or does not have the instance MSSQLSERVER running on it'
          }
          return $output
          }
      } #>
      
      function Get-PcList
      {
        <#
            .SYNOPSIS
            Short Description
            .DESCRIPTION
            Detailed Description
            .EXAMPLE
            Get-PcList
            explains how to use the command
            can be multiple lines
            .EXAMPLE
            Get-PcList
            another example
            can have as many examples as you like
        #>
        if (-not(Get-Command -Name Get-ADComputer))
        {
          throw 'The Get-PcList function requires the ActiveDirectory module to be loaded.'
        }
   
        try
        {
          Get-ADComputer -Filter 'OperatingSystem -notLike "*SERVER*"' -Properties lastlogondate,operatingsystem | Select-Object -Property name,lastlogondate,operatingsystem | Sort-Object -Property LastLogonDate -Descending
        }
        catch
        {
          "Error was $_"
          $line = $_.InvocationInfo.ScriptLineNumber
          "Error was in Line $line"
        }
      }
      
      function Get-DomainRole 
      {
        [CmdletBinding()]
        param(
          [int]$type
        )
        $role = DATA 
        {
          ConvertFrom-StringData -StringData @'
  0 = Standalone Workstation
  1 = Member Workstation
  2 = Standalone Server
  3 = Member Server
  4 = Backup Domain Controller
  5 = Primary Domain Controller
'@
        }
        $role[('{0}' -f ($type))]
      }
  
      function Invoke-Sqlcmd2
      {
        [CmdletBinding()]
        param(
          [string]$ComputerName = '.',
          [string]$Database = 'master',
          [string]$Query = 'SELECT name, CONVERT(DECIMAL(10,2),(size * 8.00) / 1024.00 / 1024.00) As UsedSpace FROM master.sys.master_files ORDER BY UsedSpace',
          [int]$QueryTimeout = 30,
          [switch]$Total
        )
  
        try
        {
          if ($Total.IsPresent)
          {
            $Query = 'SELECT CONVERT(DECIMAL(10,2),(SUM(size * 8.00) / 1024.00 / 1024.00)) As UsedSpace FROM master.sys.master_files'
          }    
          $conn = New-Object -TypeName System.Data.SqlClient.SQLConnection
          $conn.ConnectionString = 'Server={0};Database={1};Integrated Security=True' -f $ComputerName, $Database
          $conn.Open()
          $cmd = New-Object -TypeName system.Data.SqlClient.SqlCommand -ArgumentList ($Query, $conn)
          $cmd.CommandTimeout = $QueryTimeout
          $ds = New-Object -TypeName system.Data.DataSet
          $da = New-Object -TypeName system.Data.SqlClient.SqlDataAdapter -ArgumentList ($cmd)
          $null = $da.fill($ds)
          $ds.Tables[0]
          $conn.Close()
        }
        catch
        {
          ('Error was {0}' -f $_)
          $line = $_.InvocationInfo.ScriptLineNumber
          ('Error was in Line {0}' -f $line)
        }
      }
  
  
      function Get-PercInfo
      {
        param (
          [parameter(ValueFromPipeline = $true,
          ValueFromPipelineByPropertyName = $true)]
          [string]$ComputerName
        )
        PROCESS
        {
          
          #base of the powershell command
          $PsCommandBase = 'echo . | powershell -ExecutionPolicy Bypass '
  
          # The actual command you want to be passed in to powershell (example)
          # $SqlQuery = "sqlcmd.exe -Q 'SELECT @@version;'`n sqlcmd.exe -Q 'sp_helpdb;'"
          $MyCommand = 'perccli.exe /c0 show'
  
          # We'll encode the command string to prevent cmd.exe from mangling it
          $encodedcommand = [convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyCommand))
  
          # build the actual full command to send to powershell
          $PsCommand = (('{0} -EncodedCommand {1}' -f $PsCommandBase, $encodedcommand))
  
          $Manufacturer = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem | Select-Object -Property Manufacturer -ExpandProperty Manufacturer
  
          If ($Manufacturer -notlike 'Dell*')
          {
            ('{0} is not a Dell server and is not compatible with perccli.exe' -f $ComputerName)
            Break
          }
  
          If ($ComputerName -eq $env:COMPUTERNAME)
          {
            try
            {
              If (Test-Path -Path ('{0}\perccli.exe' -f $PWD))
              {
                $output = .\perccli.exe /c0 show
              }
              else
              {
                'Please insure perccli.exe is present in the current directory and try again.'
              }
            }
            catch
            {
              ('Error was {0}' -f $_)
              $line = $_.InvocationInfo.ScriptLineNumber
              ('Error was in Line {0}' -f $line)
            }
          }
          else
          {
            try
            {
              If ((Test-Path -Path ('{0}\perccli.exe' -f $PWD)) -and (Test-Path -Path ('{0}\psexec.exe' -f $PWD)))
              {
                Copy-Item -Path .\perccli.exe -Destination \\$ComputerName\c$\Windows
                $output = .\psexec.exe -nobanner -accepteula \\$ComputerName cmd /c $PsCommand
                Remove-Item -Path \\$ComputerName\c$\Windows\perccli.exe
              }
              else
              {
                'Either one or both of the following files is not present in the current directory: perccli.exe, psexec.exe'
                'Please insure both of these files are present in the current directory and try again.'
              }
            }
            catch
            {
              ('Error was {0}' -f $_)
              $line = $_.InvocationInfo.ScriptLineNumber
              ('Error was in Line {0}' -f $line)
            }
          }
          Return $output
        }
      }
      
      function Get-Faxboard
      {
        param(
          [parameter(ValueFromPipeline = $true,
          ValueFromPipelineByPropertyName = $true)]
        [string]$ComputerName)
        
        try
        {
          foreach ($item in $varFaxBoard)
          {
            Write-Output -InputObject $('Fax Board:		{0}' -f $item.Caption) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
          }
        }
        catch
        {
          ('Error was {0}' -f $_)
          $line = $_.InvocationInfo.ScriptLineNumber
          ('Error was in Line {0}' -f $line)
        }
      }
  
      function Get-RDP
      {
        param (
          [parameter(ValueFromPipeline = $true,
          ValueFromPipelineByPropertyName = $true)]
          [string]$ComputerName
        )
        try
        {
          $string = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\CIMV2\TerminalServices' -Class 'Win32_TerminalServiceSetting' -Authentication 6 | Select-Object -ExpandProperty TerminalServerMode
          
          if ($string -eq '1')
          {
            Write-Output -InputObject ('{0} is enabled with Multiple user mode' -f $ComputerName) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
            Write-Output -InputObject ('Active RDP Sessions:		' + $varTermSvc) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
            <# foreach($item in $varTermSvc)
                {
                Write-Output $("Active RDP Sessions:	{0}" -f $item.TotalSessions) | Out-File -Append -FilePath $ComputerName-sysinfo.txt;
            } #>
          }
          else
          {
            Write-Output -InputObject ('{0} is not a terminal server.' -f $ComputerName) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
          }
        }
        catch
        {
          ('Error was {0}' -f $_)
          $line = $_.InvocationInfo.ScriptLineNumber
          ('Error was in Line {0}' -f $line)
        }
      }
  
      function Get-IPv4Addr
      {
        param
        (      
          [parameter(ValueFromPipeline = $true,
          ValueFromPipelineByPropertyName = $true)]
          [string]$ComputerName
        )
        process
        {   
          try
          {
            $ip = @([Net.Dns]::GetHostByName($ComputerName).AddressList | Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)
          }
          catch
          {
            ('Error was {0}' -f $_)
            $line = $_.InvocationInfo.ScriptLineNumber
            ('Error was in Line {0}' -f $line)
          }
          Return $ip
        }
      }
      
      function Get-InstalledSoftware 
      {
        param
        (
          [parameter(ValueFromPipeline = $true,
          ValueFromPipelineByPropertyName = $true)]
          [string]$ComputerName
        )
  	  
        $service = Get-Service -ComputerName $ComputerName -Name 'RemoteRegistry'
  	  
        if ($service -ne 'Running')
        {
          Get-Service -ComputerName $ComputerName -Name 'RemoteRegistry' | Start-Service
        }
  	  
        $array = @()
    
        $basekey = [Microsoft.Win32.RegistryHive]::LocalMachine
    
        $UninstallKey32 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' 
      
        $UninstallKey64 = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  
        $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey($basekey, $ComputerName) 
  
        $regkey32 = $reg.OpenSubKey($UninstallKey32) 
  
        $regkey64 = $reg.OpenSubKey($UninstallKey64)
      
        #Retrieve an array of string that contain all the subkey names
  
        $subkeys32 = $regkey32.GetSubKeyNames() 
      
        $subkeys64 = $regkey64.GetSubKeyNames()
  
        #Open each Subkey and use GetValue Method to return the required values for each
  
        foreach($key in $subkeys32)
        {
          $thisKey = $UninstallKey32+'\' + $key 
  
          $thisSubKey = $reg.OpenSubKey($thisKey) 
  
          $obj = New-Object -TypeName PSObject
  
          $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
  
          $obj | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $($thisSubKey.GetValue('DisplayName'))
  
          $obj | Add-Member -MemberType NoteProperty -Name 'DisplayVersion' -Value $($thisSubKey.GetValue('DisplayVersion'))
  
          $obj | Add-Member -MemberType NoteProperty -Name 'InstallLocation' -Value $($thisSubKey.GetValue('InstallLocation'))
  
          $obj | Add-Member -MemberType NoteProperty -Name 'Publisher' -Value $($thisSubKey.GetValue('Publisher'))
  
          $array += $obj
        }
    
        foreach ($key in $subkeys64)
        {
          $thisKey = $UninstallKey64+'\'+$key 
  
          $thisSubKey = $reg.OpenSubKey($thisKey) 
      
          $obj = New-Object -TypeName PSObject
  
          $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
  
          $obj | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $($thisSubKey.GetValue('DisplayName'))
  
          $obj | Add-Member -MemberType NoteProperty -Name 'DisplayVersion' -Value $($thisSubKey.GetValue('DisplayVersion'))
  
          $obj | Add-Member -MemberType NoteProperty -Name 'InstallDate' -Value $($thisSubKey.GetValue('InstallDate'))
  
          $obj | Add-Member -MemberType NoteProperty -Name 'Publisher' -Value $($thisSubKey.GetValue('Publisher'))
  
          $array += $obj
        } 
  
        #$array | Where-Object { $_.DisplayName } | Select-Object -Property DisplayName, DisplayVersion | Format-Table -AutoSize
        $array |
        Where-Object -FilterScript {
          ($_.DisplayName) -and ($_.DisplayName -notlike '*(KB*)*') -and ($_.DisplayName -notlike '*Hotfix*')
        } |
        Select-Object -Property DisplayName, DisplayVersion |
        Sort-Object -Property DisplayName |
        Get-Unique -AsString
      }
  	
      # Formats
      $fmtDbName		= @{
        label      = 'DB Name'
        alignment  = 'left'
        width      = 30
        Expression = {
          $_.Name
        }
      }
      $fmtDbSize		= @{
        label        = 'Size (GB)'
        alignment    = 'right'
        width        = 20
        Expression   = {
          $_.UsedSpace
        }
        FormatString = 'N0'
      }
      $fmtName		= @{
        label      = 'CPU Name'
        alignment  = 'left'
        width      = 60
        Expression = {
          $_.Name
        }
      }
      $fmtCores		= @{
        label      = 'Cores'
        alignment  = 'right'
        width      = 12
        Expression = {
          $_.NumberOfCores
        }
      }
      $fmtSWName		= @{
        label      = 'Name'
        alignment  = 'left'
        width      = 60
        Expression = {
          $_.DisplayName
        }
      }
      $fmtSWversion	= @{
        label      = 'Version'
        alignment  = 'left'
        width      = 20
        Expression = {
          $_.DisplayVersion
        }
      }
      $fmtDrive		= @{
        label      = 'Drv'
        alignment  = 'left'
        width      = 3
        Expression = {
          $_.DeviceID
        }
      }
      $fmtVolName		= @{
        label      = 'Vol Name'
        alignment  = 'left'
        width      = 15
        Expression = {
          $_.VolumeName
        }
      }
      $fmtSize		= @{
        label        = 'Size GiB'
        alignment    = 'right'
        width        = 12
        Expression   = {
          $_.Size / 1024/1024/1024
        }
        FormatString = 'N0'
      }
      $fmtMemTag		= @{
        label      = 'Name'
        alignment  = 'left'
        width      = 20
        Expression = {
          $_.Tag
        }
      }
      $fmtMemLoc		= @{
        label      = 'ID/Location'
        alignment  = 'left'
        width      = 15
        Expression = {
          $_.DeviceLocator
        }
      }
      $fmtMemSize		= @{
        label        = 'Size (GiB)'
        alignment    = 'right'
        width        = 30
        Expression   = {
          $_.Capacity/1024/1024/1024
        }
        FormatString = 'N0'
      }
      $fmtFree		= @{
        label        = 'Free GiB'
        alignment    = 'right'
        width        = 12
        Expression   = {
          $_.FreeSpace / 1024/1024/1024
        }
        FormatString = 'N0'
      }
      $fmtPerc		= @{
        label        = 'Free %'
        alignment    = 'right'
        width        = 10
        Expression   = {
          100.0 * $_.FreeSpace / $_.Size
        }
        FormatString = 'N1'
      }
      $fmtMsg			= @{
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
  
      Get-Date | Out-File -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '     SYSTEM IDENTIFICATION' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject '-------------------------------------------------------------------------------------------' | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Server Name:		' + $varCompSys.Name) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Service Tag:		' + $varBios.SerialNumber) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Manufacturer:		' + $varCompSys.Manufacturer) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Model:			' + $varCompSys.Model) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      Write-Output -InputObject $('Domain:			' + $varCompSys.Domain) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      $varIPv4addr = Get-IPv4Addr -ErrorAction SilentlyContinue
      Write-Output -InputObject $('IP Address:		' + $varIPv4addr) | Out-File -Append -FilePath $ComputerName-sysinfo.txt
      $DomainRole = Get-DomainRole -type $varCompSys.DomainRole
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
