
function Get-Faxboard
{
  [CmdletBinding()]
  param(
    [string]$ComputerName = '.'
  )
  process
  {
    $varFaxBoard = Get-WmiObject -ComputerName $ComputerName -Class Win32_PnPEntity -Filter "name LIKE 'Brooktrout%'"
    try
    {
      $output = foreach ($item in $varFaxBoard)
      {
        $('Fax Board:		{0}' -f $item.Caption)
      }
    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    return $output
  }
}
function Get-DomainRole
{
  [CmdletBinding()]
  param(
    [int]$type
  )
  process
  {
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
}
function Get-InstalledSoftware
{
  [CmdletBinding()]
  param
  (
    [string]$ComputerName = '.'
  )
  process
  {
    $service        = Get-Service -ComputerName $ComputerName -Name 'RemoteRegistry'
    if ($service -ne 'Running')
    {
      Get-Service -ComputerName $ComputerName -Name 'RemoteRegistry' | Start-Service
    }
    $array          = @()
    $basekey        = [Microsoft.Win32.RegistryHive]::LocalMachine
    $UninstallKey32 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $UninstallKey64 = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    $reg            = [microsoft.win32.registrykey]::OpenRemoteBaseKey($basekey, $ComputerName)
    $regkey32       = $reg.OpenSubKey($UninstallKey32)
    $regkey64       = $reg.OpenSubKey($UninstallKey64)
    #Retrieve an array of string that contain all the subkey names
    $subkeys32      = $regkey32.GetSubKeyNames()
    $subkeys64      = $regkey64.GetSubKeyNames()
    #Open each Subkey and use GetValue Method to return the required values for each
    foreach($key in $subkeys32)
    {
      $thisKey    =  $UninstallKey32+'\' + $key
      $thisSubKey =  $reg.OpenSubKey($thisKey)
      $obj        =  New-Object -TypeName PSObject
      $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
      $obj | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $($thisSubKey.GetValue('DisplayName'))
      $obj | Add-Member -MemberType NoteProperty -Name 'DisplayVersion' -Value $($thisSubKey.GetValue('DisplayVersion'))
      $obj | Add-Member -MemberType NoteProperty -Name 'InstallLocation' -Value $($thisSubKey.GetValue('InstallLocation'))
      $obj | Add-Member -MemberType NoteProperty -Name 'Publisher' -Value $($thisSubKey.GetValue('Publisher'))
      $array      += $obj
    }
    foreach ($key in $subkeys64)
    {
      $thisKey    =  $UninstallKey64+'\'+$key
      $thisSubKey =  $reg.OpenSubKey($thisKey)
      $obj        =  New-Object -TypeName PSObject
      $obj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName
      $obj | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $($thisSubKey.GetValue('DisplayName'))
      $obj | Add-Member -MemberType NoteProperty -Name 'DisplayVersion' -Value $($thisSubKey.GetValue('DisplayVersion'))
      $obj | Add-Member -MemberType NoteProperty -Name 'InstallDate' -Value $($thisSubKey.GetValue('InstallDate'))
      $obj | Add-Member -MemberType NoteProperty -Name 'Publisher' -Value $($thisSubKey.GetValue('Publisher'))
      $array      += $obj
    }
    #$array | Where-Object { $_.DisplayName } | Select-Object -Property DisplayName, DisplayVersion | Format-Table -AutoSize
    return $array |
    Where-Object -FilterScript {
      ($_.DisplayName) -and ($_.DisplayName -notlike '*(KB*)*') -and ($_.DisplayName -notlike '*Hotfix*')
    } |
    Select-Object -Property DisplayName, DisplayVersion |
    Sort-Object -Property DisplayName |
    Get-Unique -AsString
  }
}
function Get-IPv4Addr
{
  [CmdletBinding()]
  param
  (
    [string]$ComputerName = '.'
  )
  process
  {
    try
    {
      $output = @([Net.Dns]::GetHostByName($ComputerName).AddressList | Select-Object -Property IPAddressToString -ExpandProperty IPAddressToString)
    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    return $output
  }
}
function Get-PcList
{
  process
  {
    if (-not(Get-Command -Name Get-ADComputer))
    {
      throw 'The Get-PcList function requires the ActiveDirectory module to be loaded.'
    }
    try
    {
      $output = Get-ADComputer -Filter 'OperatingSystem -notLike "*SERVER*"' -Properties lastlogondate, operatingsystem |
      Select-Object -Property name, lastlogondate, operatingsystem |
      Sort-Object -Property LastLogonDate -Descending
    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    return $output
  }
}
function Get-PercInfo
{
  [CmdletBinding()]
  param
  (
    [string]$ComputerName = '.'
  )
  process
  {
    #base of the powershell command
    $PsCommandBase  = 'echo . | powershell -ExecutionPolicy Bypass '
    # The actual command you want to be passed in to powershell (example)
    # $SqlQuery = "sqlcmd.exe -Q 'SELECT @@version;'`n sqlcmd.exe -Q 'sp_helpdb;'"
    $MyCommand      = 'perccli.exe /c0 show'
    # We'll encode the command string to prevent cmd.exe from mangling it
    $encodedcommand = [convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyCommand))
    # build the actual full command to send to powershell
    $PsCommand      = (('{0} -EncodedCommand {1}' -f $PsCommandBase, $encodedcommand))
    $Manufacturer   = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem | Select-Object -Property Manufacturer -ExpandProperty Manufacturer
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
    return $output
  }
}
function Get-RDP
{
  [CmdletBinding()]
  param
  (
    [string]$ComputerName = '.'
  )
  process
  {
    try
    {
      $string = Get-WmiObject -ComputerName $ComputerName -Namespace 'root\CIMV2\TerminalServices' -Class 'Win32_TerminalServiceSetting' -Authentication 6 | Select-Object -ExpandProperty TerminalServerMode
      $output = if ($string -eq '1')
      {
        ('{0} is enabled with Multiple user mode' -f $ComputerName)
        ('Active RDP Sessions:		' + $varTermSvc)
      }
      else
      {
        ('{0} is not a terminal server.' -f $ComputerName)
      }
    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    return $output
  }
}
function Invoke-Sqlcmd2
{
  [CmdletBinding()]
  param
  (
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
    $conn                  = New-Object -TypeName System.Data.SqlClient.SQLConnection
    $conn.ConnectionString = 'Server={0};Database={1};Integrated Security=True' -f $ComputerName, $Database
    $conn.Open()
    $cmd                   = New-Object -TypeName system.Data.SqlClient.SqlCommand -ArgumentList ($Query, $conn)
    $cmd.CommandTimeout    = $QueryTimeout
    $ds                    = New-Object -TypeName system.Data.DataSet
    $da                    = New-Object -TypeName system.Data.SqlClient.SqlDataAdapter -ArgumentList ($cmd)
    $null                  = $da.fill($ds)
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
function Set-HostList
{
  process
  {
    $ErrorActionPreference = 'SilentlyContinue'
    $ServerList            = @()
    $Servers               = @()
    $ServerList            = Get-ADComputer -Filter 'OperatingSystem -like "Windows*Server*"'-Properties Name | Select-Object -ExpandProperty Name
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
    }
    else
    {
      'Active Directory commands not present, attempting to import Active Directory module.'
      Import-Module -Global -Name Microsoft.ActiveDirectory.Management.dll
    }
    return $servers
  }
}
function Get-LogOns
{
  [CmdletBinding()]
  param(
    [string]$ComputerName = '.',
    [int]$Days = 7
  )
  process
  {
    try
    {
      $logs = Get-EventLog -LogName system -ComputerName $ComputerName -Source Microsoft-Windows-Winlogon -After (Get-Date).AddDays(-$Days)
    
      $res  = @()
      ForEach ($log in $logs)
      {
        if($log.instanceid -eq 7001) 
        {
          $type = 'Logon'
        }
        Elseif ($log.instanceid -eq 7002)
        {
          $type = 'Logoff'
        }
        Else 
        {
          Continue
        } 
        $res += New-Object -TypeName PSObject -Property @{
          Time  = $log.TimeWritten
          'Event' = $type
          User  = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $log.ReplacementStrings[1]).Translate([Security.Principal.NTAccount])
        }
      }
    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    return $res
  }
}