
$ErrorActionPreference = 'SilentlyContinue'

Import-Module -Name .\bin\Cassia.dll
function Get-SysDevices
{
  [CmdletBinding()]
  param
  (
    [String]$ComputerName = $env:COMPUTERNAME
  )
  process
  {
    Write-Verbose -Message "Fetching System Devices on $ComputerName"
    try
    {
      $varPNPEntity = Get-WmiObject -ComputerName $ComputerName -Class Win32_PNPEntity
    
      $varScsiDevices = $varPNPEntity |
      Where-Object -FilterScript {
        ($_.PNPDeviceID -like 'SCSI\*') -and ($_.Manufacturer -notlike '*standard*')
      } |
      Select-Object -ExpandProperty Description
    
      $varPciDevices = $varPNPEntity |
      Where-Object -FilterScript {
        ($_.PNPDeviceID -like 'PCI\*') -and ($_.Manufacturer -notlike '*standard*') -and ($_.PNPDeviceID -notlike '*VEN_8086*')
      } |
      Select-Object -ExpandProperty Description
    }
    catch
    {
      "Error was $_"
      $line = $_.InvocationInfo.ScriptLineNumber
      "Error was in Line $line"
    }
    $varScsiDevices
    $varPciDevices
  }   
}

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
  <#
      .SYNOPSIS
      Pull software details from registry on one or more computers

      .DESCRIPTION
      Pull software details from registry on one or more computers.  Details:
      -This avoids the performance impact and potential danger of using the WMI Win32_Product class
      -The computer name, display name, publisher, version, uninstall string and install date are included in the results
      -Remote registry must be enabled on the computer(s) you query
      -This command must run with privileges to query the registry of the remote system(s)
      -Running this in a 32 bit PowerShell session on a 64 bit computer will limit your results to 32 bit software and result in double entries in the results

      .PARAMETER ComputerName
      One or more computers to pull software list from.

      .PARAMETER DisplayName
      If specified, return only software with DisplayNames that match this parameter (uses -match operator)

      .PARAMETER Publisher
      If specified, return only software with Publishers that match this parameter (uses -match operator)

      .EXAMPLE
      #Pull all software from c-is-ts-91, c-is-ts-92, format in a table
      Get-InstalledSoftware c-is-ts-91, c-is-ts-92 | Format-Table -AutoSize

      .EXAMPLE
      #pull software with publisher matching microsoft and displayname matching lync from c-is-ts-91
      "c-is-ts-91" | Get-InstalledSoftware -DisplayName lync -Publisher microsoft | Format-Table -AutoSize

      .LINK
      http://gallery.technet.microsoft.com/scriptcenter/Get-InstalledSoftware-Get-5607a465

      .FUNCTIONALITY
      Computers
  #>
  param (
    [Parameter(
        Position = 0,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true, 
        ValueFromRemainingArguments = $false
    )]
    [ValidateNotNullOrEmpty()]
    [Alias('CN','__SERVER','Server','Computer')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
        
    [string]$DisplayName = $null,
        
    [string]$Publisher = $null
  )
  
  
  Begin
  {
    Write-Verbose -Message "Fetching software inventory from $ComputerName"    
    #define uninstall keys to cover 32 and 64 bit operating systems.
    #This will yeild only 32 bit software and double entries on 64 bit systems running 32 bit PowerShell
    $UninstallKeys = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 
    'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'

  }

  Process
  {

    #Loop through each provided computer.  Provide a label for error handling to continue with the next computer.
    :computerLoop foreach($computer in $ComputerName)
    {
      Try
      {
        #Attempt to connect to the localmachine hive of the specified computer
        $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer)
      }
      Catch
      {
        #Skip to the next computer if we can't talk to this one
        Write-Error ("Error:  Could not open LocalMachine hive on {0}`: {1}" -f $computer, $_)
        Write-Verbose -Message ("Check Connectivity, permissions, and Remote Registry service for '{0}'" -f $computer)
        Continue
      }

      #Loop through the 32 bit and 64 bit registry keys
      foreach($uninstallKey in $UninstallKeys)
      {
        Try
        {
          #Open the Uninstall key
          $regkey = $null
          $regkey = $reg.OpenSubKey($uninstallKey)

          #If the reg key exists...
          if($regkey)
          {
            #Retrieve an array of strings containing all the subkey names
            $subkeys = $regkey.GetSubKeyNames()

            #Open each Subkey and use GetValue Method to return the required values for each
            foreach($key in $subkeys)
            {
              #Build the full path to the key for this software
              $thisKey = $uninstallKey+'\\'+$key 
                            
              #Open the subkey for this software
              $thisSubKey = $null
              $thisSubKey = $reg.OpenSubKey($thisKey)
                            
              #If the subkey exists
              if($thisSubKey)
              {
                try
                {
                  #Get the display name.  If this is not empty we know there is information to show
                  $dispName = $thisSubKey.GetValue('DisplayName')
                                
                  #Get the publisher name ahead of time to allow filtering using Publisher parameter
                  $pubName = $thisSubKey.GetValue('Publisher')

                  #Collect subset of values from the key if there is a displayname
                  #Filter by displayname and publisher if specified
                  if( $dispName -and
                    (-not $DisplayName -or $dispName -match $DisplayName ) -and
                    (-not $Publisher -or $pubName -match $Publisher )
                  )
                  {
                    #Display the output object, compatible with PowerShell 2
                    New-Object -TypeName PSObject -Property @{
                      ComputerName    = $computer
                      DisplayName     = $dispName
                      Publisher       = $pubName
                      Version         = $thisSubKey.GetValue('DisplayVersion')
                      UninstallString = $thisSubKey.GetValue('UninstallString')
                      InstallDate     = $thisSubKey.GetValue('InstallDate')
                    } | Select-Object -Property ComputerName, DisplayName, Publisher, Version, UninstallString, InstallDate
                  }
                }
                Catch
                {
                  #Error with one specific subkey, continue to the next
                  Write-Error ('Unknown error: {0}' -f $_)
                  Continue
                }
              }
            }
          }
        }
        Catch
        {
          #Write verbose output if we couldn't open the uninstall key
          Write-Verbose -Message ("Could not open key '{0}' on computer '{1}': {2}" -f $uninstallKey, $computer, $_)

          #If we see an access denied message, let the user know and provide details, continue to the next computer
          if($_ -match 'Requested registry access is not allowed')
          {
            Write-Error ('Registry access to {0} denied.  Check your permissions.  Details: {1}' -f $computer, $_)
            continue computerLoop
          }
        }
      }
    }
  }
}

function Get-IPv4Addr
{
  [CmdletBinding()]
  param
  (
    [string]$ComputerName = $env:COMPUTERNAME
  )
  
  process
  {
    Write-Verbose -Message "Fetching IP Address for $ComputerName"
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
      $output = Get-ADComputer -Filter 'OperatingSystem -notLike "*SERVER*"' -Properties * | Select-Object -Property name, lastlogon, operatingsystem
      foreach ($item in $output)
      {
        $newdate = [datetime]::FromFileTime($item.lastlogon)
        $item.lastlogon = $newdate
      }
    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    
    return $output | Sort-Object -Property lastlogon -Descending
  }
}
function Get-PercInfo
{
  [CmdletBinding()]
  param
  (
    [string]$ComputerName = $env:COMPUTERNAME
  )
  process
  {
    #base of the powershell command
    $PsCommandBase  = 'echo . | powershell -ExecutionPolicy Bypass '
    # The actual command you want to be passed in to powershell (example)
    # $SqlQuery = "sqlcmd.exe -Q 'SELECT @@version;'`n sqlcmd.exe -Q 'sp_helpdb;'"
    $MyCommand      = 'C:\perccli.exe /c0 show'
    # We'll encode the command string to prevent cmd.exe from mangling it
    $encodedcommand = [convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyCommand))
    # build the actual full command to send to powershell
    $PsCommand      = (('{0} -EncodedCommand {1}' -f $PsCommandBase, $encodedcommand))
    $Manufacturer   = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem | Select-Object -Property Manufacturer -ExpandProperty Manufacturer
    If ($Manufacturer -notlike 'Dell*')
    {
      ('{0} is not a Dell server and is not compatible with perccli.exe' -f $ComputerName)
    }
    If ($ComputerName -eq $env:COMPUTERNAME)
    {
      try
      {
        If (Test-Path -Path ('{0}\Tools\perccli.exe' -f $PWD))
        {
          $output = .\Tools\perccli.exe /c0 show 2>$null
        }
        else
        {
          'Please insure perccli.exe is present in the Tools directory and try again.'
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
        If ((Test-Path -Path .\Tools\perccli.exe) -and (Test-Path -Path .\Tools\psexec.exe))
        {
          Copy-Item -Path .\Tools\perccli.exe -Destination \\$ComputerName\c$
          $output = .\Tools\psexec.exe -nobanner -accepteula \\$ComputerName cmd /c $PsCommand
          Remove-Item -Path \\$ComputerName\c$\perccli.exe
        }
        else
        {
          'Either one or both of the following files is not present in the Tools directory: perccli.exe, psexec.exe'
          'Please insure both of these files are present in the Tools directory and try again.'
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
      $varTermSvc = Get-WmiObject -ComputerName $ComputerName -Class Win32_TerminalService | Select-Object -Property TotalSessions -ExpandProperty TotalSessions
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
function Get-HostList
{
  process
  {
    Import-Module -Name .\bin\Microsoft.ActiveDirectory.Management.dll
    $ComputerList            = @()
    $Computers               = @()
    $ComputerList            = Get-ADComputer -Filter 'OperatingSystem -like "Windows*Server*"'-Properties Name | Select-Object -ExpandProperty Name
    if (Get-Command -Name Get-ADComputer)
    {
      foreach ($computer in $ComputerList) 
      {
        if (Test-Connection -ComputerName $computer -Quiet -Count 1)
        {
          if (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer)
          {
            $Computers = $Computers += $computer
          }
        }
      }
    }
    else
    {
      'Unable to access Active Directory - Insure the module is loaded or attempt on a domain controller machine.'
    }
    return $Computers
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
function Test-SqlSvr
{
  param ([string]$ComputerName)
  $IsSql = Get-Service -ComputerName $ComputerName |
  Select-Object -Property Status, DisplayName |
  Where-Object -FilterScript {
    ($_.DisplayName -like '*SQL Server (MSSQLSERVER)*') -and ($_.Status -eq 'Running')
  }
  if ($IsSql) 
  {
    return [Bool]1
  }
  else 
  {
    return [Bool]0
  }
}

function Test-Dell
{
  param ([string]$ComputerName)

  $Manufacturer   = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem | Select-Object -Property Manufacturer -ExpandProperty Manufacturer

  if ($Manufacturer -like 'Dell*')
  {
    return [Bool]1
  }
  else 
  {
    return [Bool]0
  }
}
