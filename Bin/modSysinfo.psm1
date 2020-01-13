$ErrorActionPreference = 'SilentlyContinue'

# Import-Module -Global -Name .\PSTerminalServices.psm1 -Force
Import-Module -Name .\Cassia.dll -Force

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
      $output = Get-ADComputer -Filter 'OperatingSystem -notLike "*SERVER*"' -Properties * | Select-Object -Property name, lastlogondate, operatingsystem
      <#foreach ($item in $output)
          {
          $newdate = [datetime]::FromFileTime($item.lastlogon)
          $item.lastlogon = $newdate
          }
    #>    }
    catch
    {
      ('Error was {0}' -f $_)
      $line = $_.InvocationInfo.ScriptLineNumber
      ('Error was in Line {0}' -f $line)
    }
    
    return $output | Sort-Object -Property lastlogondate -Descending
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
    $MyCommand      = 'C:\perccli.exe /call show'
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
          $output = .\Tools\perccli.exe /call show 2>$null
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
    if (-not(Get-Command -Name Get-ADComputer))
    {
      throw 'The Get-PcList function requires the ActiveDirectory module to be loaded.'
    }
    try
    {
      #Import-Module -Name .\bin\Microsoft.ActiveDirectory.Management.dll
      $ComputerList            = @()
      $Computers               = @()
      $ComputerList            = Get-ADComputer -Filter 'OperatingSystem -like "Windows*Server*"'-Properties Name | Select-Object -ExpandProperty Name
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
    catch
    {
      'There was a problem retrieving the information to populate the host list.  Type $error to see details.'
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

function Get-TSSession
{
	<#
	.SYNOPSIS
		Lists the sessions on a given terminal server.

	.DESCRIPTION
		Use Get-TSSession to get a list of sessions from a local or remote computers.
		Note that Get-TSSession is using Aliased properties to display the output on the console (IPAddress and State), these attributes
		are not the same as the original attributes (ClientIPAddress and ConnectionState).
		This is important when you want to use the -Filter parameter which requires the latter.
		To see all aliassed properties and their corresponding properties (Definition column), pipe the result to Get-Member:

		PS > Get-TSSession | Get-Member -MemberType AliasProperty

		   TypeName: Cassia.Impl.TerminalServicesSession

		Name      MemberType    Definition
		----      ----------    ----------
		(...)
		IPAddress AliasProperty IPAddress = ClientIPAddress
		State     AliasProperty State = ConnectionState


	.PARAMETER ComputerName
	    	The name of the terminal server computer. The default is the local computer. Default value is the local computer (localhost).

	.PARAMETER Id
		Specifies the session Id number.

	.PARAMETER InputObject
		   Specifies a session object. Enter a variable that contains the object, or type a command or expression that gets the sessions.

	.PARAMETER Filter
		   Specifies a filter based on the session properties. The syntax of the filter, including the use of
		   wildcards and depends on the properties of the session. Internally, The Filter parameter uses client side
		   filtering using the Where-Object cmdlet, objects are filtered after they are retrieved.

	.PARAMETER State
		The connection state of the session. Use this parameter to get sessions of a specific state. Valid values are:

		Value		 Description
		-----		 -----------
		Active		 A user is logged on to the session.
		ConnectQuery The session is in the process of connecting to a client.
		Connected	 A client is connected to the session).
		Disconnected The session is active, but the client has disconnected from it.
		Down		 The session is down due to an error.
		Idle		 The session is waiting for a client to connect.
		Initializing The session is initializing.
		Listening 	 The session is listening for connections.
		Reset		 The session is being reset.
		Shadowing	 This session is shadowing another session.

	.PARAMETER ClientName
		The name of the machine last connected to a session.
		Use this parameter to get sessions made from a specific computer name. Wildcrads are permitted.

	.PARAMETER UserName
		Use this parameter to get sessions made by a specific user name. Wildcrads are permitted.

	.EXAMPLE
		Get-TSSession

		Description
		-----------
		Gets all the sessions from the local computer.

	.EXAMPLE
		Get-TSSession -ComputerName comp1 -State Disconnected

		Description
		-----------
		Gets all the disconnected sessions from the remote computer 'comp1'.

	.EXAMPLE
		Get-TSSession -ComputerName comp1 -Filter {$_.ClientIPAddress -like '10*' -AND $_.ConnectionState -eq 'Active'}

		Description
		-----------
		Gets all Active sessions from remote computer 'comp1', made from ip addresses that starts with '10'.

	.EXAMPLE
		Get-TSSession -ComputerName comp1 -UserName a*

		Description
		-----------
		Gets all sessions from remote computer 'comp1' made by users with name starts with the letter 'a'.

	.EXAMPLE
		Get-TSSession -ComputerName comp1 -ClientName s*

		Description
		-----------
		Gets all sessions from remote computer 'comp1' made from a computers names that starts with the letter 's'.

	.OUTPUTS
		Cassia.Impl.TerminalServicesSession

	.COMPONENT
		TerminalServer

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSTerminalServices

	.LINK
		http://code.google.com/p/cassia/

	.LINK
		Stop-TSSession
		Disconnect-TSSession
		Send-TSMessage
	#>


	[OutputType('Cassia.Impl.TerminalServicesSession')]
	[CmdletBinding(DefaultParameterSetName='Session')]

	Param(

		[Parameter()]
		[Alias('CN','IPAddress')]
		[System.String]$ComputerName,

		[Parameter(
			Position=0,
			ValueFromPipelineByPropertyName=$true,
			ParameterSetName='Session'
		)]
		[Alias('SessionID')]
		[ValidateRange(0,65536)]
		[System.Int32]$Id=-1,

		[Parameter(
			Position=0,
			Mandatory=$true,
			ValueFromPipeline=$true,
			ParameterSetName='InputObject'
		)]
		[Cassia.Impl.TerminalServicesSession]$InputObject,

		[Parameter(
			Mandatory=$true,
			ParameterSetName='Filter'
		)]
		[ScriptBlock]$Filter,

		[Parameter()]
		[ValidateSet('Active','Connected','ConnectQuery','Shadowing','Disconnected','Idle','Listening','Reset','Down','Initializing')]
		[Alias('ConnectionState')]
		[System.String]$State='*',

		[Parameter()]
		[System.String]$ClientName='*',

		[Parameter()]
		[System.String]$UserName='*'
	)


	begin
	{
		try
		{
			$FuncName = $MyInvocation.MyCommand
			Write-Verbose "[$funcName] Entering Begin block."

			if(!$ComputerName)
			{
				Write-Verbose "[$funcName] $ComputerName is not defined, loading global value '$script:Server'."
				$ComputerName = Get-TSGlobalServerName
			}
			else
			{
				$ComputerName = Set-TSGlobalServerName -ComputerName $ComputerName
			}


			Write-Verbose "[$FuncName] Attempting remote connection to '$ComputerName'"
			$TSManager = New-Object Cassia.TerminalServicesManager
			$TSRemoteServer = $TSManager.GetRemoteServer($ComputerName)
			$TSRemoteServer.Open()

			if(!$TSRemoteServer.IsOpen)
			{
				Throw 'Connection to remote server is not open. Use Connect-TSServer to connect first.'
			}

			Write-Verbose "[$FuncName] Connection is open '$ComputerName'"
			Write-Verbose "[$FuncName] Updating global Server name '$ComputerName'"
			$null = Set-TSGlobalServerName -ComputerName $ComputerName
		}
		catch
		{
			Throw
		}
	}


	Process
	{

		Write-Verbose "[$funcName] Entering Process block."

		try
		{
			if($PSCmdlet.ParameterSetName -eq 'Session')
			{
				Write-Verbose "[$FuncName] Binding to ParameterSetName '$($PSCmdlet.ParameterSetName)'"
				if($Id -lt 0)
				{
					$session = $TSRemoteServer.GetSessions()
				}
				else
				{
					$session = $TSRemoteServer.GetSession($Id)
				}
			}

			if($PSCmdlet.ParameterSetName -eq 'InputObject')
			{
				Write-Verbose "[$FuncName] Binding to ParameterSetName '$($PSCmdlet.ParameterSetName)'"
				$session = $InputObject
			}

			if($PSCmdlet.ParameterSetName -eq 'Filter')
			{
				Write-Verbose "[$FuncName] Binding to ParameterSetName '$($PSCmdlet.ParameterSetName)'"

				$TSRemoteServer.GetSessions() | Where-Object $Filter
			}

			if($session)
			{
				$session | Where-Object {$_.ConnectionState -like $State -AND $_.UserName -like $UserName -AND $_.ClientName -like $ClientName } | `
				Add-Member -MemberType AliasProperty -Name IPAddress -Value ClientIPAddress -PassThru | `
				Add-Member -MemberType AliasProperty -Name State -Value ConnectionState -PassThru
			}
		}
		catch
		{
			Throw
		}
	}

	end
	{
		try
		{
			Write-Verbose "[$funcName] Entering End block."
			Write-Verbose "[$funcName] Disconnecting from remote server '$($TSRemoteServer.ServerName)'"
			$TSRemoteServer.Close()
			$TSRemoteServer.Dispose()
		}
		catch
		{
			Throw
		}
	}
}
