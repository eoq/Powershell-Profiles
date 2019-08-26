#create a new profile
#new-item -itemtype file -force $profile
#edit profile
#notepad $profile

#load this with:
#  iex(new-object net.webclient).downloadstring('https://edpublic.azurewebsites.net/files/gprofile.txt')
#  iex(new-object net.webclient).downloadstring('http://sysadmweb.kelly.com/gprofile.txt')
#
# append the following line to $profile to make this profile load for all shells
# . "C:\Users\quilleo\Google Drive\global\profile.ps1"
#
#
#
#

#save previous erroraction and hide errors for the rest of the profile in case we run it multiple times
$prevAction=$ErrorActionPreference
$ErrorActionPreference='silentlycontinue'

#vim stuff
$LPath="$env:appdata\0ed"
$VIMPath="$LPath\gVimPortable\app\vim\vim74"
$GVIMPath="$VIMPath\gvim.exe"
$VIMPath="$VIMPath\vim.exe"

function Check-VIMStatus {
  if (-not (test-path -path $GVIMPath)) {
    write-host "Portable vim is not installed. Run Install-VIM ..."
	return $FALSE
  }
  return $TRUE
}
 
function Install-VIM {
  if( -not (Check-VIMStatus)) {
    write-output "Installing VIM ..."
	$tmpfname=[System.IO.Path]::GetTempFileName()
        $p="h:\installs\gVimPortable.zip"
        if(test-path $p) {
          copy-item $p -destination "$env:tmp\gVimPortable.zip"
        }else {
	  (new-object net.webclient).downloadfile('https://edprivate.blob.core.windows.net/data/gVimPortable.zip',"$env:tmp\gVimPortable.zip")
        }
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	[System.IO.Compression.ZipFile]::ExtractToDirectory("$env:tmp\gVimPortable.zip",$LPath)
  }
}

Function Get-FolderSizes
{   #requires -version 3.0
    Param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    If (Test-Path $Path -PathType Container)
    {   ForEach ($Folder in (Get-ChildItem $Path -Directory ))
        {   [PSCustomObject]@{
                Folder = $Folder.FullName
                Size = (Get-ChildItem $Folder.FullName -Recurse | Measure-Object Length -Sum).Sum
            }
        }
    }
}

Function Compare-ObjectProperties {
    Param(
        [PSObject]$ReferenceObject,
        [PSObject]$DifferenceObject 
    )
    $objprops = $ReferenceObject | Get-Member -MemberType Property,NoteProperty | % Name
    $objprops += $DifferenceObject | Get-Member -MemberType Property,NoteProperty | % Name
    $objprops = $objprops | Sort | Select -Unique
    $diffs = @()
    foreach ($objprop in $objprops) {
        $diff = Compare-Object $ReferenceObject $DifferenceObject -Property $objprop
        if ($diff) {            
            $diffprops = @{
                PropertyName=$objprop
                RefValue=($diff | ? {$_.SideIndicator -eq '<='} | % $($objprop))
                DiffValue=($diff | ? {$_.SideIndicator -eq '=>'} | % $($objprop))
            }
            $diffs += New-Object PSObject -Property $diffprops
        }        
    }
    if ($diffs) {return ($diffs | Select PropertyName,RefValue,DiffValue)}     
}

###### key mappings (psreadline) ##########
Set-PSReadLineOption -EditMode Emacs
if(!$?) {
  #probably < 5.0 so lets at least do this ...
  Set-PSReadLineKeyHandler -Chord Ctrl+d -Function DeleteChar
}

###### aliases ############################ 
#
#

function top {gwmi Win32_PerfFormattedData_PerfProc_Process -filter "PercentProcessorTime > 1" | Sort PercentProcessorTime -desc | ft PercentProcessorTime,Name,idprocess,IODataBytesPersec}

new-alias grep findstr
#grep as select-string doesn't process object lists as you would think: gal | select-string grep to see what i am saing
#new-alias grep Select-String
#alternate grep method
#function grep {
#  $input | out-string -stream | select-string $args
#}
function rpm {Get-WmiObject -Class Win32_Product}
function uptime {Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime}
function ruptime {Get-CimInstance -computername $args[0] -ClassName win32_operatingsystem | select csname, lastbootuptime}
function fta {
  param (
    [parameter(ValueFromPipeline)]
    $stuff
  )
  $stuff | format-table -autosize
}
new-alias wc measure
new-alias less more
new-alias df get-psdrive
new-alias vim $VIMPath
new-alias vi vim
new-alias gvim $GVIMPath
new-alias lsltr ls-ltr
new-alias notepad++ "C:\Program Files (x86)\Notepad++\notepad++.exe"
new-alias np notepad++
new-alias npp notepad++
new-alias code "$ENV:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"
new-alias which get-command
new-alias ff Find-Files
new-alias find Find-Files
function ss {Get-AzSubscription | ogv -PassThru | Select-AzSubscription}  #azure
function vip {gvim $gsource}
function ls-ltr {gci $args | sort LastWriteTime}
function islocked {get-aduser $args[0] -properties * | select lockedout}
function cdrdm {cd \\amer\dfs\winlin\wintel\Public\Scripts\rdm}
function cddr {cd \\amdrwfs01\drdoc\ILNX\0dr_recovery_scripts}
function head {$input | select-object -first 10}
function mygal {cat $gfile | sls "^new-alias|^func"}
function hs {Get-Content (Get-PSReadlineOption).HistorySavePath |sls $args}
function as {get-azcontext;get-azvm | measure | select count} #azure
#function golab {select-azurermprofile c:\temp\azure_lab.txt}
#function goprod {select-azurermprofile c:\temp\azure_prod.txt}

#otv will pipe input to gvim for eyeballing
function otv { param([parameter(ValueFromPipeline=$TRUE)] $i ) Begin {$all=@()} Process {$all += $i} End {$all | out-string -width 4096 | gvim -R -c "set guioptions+=b" -c "set nowrap" -}}

#new-alias powercli ". C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1"

function powercli {
  Add-PsSnapin VMware.VimAutomation.Core -ea "SilentlyContinue"
  #Add-PSSnapin VMware.VumAutomation.Core
  #Add-PSSnapin VMware.VumAutomation
  foreach ($d in ("C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Scripts","C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1")) {
	if(test-path $d) {
		. "$d\Initialize-PowerCLIEnvironment.ps1"
		break
	}
  }
}

function tips {
  "";
  "";
  'ps | group-object name	#total up distict name';
  '(get-date).AddDays(-7)	#last week date';
  'dir | sort LastWriteTime -Descending | select -First 10	#ls -ltr | head';
  '$profile | fl -force		#list all profiles';
  "gal | grep -i string  	#to list all alias and search for a string";
  "| gm				#describe object from pipe";
  "| format-table -autosize	#";
  "| select -first 5		#head"
  "| select id			#awk "
  "| where {\$_.processname -match 'xiv'} #egrep, -match is regex"
  "Get-WmiObject -computername amtrowtm103 -Class Win32_LogicalDisk | Where { $_.DriveType -eq 3 } | ft"
  "";
  "h				#alias for show history";
  "r <#>			#alias to run past command from history";
  "";
  "dir variable:		#list all vars";
  "@(Dir).Count			#force dir output into an array and show count"
  '(new-object Net.WebClient).DownloadString("http://...ps1") | iex #download url and execute'
  'foreach ($srv in "amtrowbtfsp02","amtrowbs13prf02","amtrowbs13prd02") { " ... $srv ...";Get-EventLog system -Newest 500 -ComputerName $srv | where { $_.TimeGenerated -ge "01/21/2016 10:00" -and $_.EntryType -ne "Information" } } ';
  "";
  "#HINT:mod tips function in profile.ps1 for add tips"
}

#now lets change the prompt to tell me if i have admin or not
function prompt 
        {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal] $identity

            $(if (test-path variable:/PSDebugContext) { '[DBG]: ' } 

            elseif($principal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
            { "[ADMIN]: " }

            else { '' }) + 'PS ' + $(Get-Location) + $(if ($nestedpromptlevel -ge 1) { '>>' }) + '> '
        }

##########################################################################
#### Here are the commands to run after env is set   #####################
##########################################################################
# Welcome message
#clear-host
#
"You are now entering PowerShell (default profile): " + $env:Username

#Lets check if we have admin privs 
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
$haveAdmin = $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
"I have admin rights?  " + $haveAdmin
""

#change to google drive global if it exists
$GGDIR=$HOME + "\Google Drive\global";if(test-path $ggdir) {cd $ggdir}

#now lets add modules from ggdir if it exists
if(test-path $ggdir\scripts\powershell\Modules) {
  $env:psmodulepath = $env:psmodulepath + ";$ggdir\scripts\powershell\Modules"
}

#restore the previous error action
$ErrorActionPreference=$prevAction

#cleanup variables we used in this profile
Remove-Variable prevaction

Check-VIMStatus | Out-Null


#larger function go below here

function Test-Cred {
           
    [CmdletBinding()]
    [OutputType([String])] 
       
    Param ( 
        [Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
        [Alias( 
            'PSCredential'
        )] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials
    )
    $Domain = $null
    $Root = $null
    $Username = $null
    $Password = $null
      
    If($Credentials -eq $null)
    {
        Try
        {
            $Credentials = Get-Credential "amer\$env:username" -ErrorAction Stop
        }
        Catch
        {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }
      
    # Checking module
    Try
    {
        # Split username and password
        $Username = $credentials.username
        $Password = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Root = "LDAP://" + ([ADSI]'').distinguishedName
        $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    }
    Catch
    {
        $_.Exception.Message
        Continue
    }
  
    If(!$domain)
    {
        Write-Warning "Something went wrong"
    }
    Else
    {
        If ($domain.name -ne $null)
        {
            return "Authenticated"
        }
        Else
        {
            return "Not authenticated"
        }
    }
}

function Find-Files {
  [cmdletbinding()]
  param (
    [Parameter(Position=0)]$Path = ".",
    $mday,
    $mhour,
    $mmin,
    $msec
  )
  $Now=Get-Date
  $SinceWhen=[DateTime]0   #beginning of time by default
  if($mday) {
    $SinceWhen=$Now.AddDays(-$mday)
  }elseif ($mmin) {
    $SinceWhen=$Now.AddMinutes(-$mmin)
  }elseif($mhour) {
    $SinceWhen=$Now.AddHours(-$mhour)
  }elseif($msec) {
    $SinceWhen=$Now.AddSeconds(-$msec)
  }else {
    #default to 1 day
    $SinceWhen=$Now.AddDays(-1)
  }
  Get-ChildItem -Path $Path -File -Recurse | Where-Object {$_.LastWriteTime -ge $SinceWhen} | Sort-Object LastWriteTime -Descending | Select-Object Name,LastWriteTime,Length,FullName
}

Function Get-Software {
  [OutputType('System.Software.Inventory')]
  [Cmdletbinding()] 
  Param( 
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)] 
    [String[]]$Computername = $env:COMPUTERNAME
  )         
  Begin {
  }
  Process {     
    ForEach ($Computer in  $Computername) { 
      If (Test-Connection -ComputerName  $Computer -Count  1 -Quiet) {
        $Paths = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")         
        ForEach ($Path in $Paths) { 
          Write-Verbose  "Checking Path: $Path"
          #  Create an instance of the Registry Object and open the HKLM base key 
          Try { 
            $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine', $Computer, 'Registry64') 
          }
          Catch { 
            Write-Error $_ 
            Continue 
          } 
          #  Drill down into the Uninstall key using the OpenSubKey Method 
          Try {
            $regkey = $reg.OpenSubKey($Path)  
            # Retrieve an array of string that contain all the subkey names 
            $subkeys = $regkey.GetSubKeyNames()      
            # Open each Subkey and use GetValue Method to return the required  values for each 
            ForEach ($key in $subkeys) {   
              Write-Verbose "Key: $Key"
              $thisKey = $Path + "\\" + $key 
              Try {  
                $thisSubKey = $reg.OpenSubKey($thisKey)   
                # Prevent Objects with empty DisplayName 
                $DisplayName = $thisSubKey.getValue("DisplayName")
                If ($DisplayName -AND $DisplayName -notmatch '^Update  for|rollup|^Security Update|^Service Pack|^HotFix') {
                  $Date = $thisSubKey.GetValue('InstallDate')
                  If ($Date) {
                    Try {
                      $Date = [datetime]::ParseExact($Date, 'yyyyMMdd', $Null)
                    }
                    Catch {
                      Write-Warning "$($Computer): $_ <$($Date)>"
                      $Date = $Null
                    }
                  } 
                  # Create New Object with empty Properties 
                  $Publisher = Try {
                    $thisSubKey.GetValue('Publisher').Trim()
                  } 
                  Catch {
                    $thisSubKey.GetValue('Publisher')
                  }
                  $Version = Try {
                    #Some weirdness with trailing [char]0 on some strings
                    $thisSubKey.GetValue('DisplayVersion').TrimEnd(([char[]](32, 0)))
                  } 
                  Catch {
                    $thisSubKey.GetValue('DisplayVersion')
                  }
                  $UninstallString = Try {
                    $thisSubKey.GetValue('UninstallString').Trim()
                  } 
                  Catch {
                    $thisSubKey.GetValue('UninstallString')
                  }
                  $InstallLocation = Try {
                    $thisSubKey.GetValue('InstallLocation').Trim()
                  } 
                  Catch {
                    $thisSubKey.GetValue('InstallLocation')
                  }
                  $InstallSource = Try {
                    $thisSubKey.GetValue('InstallSource').Trim()
                  } 
                  Catch {
                    $thisSubKey.GetValue('InstallSource')
                  }
                  $HelpLink = Try {
                    $thisSubKey.GetValue('HelpLink').Trim()
                  } 
                  Catch {
                    $thisSubKey.GetValue('HelpLink')
                  }
                  $Object = [pscustomobject]@{
                    Computername    = $Computer
                    DisplayName     = $DisplayName
                    Version         = $Version
                    InstallDate     = $Date
                    Publisher       = $Publisher
                    UninstallString = $UninstallString
                    InstallLocation = $InstallLocation
                    InstallSource   = $InstallSource
                    HelpLink        = $thisSubKey.GetValue('HelpLink')
                    EstimatedSizeMB = [decimal]([math]::Round(($thisSubKey.GetValue('EstimatedSize') * 1024) / 1MB, 2))
                  }
                  $Object.pstypenames.insert(0, 'System.Software.Inventory')
                  Write-Output $Object
                }
              }
              Catch {
                Write-Warning "$Key : $_"
              }   
            }
          }
          Catch { }   
          $reg.Close() 
        }                  
      }
      Else {
        Write-Error  "$($Computer): unable to reach remote system!"
      }
    } 
  } 
} 

