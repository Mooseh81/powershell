param (
   [string]$SPServerName,
   [string]$SPIPAddress,
   [int]$SPvCPU,
   [int]$SPMemory,
   [string]$SPDatacentre,
   [string]$SPNetwork,
   [string]$SPOS,
   [string]$SPUsername,
   [string]$SPPassword,
   [string]$SPUser,
   [string]$SPRFC,
   [string]$SPBackup
)

#Load Modules
import-Module VMware.VimAutomation.Core
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Web

#
$password = $SPPassword | ConvertTo-SecureString -asPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($SPUsername,$password)


function Edit-Page($title, $summary, $text)
{
    $uri = $protocol + $wiki + $api

    $body = @{}
    $body.action = 'edit'
    $body.format = 'json'
    $body.bot = ''
    $body.title = $title
    $body.summary = $summary
    $body.text = $text
    $body.token = Get-CsrfToken

    $object = Invoke-WebRequest $uri -Method Post -Body $body -WebSession (Get-WebSession) -UseBasicParsing
    $json = $object.Content
    $object = ConvertFrom-Json $json

    if($object.edit.result -ne 'Success')
    {
        throw('Error editing page:' + $object + ',' + $object.error)
    }
}

function Get-CsrfToken()
{
    if($csrftoken -eq $null)
    {
        $uri = $protocol + $wiki + $api

        if((Get-Version) -lt '1.24')
        {
            $uri = $protocol + $wiki + $api

            $body = @{}
            $body.action = 'query'
            $body.format = 'json'
            $body.prop = 'info'
            $body.intoken = 'edit'
            $body.titles = 'User:' + $username

            $object = Invoke-WebRequest $uri -Method Get -Body $body -WebSession (Get-WebSession) -UseBasicParsing
            $json = $object.Content
            $object = ConvertFrom-Json $json

            $pages = $object.query.pages
            $page = ($pages | Get-Member -MemberType NoteProperty).Name
            $csrftoken = $pages.($page).edittoken
        }
        else
        {
            $body = @{}
            $body.action = 'query'
            $body.format = 'json'
            $body.meta = 'tokens'
            $body.type = 'csrf'

            $object = Invoke-WebRequest $uri -Method Get -Body $body -WebSession (Get-WebSession) -UseBasicParsing
            $json = $object.Content
            $object = ConvertFrom-Json $json

            $csrftoken = $object.query.tokens.csrftoken
        }
    }

    return $csrftoken
}

function Get-Version()
{
    if($wikiversion -eq $null)
    {
        $uri = $protocol + $wiki + $api

        $body = @{}
        $body.action = 'query'
        $body.format = 'json'
        $body.meta = 'siteinfo'
        $body.siprop = 'general'

        $object = Invoke-WebRequest $uri -Method Get -Body $body -WebSession (Get-WebSession) -UseBasicParsing
        $json = $object.Content
        $object = ConvertFrom-Json $json

        $wikiversion = $object.query.general.generator
        $wikiversion = $wikiversion -replace 'MediaWiki ', ''
    }

    return $wikiversion
}

function Invoke-Login($username, $password)
{
    $uri = $protocol + $wiki + $api

    $body = @{}
    $body.action = 'login'
    $body.format = 'json'
    $body.lgname = $username
    $body.lgpassword = $password

    $object = Invoke-WebRequest $uri -Method Post -Body $body -SessionVariable global:websession -UseBasicParsing
    $json = $object.Content
    $object = ConvertFrom-Json $json

    if($object.login.result -eq 'NeedToken')
    {
        $uri = $protocol + $wiki + $api

        $body.action = 'login'
        $body.format = 'json'
        $body.lgname = $username
        $body.lgpassword = $password
        $body.lgtoken = $object.login.token

        $object = Invoke-WebRequest $uri -Method Post -Body $body -WebSession $global:websession -UseBasicParsing
        $json = $object.Content
        $object = ConvertFrom-Json $json
    }
    if($object.login.result -ne 'Success')
    {
        throw ('Login.result = ' + $object.login.result)
    }
}


function Get-WebSession()
{
    if($websession -eq $null)
    {
        Invoke-LogIn $username $password
    }
    return $websession
}

$result = $false

Try {
        $validName = Get-ADComputer $SPServerName -ErrorAction Stop
    }
	Catch{
	}
	
if($validName){
	write-output "Server $SPServerName already exists please either change the name or delete from AD (Remember to wait for the change to replicate) $validName"
	exit 1
}

#Check IP Address
Try{
	$validIP = Test-Connection -ComputerName $SPIpAddress
	}
	Catch {
	}

if($validIP){
	write-output "IP Address $SPIPAddress is already in use"
	exit 1
}

   If ($SPDatacentre -eq "####") {
   		$Global:VCS = "####"
		$Global:DCFull = "####"
		$Global:Range = "####"
		$Global:DNSServer = "####"
		$Global:Gateway = "####"
		$Global:BaseOU = "####"
   }
    if ($SPDatacentre -eq "####"){
   		$Global:VCS = "####"
		$Global:DCFull = "####"
		$Global:Range = "####"
		$Global:DNSServer = "####"
		$Global:Gateway = "####"
		$Global:BaseOU = "####"
	}
	    if ($SPDatacentre -eq "####"){
		$Global:VCS = "####"
		$Global:DCFull = "####"
		$Global:Range = "####"
		$Global:DNSServer = "####"
		$Global:Gateway = "####"
		$Global:BaseOU = "####"
	}
		if ($SPDatacentre -eq "####"){
		$Global:VCS = "####"
		$Global:DCFull = "####"
		$Global:Range = "####"
		$Global:DNSServer = "####"
		$Global:Gateway = "####"
		$Global:BaseOU = "####"
	}
		if ($SPDatacentre -eq "####"){
		$Global:VCS = "####"
		$Global:DCFull = "####"
		$Global:Range = "####"
		$Global:DNSServer = "####"
		$Global:Gateway = "####"
		$Global:BaseOU = "####"
	}
	
	   If ($SPOS -like "*2016*"){
	$Global:OperatingSystemSelected = "2016"
	$Global:BasevCPU = "1"
	$Global:BaseMemory = "4"
	$Global:ProductKey = "####"
	$Global:Template = "WIN2016"
   }
   
try{
	connect-viserver $Global:VCS -cred $cred
}catch{
	$ErrorMessage = $_.Exception.Message
write-output "VCS Error: $ErrorMessage"
}

try{
	$Datacenter = get-Datacenter $DCFull
}catch{
    $ErrorMessage = $_.Exception.Message
	write-output "Datacenter Error: $ErrorMessage"
}

try{
	$Cluster = get-datacenter $DCFull | get-cluster $SPNetwork
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Cluster Error: $ErrorMessage"
}

try{
	$Datastore = get-cluster $Cluster | Get-vmhost | get-datastore | Get-Datastorecluster 
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Datastore Error: $ErrorMessage"
}

$Datastoreselected = Get-Datastorecluster $datastore | Get-Datastore | Sort-Object FreeSpaceGB -Descending | select-object -first 1
$pfiledatastore = "$datastoreselected" + "_pagef"
$pfilesize = 1.5 * $SPMemory
$AdminPassword = "B1tbctl1"
$TemplateSelected = get-template -location $DCFull | Where-object {$_.name -like "*$template*"} | select-object -first 1
$RunOnce = ("wuauclt.exe /detectnow /updatenow","sc config `"Sophos AutoUpdate Service`" start=auto","netsh interface set interface name = Ethernet0 newname = ServerProduction")
$custSpec = New-OSCustomizationSpec -Type NonPersistent -OSType Windows -FullName $SPServername -OrgName "Holmans" -name $SPServername -Domain "####"  -DomainCredentials $Cred -productkey $ProductKey -adminpassword $AdminPassword -Timezone 090 -ChangeSID -GuiRunOnce $RunOnce -AutoLogonCount 1 -confirm:$false
$custSpec | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode UseStaticIP -IpAddress $SPIPAddress -SubnetMask 255.255.255.0 -Dns $DNSServer -DefaultGateway $Gateway
try{
New-VM -Name $SPServerName -Template $TemplateSelected -OSCustomizationSpec $custSpec -resourcepool $Cluster -datastore $Datastoreselected
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Build Error: $ErrorMessage"
}

try{
Set-VM -VM $SPServerName -NumCpu $SPvCPU -MemoryGB $SPMemory -Confirm:$false
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Customisation Error: $ErrorMessage"
	exit 1
}
try{
New-HardDisk -VM $SPServerName -CapacityGB $pfilesize -Persistence IndependentNonPersistent -datastore $pfiledatastore
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Hard Disk Error: $ErrorMessage"
	exit 1
}
try{
Start-VM $SPServerName

}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Start VM Error: $ErrorMessage"
	exit 1
}

try{
	Do{
		Start-Sleep -Seconds 60
		$events = Get-VM -Name $SPServerName | Get-VIEvent -Types Info | Where-Object {($_ -is "VMware.Vim.CustomizationSucceeded") -or ($_ -is "VMware.Vim.CustomizationFailed")}
	}While($events -eq $null)
		If($events -is "VMware.Vim.CustomizationSucceeded")
	{
		Write-Output "Customization Completed Successfully"
	}
	ElseIF($events -is "VMware.Vim.CustomizationFailed")
	{
		Write-Output "Customization Did Not Complete Successfully"
	}
}catch{
		$ErrorMessage = $_.Exception.Message
		write-output "Start VM Error: $ErrorMessage"
		exit 1
}
Start-Sleep -Seconds 60
$secpwd=ConvertTo-SecureString $AdminPassword -AsPlainText -Force  
$credps = New-Object System.Management.Automation.PSCredential ("Administrator",  $secpwd)

try{
	Invoke-VMScript -VM $SPServerName -scripttext "Initialize-Disk 1;New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter P| Format-Volume -FileSystem NTFS -NewFileSystemLabel Pagefile" -guestcredential $credps
	Start-Sleep -Seconds 60
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Intialise Pagefile Error: $ErrorMessage"
	exit 1
	}

try{
	Invoke-VMScript -VM $SPServerName -scripttext "wmic.exe set AutomaticManagedPagefile=False;wmic.exe pagefileset create name='P:\pagefile.sys';wmic.exe pagefileset where name='C:\\pagefile.sys' delete" -guestcredential $credps
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Set Pagefile Error: $ErrorMessage"
	exit 1
}
Restart-VMGuest -VM $SPServerName -Confirm:$false


$protocol = 'http://'
$wiki = 'wiki.#####.com/'
$api = 'api.php'
$username = '###'
#$password = '##'
$password = '##'

try{
	invoke-login $username $password
	edit-page "$SPServerName" "$SPServerName" "{{VMDetails|servername=$SPServerName|ipaddress=$SPIPAddress|operatingsystem=$SPOS|mainrole=}}"
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Wiki Update Error: $ErrorMessage"
}
try{
	$date = Get-Date -Format g
	Set-Annotation $SPServerName -CustomAttribute "Build Date" -Value $date
	Set-Annotation $SPServerName -CustomAttribute "Requested by" -Value $SPUser
	Set-Annotation $SPServerName -CustomAttribute "RFC" -Value $SPRFC
	if ($SPBackup -eq "Yes"){
	Set-Annotation $SPServerName -CustomAttribute "Backup" -Value "Yes"
	}
}catch{
	$ErrorMessage = $_.Exception.Message
	write-output "Custom Attribute Error: $ErrorMessage"
}
Try {
        $validName = Get-ADComputer $SPServerName -ErrorAction Stop
    }
Catch{
}
	
Try{
	$validIP = Test-Connection -ComputerName $SPServerName
	}
	Catch {
}	
	
if($validName -and $validip){
	write-output "Server built Successfully!"
}


