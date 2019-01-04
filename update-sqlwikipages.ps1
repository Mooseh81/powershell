import-module sqlserver
Add-Type -AssemblyName System.Web

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

$protocol = 'http://'
$wiki = 'wiki.holmans.com/'
$api = 'api.php'
$username = ''
$password = ''
$SQLServers = @("SERVERNAME1","SERVERNAME2")
#$SQLServers = @("SERVERNAME")
foreach ($SQLServer in $SQLServers){
	$inst = @()
	$instlink = @()
	try{
		$Instances = (Get-ChildItem -Path "SQLSERVER:\SQL\$SQLServer")
	}catch{
		write-output "Error with $SQLServer listing instances"
	}
	foreach ($instance in $instances){
	$databasetable = @"
{| class="wikitable"
|+
!Database Name
!Size
!Recovery Model
|-
"@
		$instancename = $instance -replace '[][]',''
		if ($instancename -eq $SQLServer){
			$instancename = "$SQLServer\DEFAULT"
			$curinst = "$SQLServer\DEFAULT"
			$inst+= "$SQLServer\DEFAULT"
			$defaultinst = $true
			$instlink+= @"
[[$SQLServer\DEFAULT]]
"@
		} else {
			$defaultinst = $false
			$curinst = "$instancename"
			$inst+= "$instancename"
			$instlink+= @"
|[[$instancename]]
|-

"@
		}
		try{
			$databases = $instance | get-sqlDatabase  | Where-Object {($_.name -ne "master") -and ($_.name -ne "model") -and ($_.name -ne "msdb") -and ($_.name -ne "tempdb")} | Select-Object Name,Size,RecoveryModel
		}catch{
			write-output "Error listing database on instance $instance"
		}
		try{
			if (!$defaultinst){
				$version = Invoke-SqlCmd -query "select @@version" -ServerInstance "$instancename" | Out-String
			}else{
				$version = Invoke-SqlCmd -query "select @@version" -ServerInstance "$SQLServer" | Out-String
			}
		}catch{
			write-output "Error getting version $instancename"
		}
		if ($version -like "*Microsoft SQL Server 2014*"){
			$sqlversion = "[[SQL Server 2014]]"
		} elseif ($version -like "*Microsoft SQL Server 2016*"){
			$sqlversion = "[[SQL Server 2016]]"
		} elseif ($version -like "*Microsoft SQL Server 2008 R2*"){
			$sqlversion = "[[SQL Server 2008 R2]]"
		}elseif ($version -like "*Microsoft SQL Server 2012*"){
			$sqlversion = "[[SQL Server 2012]]"
		}elseif ($version -like "*Microsoft SQL Server 2017*"){
			$sqlversion = "[[SQL Server 2017]]"
		}elseif ($version -like "*Microsoft SQL Server 2005*"){
			$sqlversion = "[[SQL Server 2005]]"
		}else{
			$sqlversion = $version
		}
		foreach ($database in $databases){
			$dbname = $database.name
			$dbsize = $database.size /1024
			$dbrm = $database.recoverymodel
			$databasetable+=@"

|[[$instancename\$dbname|$dbname]]
|$dbsize
|$dbrm
|-
"@
		}
		$bodytext = @"
{{Note|notetext=This page is created dynamically.  Any updates will be lost on the next refresh}}
== Version ==
$sqlversion

== Databases ==
$databasetable
"@
	try{
		invoke-login $username $password
		edit-page "$curinst" "$curinst" "$bodytext"
	}catch{
		$ErrorMessage = $_.Exception.Message
		write-output "Wiki Update Error: $ErrorMessage"
	}
	}

	$wmiOS = Get-WmiObject -ComputerName $SQLServer -Class Win32_OperatingSystem;
	$OS = $wmiOS.caption
	if ($OS -eq "Microsoft Windows Server 2016 Standard"){
		$OS =  "Windows Server 2016"
	}
	if ($OS -eq "Microsoft Windows Server 2012 R2 Standard"){
		$OS =  "Windows Server 2012 R2"
	}
	if ($OS -like "*Server 2008 R2*"){
		$OS =  "Windows Server 2008 R2"
	}
	if ($OS -like "*2008 Standard*"){
		$OS =  "Windows Server 2008"
	}
	if ($OS -like "*Server 2003*"){
		$OS =  "Windows Server 2003"
	}
	$IPAddress = [System.Net.Dns]::GetHostAddresses("$SPServerName").IPAddressToString | select-object -first 1
	$bodytext = @"
{{Note|notetext=This page is created dynamically.  Any updates will be lost on the next refresh}}
{{VMDetails|servername=$SQLServer|ipaddress=$IPAddress|operatingsystem=$OS|mainrole=SQL}}
== Instances ==
{| class="wikitable"
|+
!Instance
|-
$instlink
|}
"@
	try{
		invoke-login $username $password
		edit-page "$SQLServer" "$SQLServer" "$bodytext"
	}catch{
		$ErrorMessage = $_.Exception.Message
		write-output "Wiki Update Error: $ErrorMessage"
	}
}
