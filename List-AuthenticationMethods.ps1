<#
.SYNOPSIS

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        0.1
Creation Date:  2023/06/23

.DESCRIPTION
This Scripts lists all Users and their registered authentication methods.
It needs an App Registration which has the delegated app permissions 'User.Read.All' and 'UserAuthenticationMethod.Read.All'
The Authentication platform configuration should be a 'Mobile and desktop application' which can issue Access Tokens

.PARAMETER ReportPath
This Parameter defines csv-report ist stored. 

.EXAMPLE
List-AuthenticationMethods.ps1 -ImageRootPath 'C:\Temp\UploadImages'
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][string]$ReportPath="c:\Temp"
)

#Requires -Version 7

#Vars
$GraphURL="https://graph.microsoft.com/beta/"
$tenantID="763aefea-a45b-49f4-a4a4-30d135e944f5"
$AppID="21dad8ef-8626-4551-b69d-f0749705e3c4"
$redirectUri="https://login.microsoftonline.com/common/oauth2/nativeclient"

function Get-UserAuthCredentials{
    param (
    [Parameter(Mandatory=$false)][string]$Environment
)


    #Source App Data: Fill in Client ID, Secret and RedirectUri here:


    if ($Environment -eq "ShortName" -OR !($Environment)){
        $clientId = $AppID
        $tenantId = $tenantid
        $redirectUri=$redirectUri
    }

    $resource = "https://graph.microsoft.com"

Function Get-AuthCode {
    Add-Type -AssemblyName System.Windows.Forms

    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($url -f ($Scope -join "%20")) }

    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri        
        if ($Global:uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null

    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    $output = @{}
    foreach($key in $queryOutput.Keys){
        $output["$key"] = $queryOutput[$key]
    }

    #$output
}

Write-Host -ForegroundColor Gray -Object "Action: Please Logon to the AzureAD of the Tenant." # TBD Permissions Admin or any user?

Add-Type -AssemblyName System.Web
$clientIDEncoded = [System.Web.HttpUtility]::UrlEncode($ClientID)
$clientSecretEncoded = [System.Web.HttpUtility]::UrlEncode($ClientSecret)
$redirectUriEncoded =  [System.Web.HttpUtility]::UrlEncode($redirectUri)
$resourceEncoded = [System.Web.HttpUtility]::UrlEncode($resource)


# Get AuthCode
$url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&redirect_uri=$redirectUriEncoded&client_id=$clientIDEncoded&resource=$resourceEncoded"
Get-AuthCode

# Extract Access token from the returned URI
$regex = '(?<=code=)(.*)(?=&)'
$authCode  = ($uri | Select-string -pattern $regex).Matches[0].Value

#get Access Token
#$body = "grant_type=authorization_code&redirect_uri=$redirectUri&client_id=$clientId&client_secret=$clientSecretEncoded&code=$authCode&resource=$resource"
$body = "grant_type=authorization_code&redirect_uri=$redirectUri&client_id=$clientId&code=$authCode&resource=$resource"
$tokenResponse = Invoke-RestMethod https://login.microsoftonline.com/common/oauth2/token `
    -Method Post -ContentType "application/x-www-form-urlencoded" `
    -Body $body `
    -ErrorAction STOP

#EndRegion Auth
$output=$tokenResponse.access_token
$output

#EndRegion Auth
}

$token=Get-UserAuthCredentials

$UserCollection=@()

#List all Users:
$command=@{
    Method="GET"
    Headers=@{
        Authorization="Bearer $($token)"
    } 
    ContentType= "application/json; charset=utf-8"
    URI=($GraphURL+"users?`$select=userPrincipalName,id")
    ErrorAction = "Stop"
}
try {
    do {
        Write-Host -ForegroundColor Gray -Object "INFO: Collecting Users from AAD"
        $Query=Invoke-RestMethod @command
        $UserCollection+=$query.value

    } until (
        !($Query."@odata.nextlink")
    )
}
catch {
    Write-Host -ForegroundColor RED -Object "ERROR: Unable to list users."
    $SkippedImages+=$imageFile
}
#EndRegion

$authorizationCollection=@()
Write-Host -ForegroundColor Gray -Object "INFO: Collecting Authentication Methods"
foreach($user in $UserCollection){
    
    $command.URI=($GraphURL+"users/"+$($user.id)+"/authentication/methods")
    $Query=Invoke-RestMethod @command

    $authorizationCollection+=[PSCustomObject]@{
        UserID = $user.id
        userPrincipalName = $user.userPrincipalName
        #authenticationMethods= $query.value
        authenticationMethods=($Query.value."@odata.type") -join ','
        NeedsToRegisterSecureMFA= $(if($Query.value."@odata.type" -notcontains "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" ){$true})
    }
}

try {
    $ReportOutputPath=($ReportPath+"\AuthenticationMethodReport_"+(Get-Date -Format FileDateTimeUniversal)+".csv")
    $authorizationCollection |export-csv -Path $ReportOutputPath -Delimiter ';' -Encoding utf8
    Write-Host -ForegroundColor Gray -Object "INFO: Report was stored in $($ReportOutputPath)"
}
catch {
    Write-Host -ForegroundColor RED -Object "ERROR: An Error occured while exporting the report to $($ReportOutputPath)"
}

