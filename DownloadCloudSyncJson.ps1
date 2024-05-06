$ServicePrincipalID="12360c7b-b607-41e5-9f90-f60c0ab83e9b"
$SyncJobbID="AAD2ADGroupProvisioning.123efeaa45b49f4a4a430d135e944f5.f2c8e3df-73dd-47ec-81d7-d65379702efe"
$OutPath="c:\temp\syncJobJSON.json"


function Get-AppAuthCredentials{
    param (
        [Parameter(Mandatory=$false)][string]$Environment
    )

    # Application (client) ID, tenant ID and secret
    if ($Environment -eq "DEV" -OR !($Environment)) {
        $clientId = (Get-Secret "AppReg-CloudSync-AppID" -Vault Local -AsPlainText) #Insert the AppReg Application ID here. 
        $tenantId = (Get-Secret "AppReg-CloudSync-TenantID" -Vault Local -AsPlainText) #Insert the TenantID here
        $clientSecret = (Get-Secret "AppReg-CloudSync-AppSecret" -Vault Local -AsPlainText) # Insert the ClientSecret Value here
    }

    # Construct URI
    $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    # Construct Body
    $body = @{
        client_id     = $clientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $clientSecret
        grant_type    = "client_credentials"
    }

    # Get OAuth 2.0 Token
    $tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing

    # Access Token
    return $token = ($tokenRequest.Content | ConvertFrom-Json).access_token
    #$tokenRequestTime=get-date
}
$token=Get-AppAuthCredentials

$graphBaseURL="https://graph.microsoft.com"
$graphVersion="/beta"
$query=@{
    Method="GET"
    URI=$graphBaseURL+$graphVersion+"/servicePrincipals/"+$ServicePrincipalID+"/synchronization/jobs/"+$SyncJobbID+"/schema"
    Headers=@{
        Authorization="Bearer $($token)"
    }
    ContentType="application/json"
    ErrorAction="Stop"
}
try {
    $CloneObjectrequest=Invoke-RestMethod @query    
}
catch {
    Write-Error -Message "Could not fetch the template from the existing job"
    $Errors[0]
}
$cloneObjectrequest |convertto-json -Depth 50 |Out-File $OutPath