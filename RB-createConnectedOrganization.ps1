<#
.SYNOPSIS
Creates a connected organization for a new partner - RB-createConnectedOrganization.ps1

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        1.0
Creation Date:  2020/09/21

.DESCRIPTION
This script is part of a teams Governance Process.
LINK: http://blog.thinformatics.com/2020/09/another-microsoft-teams-governance-approach-using-aad-identity-governance/
In this Azure Automation Runbook a Connected Organization is created which will be used for Access Package Policies and Approval Scenarios

.PARAMETER PartnerDomains
The primary SMTP Domain for the partner
.PARAMETER ExternalSponsors
Array of the users from the partner organization which should be External Sponsor
.PARAMETER GuestInvitationsEnabled
Array of the users from our organization which should be Internal Sponsor
.PARAMETER ConnectedOrgId 
If a connected Org is named, the Guest Access Policy bound to that.

.EXAMPLE
This Script is part of a whole Governance Story and is not intended to run out of this process.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$PartnerDomains,
    [Parameter(Mandatory=$false)][string[]]$ExternalSponsors,
    [Parameter(Mandatory=$false)][string[]]$InternalSponsors
)

$ClientID=Get-AutomationVariable -Name DelegatedAppClientID
$AppCreds=Get-AutomationPSCredential -Name DelegatedAppPermissions

#tempVars
$CustomerDomain=$PartnerDomains

# The resource URI
$resource = "https://graph.microsoft.com"
$GraphVersion = "/beta"
$GraphURL=$resource+$GraphVersion
$guestUsersInvited=@()

# Function to get delegated Account Access Token

Function Get-MSGraphAuthenticationToken {
    
    <#
      .SYNOPSIS
      This function is used to get an authentication token for the Graph API REST interface
      .DESCRIPTION
      Built based on the following example script from Microsoft: https://github.com/microsoftgraph/powershell-intune-samples/blob/master/Authentication/Auth_From_File.ps1
      .EXAMPLE
      $Credential = Get-Credential
      $ClientId = 'f338765e-1cg71-427c-a14a-f3d542442dd'
      $AuthToken = Get-MSGraphAuthenticationToken -Credential $Credential -ClientId $ClientId
  #>
    [cmdletbinding()]
      param
    (
        [Parameter(Mandatory=$true)]
        [PSCredential] $Credential,
        [Parameter(Mandatory=$true)]
        [String]$ClientId
    )
  
    Write-Verbose 'Importing prerequisite modules...'
    try {
    $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    } catch {
         throw 'Prerequisites not installed (AzureAD PowerShell module not installed'
    }

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $Credential.Username
    $tenant = $userUpn.Host
      
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
   
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
  
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com"
    $authority = "https://login.microsoftonline.com/$Tenant"
  
    try {
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($Credential.Username, "OptionalDisplayableId")
        $userCredentials = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential -ArgumentList $Credential.Username,$Credential.Password
        $authResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($authContext, $resourceAppIdURI, $clientid, $userCredentials);
  
        if ($authResult.Result.AccessToken) {
              # Creating header for Authorization token
              $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.Result.AccessToken
                'ExpiresOn'     = $authResult.Result.ExpiresOn
            }
            return $authHeader
        } elseif ($authResult.Exception) {
            throw "An error occured getting access token: $($authResult.Exception.InnerException)"
        }
    }
    catch {
        throw $_.Exception.Message 
    }
}

$AuthToken = Get-MSGraphAuthenticationToken -Credential $AppCreds -ClientId $ClientId


#now do stuff    


#find tenant id of the foreign tenant (lets check how to connect non m365 orgs later)
try {
    $openIdURL="https://login.windows.net/"+$CustomerDomain+"/.well-known/openid-configuration"
    $Content=(Invoke-WebRequest -Uri $openIdURL -UseBasicParsing -ErrorAction Stop).content
    $tokenEndpoint=(ConvertFrom-Json $content -ErrorAction Stop).token_endpoint
    $urlparts=$tokenEndpoint.Split("/")
    $ConnectedOrgTenantID=$urlparts[3]
    $IsM365Tenant=$true
}
catch {
    $IsM365Tenant=$false
}

if ($IsM365Tenant) {
    #check if the connected org already exists before
    $GetConnectedOrgsURI = $GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations"
    $GetConnectedOrgsQuery = Invoke-RestMethod -Method GET -Uri $GetConnectedOrgsURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
    $ConnectedOrgs=$GetConnectedOrgsQuery.value.identitySources.tenantId

    if ($ConnectedOrgs -contains $ConnectedOrgTenantID) {
        #the connected Orf already exists, Skipping further processing
        $statusmessage="The customer domain is contained in a Connected Organization that already exists"
    }else {
        #connected organization is not existant, proceeding to create it
        
        $CreateConnectedOrgURI = $GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations"
        $ConnectedOrgDisplayName=$CustomerDomain
        $ConnectedOrgDescription="Connected Org created while Teams Provisioning Process "+$CustomerDomain


        $CreateConnectedOrgBody =@"
        {
            "displayName": "$ConnectedOrgDisplayName",
            "description": "$ConnectedOrgDescription",
            "identitySources": [
                {
                "@odata.type": "#microsoft.graph.azureActiveDirectoryTenant",
                "tenantId": "$ConnectedOrgTenantID",
                "displayName": "$CustomerDomain"
            }
            ],
            "state": "configured"
        }
"@
        try {
            $CreateConnectedOrgQuery= Invoke-RestMethod -Method POST -Uri $CreateConnectedOrgURI  -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateConnectedOrgBody -ErrorAction Stop    
            $Status="ConnectedCreatedOrg"
        }
        catch {
            $Status="Error"
            $statusmessage+=$Error[0]
        }
        
        $ConnectedOrgID=$CreateConnectedOrgQuery.id

        #Add internal Sponsors
        foreach ($internalSponsor in $internalSponsors) {
            #get user id
            $GetUserIDURI = $GraphURL+"/users/"+$internalSponsor
            $GetUserIDQuery = Invoke-RestMethod -Method GET -Uri $GetUserIDURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
            $userID=$GetUserIDQuery.id
            
            #add user
            $AddInternalSponsorURI = $GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations/"+$ConnectedOrgID+"/internalSponsors/"+"$"+"ref"
            $AddUserData= $GraphURL+"/users/"+$userID
            $AddInternalSponsorBody =@"
            {
                "@odata.id": "$AddUserData",
            }
"@ 
            $AddInternalSponsorQuery= Invoke-RestMethod -Method POST -Uri $AddInternalSponsorURI  -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $AddInternalSponsorBody
        }

        #Add External Sponsors
        $i=0
        foreach ($externalSponsor in $externalSponsors) {
            
            #find out if guest with email address exists
            Remove-Variable guestUserID -ErrorAction SilentlyContinue
            $GetGuestUserIDURI=$GraphURL+"/users?"+"$"+"filter=userType eq 'Guest' and mail eq '"+$externalSponsor+"'"
            $GetGuestUserIDQuery = Invoke-RestMethod -Method GET -Uri $GetGuestUserIDURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
            $GuestUserID=$GetGuestUserIDQuery.value.id

            if ($GuestUserID) {
                Remove-Variable AddUserData -ErrorAction SilentlyContinue
                $AddExternalSponsorURI = $GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations/"+$ConnectedOrgID+"/externalSponsors/"+"$"+"ref"
                $AddUserData= $GraphURL+"/users/"+$GuestUserID
                $AddExternalSponsorBody =@"
                {
                    "@odata.id": "$AddUserData"
                }
"@ 
                try {
                    $AddExternalSponsorQuery= Invoke-RestMethod -Method POST -Uri $AddExternalSponsorURI  -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $AddExternalSponsorBody -ErrorAction Stop
                    $i++
                }
                catch {
                    $statusmessage+="Error occured while adding external sponsor: $externalSponsor"
                }
            }else {
                #create Guest Invitation, the user can´t be added as external Sponsor before the invitation was redeemed
                $CreateGuestInvitationURI = $GraphURL+"/invitations"
                $CreateGuestInvitationBody =@"
                {
                    "invitedUserEmailAddress": "$externalSponsor",
                    "inviteRedirectUrl": "https://account.activedirectory.windowsazure.com/",
                    "sendInvitationMessage": true,
                    "invitedUserMessageInfo":{
                        "customizedMessageBody": "Moin! Hereinspaziert!"
                    }
                }
"@ 
                try {
                    $CreateGuestInvitationQuery = Invoke-RestMethod -Method POST -Uri $CreateGuestInvitationURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateGuestInvitationBody -ErrorAction Stop
                    $i++
                    $GuestInvitationInProgress

                }
                catch {
                    $statusmessage+=$Error[0]
                }
                
                #Write-Output $CreateGuestInvitationQuery
                $Status="Waiting for Guest Invitaton Redemption"
                $guestUsersInvited+=$externalSponsor
            }       
        $statusmessage+="Handled $i/$($ExternalSponsors.Count) Guest Users successfull"
        }
    }
}

$Output = New-Object psobject -Property @{
    Status=$Status
    StatusMessage=$statusmessage
    TenantID=$ConnectedOrgTenantID
    GuestUsersInvited=$guestUsersInvited
    ConnectedOrgID=$ConnectedOrgID
    IsM365Tenant=$IsM365Tenant
    }

write-output $Output | convertto-json