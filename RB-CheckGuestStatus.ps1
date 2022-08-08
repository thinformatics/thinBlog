<#
.SYNOPSIS
Guest User Status Check - RB-CheckGuestStatus.ps1

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        1.0
Creation Date:  2020/09/21

.DESCRIPTION
This script is part of a teams Governance Process.
LINK: http://blog.thinformatics.com/2020/09/another-microsoft-teams-governance-approach-using-aad-identity-governance/
In this Azure Automation Runbook one or more given identitys will be checked for their status.
Every given user (Paramter $GuestsToCheck) is checked if the it's Status equals "Accepted". If not the userid will be returned. If the status equals Accepted the given user is added to a connected organization (Parameter ConnectedOrgID) as an external Sponsor.

.PARAMETER GuestsToCheck
Array of Guests which should be checked and added to the Connected Organization
.PARAMETER ConnectedOrgID
The ID of the Connected Organization where 

.EXAMPLE
This Script is part of a whole Governance Story and is not intended to run out of this process
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string[]]$GuestsToCheck,
    [Parameter(Mandatory=$true)][string]$ConnectedOrgID
)

#Automation Variables for automated authentication
$ClientID=Get-AutomationVariable -Name DelegatedAppClientID
$AppCreds=Get-AutomationPSCredential -Name DelegatedAppPermissions

# The resource URI
$resource = "https://graph.microsoft.com"
$GraphVersion = "/beta"
$GraphURL=$resource+$GraphVersion

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
$output=@()
$PendingAcceptance=@()

#loop through all given Guest Accounts
foreach($guest in $GuestsToCheck){
    $GetGuestUserIDURI=$GraphURL+"/users?"+"$"+"filter=userType eq 'Guest' and mail eq '"+$guest+"'"
    $GetGuestUserIDQuery = Invoke-RestMethod -Method GET -Uri $GetGuestUserIDURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
    $GuestUserValues=$GetGuestUserIDQuery.value
    $GuestUserisFunctional=$true

    if ($GuestUserValues.externalUserState -eq "Accepted") {
        #"externalUserState": "PendingAcceptance", is the initial state
        
        $CheckIfUserIsAlreadyASponsorURI = $GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations/"+$ConnectedOrgID+"/externalSponsors/"+$GuestUserValues.ID
        try {
            #Check if the user is already a member of this connected Org
            $CheckIfUserIsAlreadyASponsorQuery = Invoke-RestMethod -Method GET -Uri $CheckIfUserIsAlreadyASponsorURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -ErrorAction Stop
        }
        catch {
            # add user as external sponsor to the connected org
            $AddExternalSponsorURI = $GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations/"+$ConnectedOrgID+"/externalSponsors/"+"$"+"ref"
            $AddUserData= $GraphURL+"/users/"+$GuestUserValues.ID
            $AddExternalSponsorBody =@"
            {
                "@odata.id": "$AddUserData"
            }
"@ 
            try {
                $AddExternalSponsorQuery= Invoke-RestMethod -Method POST -Uri $AddExternalSponsorURI  -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $AddExternalSponsorBody -ErrorAction Stop
            }
            catch {
                $statusmessage+="Error occured while adding external sponsor: $externalSponsor"
                $PendingAcceptance+=$guest
            }
        }
    }else {
        #Store pending entries in the outpur Var
        $PendingAcceptance+=$guest
    }
     $line =  New-Object psobject
     $line | add-member -Membertype NoteProperty -Name GuestUser -value $guest
     $line | add-member -Membertype NoteProperty -Name GuestUserIsFunctional -value $GuestUserisFunctional
     $line | add-member -Membertype NoteProperty -Name GuestUserStatus -value $GuestUserValues.externalUserState
     $output+=$line
 }

#Generate readable Output 
 write-output $PendingAcceptance |ConvertTo-Json
