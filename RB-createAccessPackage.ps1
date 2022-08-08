<#
.SYNOPSIS
Create an Azure Access Package including Catalog and Policies for a Team - RB-createAccessPackage.ps1

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        1.1
Creation Date:  2020/10/21

.DESCRIPTION
This script is part of a teams Governance Process.
LINK: http://blog.thinformatics.com/2020/09/another-microsoft-teams-governance-approach-using-aad-identity-governance/
In this Azure Automation Runbook a Access Package Catalog for a new Team. This Catalog is used in a new created Access Package to govern the membership´s based on policy's.
This script returns the Access Pack Link

.PARAMETER TeamName
The Name of the Team for which the Access Package should be build for. This Name is used to name the Access Package and it's components
.PARAMETER ConnectedOrgID
The ID of the Team for which the Access Package should be build for
.PARAMETER GuestInvitationsEnabled
If this value is true an additional access policy is build to allow external guest requests for the team
.PARAMETER ConnectedOrgId 
If a connected Org is named, the Guest Access Policy bound to that.

.EXAMPLE
This Script is part of a whole Governance Story and is not intended to run out of this process
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$TeamName,
    [Parameter(Mandatory=$true)][string]$TeamID,
    [Parameter(Mandatory=$true)][bool]$GuestInvitationsEnabled,
    [Parameter(Mandatory=$false)][string]$ConnectedOrgId    
)

$ClientID=Get-AutomationVariable -Name DelegatedAppClientID
$AppCreds=Get-AutomationPSCredential -Name DelegatedAppPermissions

# The resource URI
$resource = "https://graph.microsoft.com"
$GraphVersion = "/beta"
$GraphURL=$resource+$GraphVersion

#Naming Vars
$AccessPackagePrefix="AP-Teams-"
$AccessPackageCatalogPrefix="AP-Catalog-Teams-"
$AccessPackagePolicyPrefix="AP-Policy-Teams-"

#IDs of connected Partner Orgs (blutito.com & thinfabrics.com)
$PartnerOrgIDs="0966968d-e1f4-480c-9e50-e0bb42577208","e24fbbd5-45ce-4ca9-8a44-3e426506e554"


#Acess Policy Vars
$InternalPolicyAssignmentDuration="365"
#$InternalPolicyAccessReviewDuration="25"
#$InternalPolicyAccessReviewReoccurence="annual"
$PartnersPolicyAssignmentDuration="365"
#$ExternalPolicyAccessReviewDuration="25"
#$ExternalPolicyAccessReviewReoccurence="annual"
$ConnectedOrgPolicyAssignmentDuration="365"
#$ExternalPolicyAccessReviewDuration="25"
#$ExternalPolicyAccessReviewReoccurence="annual"
$OtherGuestsPolicyAssignmentDuration="180"
#$ExternalPolicyAccessReviewDuration="25"
#$ExternalPolicyAccessReviewReoccurence="annual"

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

#Access Package Catalog Creation
$CreateAccessPackageCatalogURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageCatalogs"
$CatalogDisplayName=$AccessPackageCatalogPrefix+$TeamName
$AccessPackageCatalogDescription="Access Package Catalog created as part of the Teams Provisioning Process"
$CreateAccessPackageCatalogBody =@"
{
    "displayName": "$CatalogDisplayName",
    "description": "$AccessPackageCatalogDescription",
    "isExternallyVisible": true,
    }
"@
$queryCreateAccessPackageCatalog = Invoke-RestMethod -Method POST -Uri $CreateAccessPackageCatalogURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackageCatalogBody
$AccessPackageCatalogID=$queryCreateAccessPackageCatalog.id

#Access Package Ressource linking
$CreateAccessPackageRessourceURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageResourceRequests"
$CreateAccessPackageRessourceBody =@"
{
    "catalogId": "$AccessPackageCatalogID",
    "requestType": "AdminAdd",
    "justification": "Automated addition in the teams deployment process",
    "accessPackageResource": {
        "originId": "$TeamID",
        "originSystem": "AadGroup",
        "resourceType": "O365 Group"
    }
    }
"@
$queryCreateAccessPackageRessource = Invoke-RestMethod -Method POST -Uri $CreateAccessPackageRessourceURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackageRessourceBody
$AccessPackageRessourceID=$queryCreateAccessPackageRessource.id

#Get ID of the new connected Access Package Ressource
$GetAccessPackageRessourcesURI = $GraphURL+"/identityGovernance/entitlementManagement/accessPackageCatalogs/"+$AccessPackageCatalogID+"/accessPackageResources"
$queryGetAccessPackageRessources = Invoke-RestMethod -Method GET -Uri $GetAccessPackageRessourcesURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
$RessourceID=$queryGetAccessPackageRessources.value.id

#Access Package creation
$CreateAccessPackageURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackages"
$AccessPackageDisplayName=$AccessPackagePrefix+$TeamName
$AccessPackageDescription="Access Package created as part of the Teams Provisioning Process"

$CreateAccessPackageBody =@"
{
    "catalogId": "$AccessPackageCatalogID",
    "displayName": "$AccessPackageDisplayName",
    "description": "$AccessPackageDescription",
    }
"@

$queryCreateAccessPackage = Invoke-RestMethod -Method POST -Uri $CreateAccessPackageURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackageBody
$AccessPackageID=$queryCreateAccessPackage.id

#get team owners to make them to the backup approver
$GetTeamOwnerURI = $GraphURL+"/groups/"+$TeamID+"/owners"
$GetTeamOwnersQuery = Invoke-RestMethod -Method Get -Uri $GetTeamOwnerURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
$TeamOwners=$GetTeamOwnersQuery.Value

#Access Package Policy

#internal users policy
$CreateAccessPackagePolicyURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageAssignmentPolicies"
$AccessPackagePolicyDisplayName=$AccessPackagePolicyPrefix+$TeamName+"-Internal"
$AccessPackagePolicyDescription="Access Package Policy created as part of the Teams Provisioning Process"
$AssignmentDuration=365

$CreateAccessPackagePolicyBody =@"
{
    "accessPackageId": "$AccessPackageID",
    "displayName": "$AccessPackagePolicyDisplayName",
    "description": "$AccessPackagePolicyDescription",
    "canExtend": "true",
    "durationInDays": "$AssignmentDuration",
    "requestorSettings": {
        "scopeType": "AllExistingDirectoryMemberUsers",
        "acceptRequests": true
    },
    "requestApprovalSettings": {
        "isApprovalRequired": true,
        "isApprovalRequiredForExtension": false,
        "isRequestorJustificationRequired": false,
        "approvalMode": "SingleStage",
        "approvalStages": [
            {
                "approvalStageTimeOutInDays": 14,
                "isApproverJustificationRequired": false,
                "isEscalationEnabled": false,
                "escalationTimeInMinutes": 0,
                "primaryApprovers": [
"@               
foreach ($owner in $TeamOwners){
    $CreateAccessPackagePolicyBody+=@"
    {
        "@odata.type": "#microsoft.graph.singleUser",
        "isBackup": false,
        "id": "$($owner.id)"
    },
"@
}
$CreateAccessPackagePolicyBody+= @"

                ]
            }
        ]
    },
    "accessReviewSettings": null
}
"@

$queryCreateAccessPackagePolicy= Invoke-RestMethod -Method POST -Uri $CreateAccessPackagePolicyURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackagePolicyBody

#partner orgs policy
$CreateAccessPackagePolicyURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageAssignmentPolicies"
$AccessPackagePolicyDisplayName=$AccessPackagePolicyPrefix+$TeamName+"-Partners"
$AccessPackagePolicyDescription="Access Package Policy created as part of the Teams Provisioning Process"
$AssignmentDuration=$PartnersPolicyAssignmentDuration

$CreateAccessPackagePolicyBody =@"
{
    "accessPackageId": "$AccessPackageID",
    "displayName": "$AccessPackagePolicyDisplayName",
    "description": "$AccessPackagePolicyDescription",
    "canExtend": "true",
    "durationInDays": "$AssignmentDuration",
    "requestorSettings": {
        "scopeType": "SpecificConnectedOrganizationSubjects",
        "acceptRequests": true,
        "allowedRequestors":[
"@               
            foreach ($PartnerOrg in $PartnerOrgIDs){
                $CreateAccessPackagePolicyBody+=@"
                {
                    "@odata.type": "#microsoft.graph.connectedOrganizationMembers",
                    "isBackup": false,
                    "id": "$PartnerOrg"
                },
"@
            }
            $CreateAccessPackagePolicyBody+= @"
            
        ]
    },
    "requestApprovalSettings": {
        "isApprovalRequired": true,
        "isApprovalRequiredForExtension": false,
        "isRequestorJustificationRequired": true,
        "approvalMode": "SingleStage",
        "approvalStages": [
            {
                "approvalStageTimeOutInDays": 14,
                "isApproverJustificationRequired": true,
                "isEscalationEnabled": false,
                "escalationTimeInMinutes": 0,
                "primaryApprovers": [
"@               
foreach ($owner in $TeamOwners){
    $CreateAccessPackagePolicyBody+=@"
    {
        "@odata.type": "#microsoft.graph.singleUser",
        "isBackup": false,
        "id": "$($owner.id)"
    },
"@
}
$CreateAccessPackagePolicyBody+= @"

                ]
            }
        ]
    },
    "accessReviewSettings": null
}
"@

$queryCreateAccessPackagePolicy= Invoke-RestMethod -Method POST -Uri $CreateAccessPackagePolicyURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackagePolicyBody


#external users policy
if ($ConnectedOrgId -and $GuestInvitationsEnabled) {

    $ConnectedOrgDetailsURI=$GraphURL+"/IdentityGovernance/entitlementManagement/connectedOrganizations/"+$ConnectedOrgID
    $queryConnectedOrgDetails= Invoke-RestMethod -Method GET -Uri $ConnectedOrgDetailsURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
    $ConnectedOrgDetails=$queryConnectedOrgDetails
    

    $CreateAccessPackagePolicyURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageAssignmentPolicies"
    $AccessPackagePolicyDisplayName=$AccessPackagePolicyPrefix+$TeamName+"-"+$ConnectedOrgDetails.displayName
    $AccessPackagePolicyDescription="Access Package Policy created as part of the Teams Provisioning Process"
    $AssignmentDuration=365

    #TBD: review settings for the approver, the owner of the team should be the fallback approver
    $CreateAccessPackagePolicyBody =@"
    {
        "accessPackageId": "$AccessPackageID",
        "displayName": "$AccessPackagePolicyDisplayName",
        "description": "$AccessPackagePolicyDescription",
        "canExtend": "true",
        "durationInDays": "$AssignmentDuration",
        "requestorSettings": {
            "scopeType": "SpecificConnectedOrganizationSubjects",
            "acceptRequests": true,
            "allowedRequestors": [
                {
                    "@odata.type": "#microsoft.graph.connectedOrganizationMembers",
                    "isBackup": false,
                    "id": "$ConnectedOrgId"
                }
            ]
        },
        "requestApprovalSettings": {
            "isApprovalRequired": true,
            "isApprovalRequiredForExtension": false,
            "isRequestorJustificationRequired": true,
            "approvalMode": "SingleStage",
            "approvalStages": [
                {
                    "approvalStageTimeOutInDays": 14,
                    "isApproverJustificationRequired": true,
                    "isEscalationEnabled": false,
                    "escalationTimeInMinutes": 0,
                    "primaryApprovers": [
"@               
    foreach ($owner in $TeamOwners){
        $CreateAccessPackagePolicyBody+=@"
        {
            "@odata.type": "#microsoft.graph.singleUser",
            "isBackup": true,
            "id": "$($owner.id)"
        },
"@
    }
    $CreateAccessPackagePolicyBody+= @"
                        {
                            "@odata.type": "#microsoft.graph.externalSponsors",
                            "isBackup": false
                        }
                    ]
                }
            ]
        },
        "accessReviewSettings": null
    }
"@

    $queryCreateAccessPackagePolicy= Invoke-RestMethod -Method POST -Uri $CreateAccessPackagePolicyURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackagePolicyBody
}

#regularguests access policy
#this policy is used if guests are allowed, but the requestor is not in the ConnectedOrg of the external partner
#If guests are now allowed, this policy is created, but not enabled
#get team owners to make them to the backup approver
$GetTeamOwnerURI = $GraphURL+"/groups/"+$TeamID+"/owners"
$GetTeamOwnersQuery = Invoke-RestMethod -Method Get -Uri $GetTeamOwnerURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
$TeamOwners=$GetTeamOwnersQuery.Value


$CreateAccessPackagePolicyURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageAssignmentPolicies"
$AccessPackagePolicyDisplayName=$AccessPackagePolicyPrefix+$TeamName+"-Guests"
$AccessPackagePolicyDescription="Access Package Policy created as part of the Teams Provisioning Process"
$AssignmentDuration=$OtherGuestsPolicyAssignmentDuration
#$ReviewDuration=30
#$reviewers="" #Insert the Owners of the Team here. #the reviewerType is Reviewers, this collection specifies the users who will be reviewers, either by ID or as members of a group, using a collection of singleUser and groupMembers.

$CreateAccessPackagePolicyBody =@"
{
    "accessPackageId": "$AccessPackageID",
    "displayName": "$AccessPackagePolicyDisplayName",
    "description": "$AccessPackagePolicyDescription",
    "canExtend": "true",
    "durationInDays": "$AssignmentDuration",
    "requestorSettings": {
        "scopeType": "AllExternalSubjects",
        "acceptRequests": "$GuestInvitationsEnabled"
    },
    "requestApprovalSettings": {
        "isApprovalRequired": true,
        "isApprovalRequiredForExtension": false,
        "isRequestorJustificationRequired": true,
        "approvalMode": "SingleStage",
        "approvalStages": [
            {
                "approvalStageTimeOutInDays": 14,
                "isApproverJustificationRequired": true,
                "isEscalationEnabled": false,
                "escalationTimeInMinutes": 0,
                "primaryApprovers": [
"@               
foreach ($owner in $TeamOwners){
    $CreateAccessPackagePolicyBody+=@"
    {
        "@odata.type": "#microsoft.graph.singleUser",
        "isBackup": false,
        "id": "$($owner.id)"
    },
"@
}
$CreateAccessPackagePolicyBody+= @"

                ]
            }
        ]
    },
    "accessReviewSettings": null
}
"@

$queryCreateAccessPackagePolicy= Invoke-RestMethod -Method POST -Uri $CreateAccessPackagePolicyURI -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackagePolicyBody



#Ressource Role Scope (here: which Teams)
$CreateAccessPackageRessourceRoleScopeURI = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackages/"+$AccessPackageID+"/accessPackageResourceRoleScopes"

$originID="Member_"+$TeamID

$CreateAccessPackageResourceRoleScopeBody=@"
{
    "accessPackageResourceRole": {
        "displayName": "Member",
        "description": "anythint",
        "originSystem": "AadGroup",
        "originId": "$OriginID",
        "accessPackageResource": {
            "id": "$RessourceID",
            "originSystem": "AadGroup"
        }
    },
    "accessPackageResourceScope": {
        "originId": "$TeamID",
        "originSystem": "AadGroup"
    }
}
"@

$queryCreateAccessPackagePolicy= Invoke-RestMethod -Method POST -Uri $CreateAccessPackageRessourceRoleScopeURI  -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization } -Body $CreateAccessPackageResourceRoleScopeBody

$getTenantDefaultDomainURI="https://graph.microsoft.com/v1.0/organization"
$getTenantDefaultDomainQuery=Invoke-RestMethod -Method Get -Uri $getTenantDefaultDomainURI  -ContentType "application/json; charset=utf-8" -Headers @{Authorization = $AuthToken.Authorization }
$verifieddomains=$getTenantDefaultDomainQuery.value.verifieddomains
$initialdomain=($verifieddomains | where {$_.isInitial -eq $true}).name

$output = @()
$line =  New-Object psobject
$line | add-member -Membertype NoteProperty -Name AccessPackageID -value $AccessPackageID
$line | add-member -Membertype NoteProperty -Name AccessPackageURI -value ("https://myaccess.microsoft.com/@"+$initialdomain+"#/access-packages/"+$AccessPackageID)
$output+=$line

write-output $output | convertto-json