<#
.SYNOPSIS
Script to to reassign Access Package Assignments - ReAssignUsers.ps1

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        1.0
Creation Date:  2021/07/01

.DESCRIPTION
This script iterates through all Access Packages in the AAD and reassign them.
Run this script after changing access packages policies to let the assignments reflect the changes.
Use this script carefully, the script is build in the Microsoft Graph API BETA because V1.0 has not availlable all needed methods.

The script is using an App registration with App Authentication to process the assignments. The App Registration has to be created before.
The client id, tenant id and an App Secret have to be used in the function "Get-AppAuthCredentials"

The permissions which have to be definied and consented in the app registration are:
EntitlementManagement.ReadWrite.All
User.Read.All

.PARAMETER Mode
The mode "Report" can be used to collect report all Access Package Assignments. Use the Mode "Process" to report and  reassign the access packageassignments

.PARAMETER ReassignmentWithExpiration
If set to true the new assignment will have an expiration included. If set to false the new assignment will expire according the policiy settings

.PARAMETER MinAssignmentTime
This parameter should be filled when ReassignmentWithExpiration eq true. It will define the minimal assignment time which will be used for the reassignment.

.PARAMETER MaxAssignmentTime
This parameter should be filled when ReassignmentWithExpiration eq true. It will define the maximal assignment time which will be used for the reassignment.

.EXAMPLE
TBD
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$Mode="Report",
    [Parameter(Mandatory=$false)][string]$ReportPath="c:\temp\",
    [Parameter(Mandatory=$true)][bool]$ReAssignmentWithExpiration=$false,
    [Parameter(Mandatory=$false)][int]$MinAssignmentTime=130,
    [Parameter(Mandatory=$false)][int]$MaxAssignmentTime=170
)

#justification text for reassignment
$justificationText="Admin Assignment for a programatically reassignment"

#after how many minutes of processing the scrict should request a new token
$minutesToCreateANewToken=50
#used in the function Get-AppAuthCredentials to define the environment in which the token should be requested
$tokenEnvironment="DEVAPM"

#use this string var to filter the AP Policies which should be processed by a prefix
#$AccessPackagePolicySearchPhrasePrefix="AP-"

$resource = "https://graph.microsoft.com"
$GraphVersion = "/beta"
$GraphURL=$resource+$GraphVersion

#declare functional vars
$Errors=@()
$AccessPackagesToSkip=@()
$NonExistantUsers=@()
$ReportedAssignments=@()
$FailedReAssignments=@()

#This function requests an app token. Here we use the powershell secretmanagement module to store the credentials in a secured way
function Get-AppAuthCredentials{
    param (
        [Parameter(Mandatory=$false)][string]$Environment="PAT"
    )
    #Region Auth
    # Azure AD OAuth Application Token for Graph API
    # Get OAuth token for a AAD Application (returned as $token)

    # Application (client) ID, tenant ID and secret
    if ($Environment -eq "DEV" -OR !($Environment)) {
        $clientId = (Get-Secret "DEV-ReadEverything-AppID" -Vault Local -AsPlainText)
        $tenantId = (Get-Secret "DEV-ReadEverything-TenantID" -Vault Local -AsPlainText)
        $clientSecret = (Get-Secret "DEV-ReadEverything-AppSecret" -Vault Local -AsPlainText) 
    }elseif ($Environment -eq "DEVSPOPermissionReport"){
        $clientId = (Get-Secret "DEV-ReadEverything-AppID" -Vault Local -AsPlainText)
        $tenantId = (Get-Secret "DEV-ReadEverything-TenantID" -Vault Local -AsPlainText)
        $clientSecret = (Get-Secret "DEV-ReadEverything-AppSecret" -Vault Local -AsPlainText) 
    }elseif ($Environment -eq "DEVAPM"){
        $clientId = (Get-Secret "DEV-EntitlementManagement-AppID" -Vault Local -AsPlainText)
        $tenantId = (Get-Secret "DEV-EntitlementManagement-TenantID" -Vault Local -AsPlainText)
        $clientSecret = (Get-Secret "DEV-EntitlementManagement-AppSecret" -Vault Local -AsPlainText) 
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

#Request a token
$token=Get-AppAuthCredentials -Environment $tokenEnvironment
$tokenRequestTime=get-date

try {
    #Get Access Packages         
    $URIGetAccessPackages = $GraphURL+'/identityGovernance/entitlementManagement/accessPackages'
    $QUERYGetAccessPackages = Invoke-RestMethod -Method GET -Uri $URIGetAccessPackages -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction Stop
    
    $AllResults= @()
    $AllResults+=$QUERYGetAccessPackages.value
    $NextResults=$QUERYGetAccessPackages.'@odata.nextLink'
    while ($null -ne $NextResults) {
        $AdditionalResults = Invoke-RestMethod -Method GET -Uri $NextResults -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction STOP

        if ($NextResults){
            $NextResults = $AdditionalResults."@odata.nextLink"
            }
            $AllResults += $AdditionalResults.value
    }

    #Filter Access Packages
    $AccessPackages =$AllResults |where{!($AccessPackagesToSkip -contains $_.id) -AND $_.displayname -like ($AccessPackagePolicySearchPhrasePrefix+"*")}
}
catch {
    $ErrorOccured=$true
    Write-Host -ForegroundColor RED -Object "ERROR: Can't get a List of Access Packages"
}

#Iterate through Access Packages
foreach ($AccessPackage in $AccessPackages) {

    #request a new token when actualTokenRequestTime + $minutesToCreateANewToken is lower than now
    if ($tokenRequestTime) {
        $newTokenNeeded=(($tokenRequestTime).AddMinutes($minutesToCreateANewToken) -lt (get-date))
    }
    if(!($token) -OR $newTokenNeeded){
        $token=Get-AppAuthCredentials -Environment $tokenEnvironment
        $tokenRequestTime=get-date
    }

    write-host -ForegroundColor GRAY -Object "INFO: Processing $($AccessPackage.displayName)"
    #Get Policies
    #Filter by suffing while getting it from the grapoh isn't working for reasons
    #$URIGetAccessPackagePolicies = $GraphURL+'/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies?'+'$'+"filter=endsWith(displayName,'$($AccessPackagePolicySearchPhraseSuffix)') and accessPackageID eq '$($AccessPackage.ID)'"
    $URIGetAccessPackagePolicies = $GraphURL+'/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies?'+'$'+"filter=accessPackageID eq '$($AccessPackage.ID)'"
    $QUERYGetAccessPackagePolicies = Invoke-RestMethod -Method GET -Uri $URIGetAccessPackagePolicies -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction Stop
    #Filter Policies
    $AccessPackagePolicies =$QUERYGetAccessPackagePolicies.value <#|where{$_.displayname -like ("*"+$AccessPackagePolicySearchPhraseSuffix)}#>
    foreach ($AccessPackagePolicy in $AccessPackagePolicies) {
        #get Access Package Policy Assignments
        $URIGetAccessPackageAssignments = $GraphURL+'/identityGovernance/entitlementManagement/accessPackageAssignments?'+'$'+"filter=accessPackageAssignmentPolicy/id eq '$($AccessPackagePolicy.ID)' and assignmentState eq 'Delivered'&"+"$"+"expand=target,accessPackage"
        #$URIGetAccessPackageAssignments = $GraphURL+'/identityGovernance/entitlementManagement/accessPackageAssignments?'+'$'+"filter=assignmentState eq 'Delivered'&"+"$"+"expand=target,accessPackage"
        $QUERYGetAccessPackageAssignments = Invoke-RestMethod -Method GET -Uri $URIGetAccessPackageAssignments -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction Stop

        $AllResults= @()
        $AllResults+=$QUERYGetAccessPackageAssignments.value
        $NextResults=$QUERYGetAccessPackageAssignments.'@odata.nextLink'
        while ($null -ne $NextResults) {
            $AdditionalResults = Invoke-RestMethod -Method GET -Uri $NextResults -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction STOP

            if ($NextResults){
                $NextResults = $AdditionalResults."@odata.nextLink"
                }
                $AllResults += $AdditionalResults.value     
        }

        #Filter all results only for valid active assignments
        $AccessPackageAssignments=$AllResults |where {$_.assignmentState -eq 'Delivered'}

        #Filter all results only for assignments that will expire
        $AccessPackageAssignments=$AccessPackageAssignments |where {$_.schedule.expiration.type -ne 'noExpiration'}

        #TBD: Insert some filter here to identify not yet reassigned requests
        if ($Mode -eq 'Report') {
            foreach ($AccessPackageAssignment in $AccessPackageAssignments) {
                $ReportedAssignments+=$AccessPackageAssignment
            }
        }elseif ($Mode -eq'Process'){
            foreach ($AccessPackageAssignment in $AccessPackageAssignments) {
                #Remove Assignment
                try {
                    $URIRemoveAccessPackageAssignment = $GraphURL+'/identityGovernance/entitlementManagement/accessPackageAssignmentRequests'
                    $BODYRemoveAccessPackageAssignment=@"
                    {
                        "requestType": "AdminRemove",
                        "accessPackageAssignment":{
                            "ID": "$($AccessPackageAssignment.ID)"
                        }
                    }
"@
                    $QUERYRemoveAccessPackageAssignment = Invoke-RestMethod -Method POST -Uri $URIRemoveAccessPackageAssignment -Body $BODYRemoveAccessPackageAssignment -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction STOP    
                }
                catch {
                    Write-Host -ForegroundColor Yellow -Object "WARNING: An Error occured while removing the expiring Assignment with the ID $($AccessPackageAssignment.ID)"
                    #Continue
                }
                #Start-Sleep -Seconds 2
                #Re-Assign
                try {
                    if($NonExistantUsers -contains $AccessPackageAssignment.targetID){
                        #Skip this user because it is not valid anymore
                        continue
                    }else{
                        #Filter non existant / disabled users to be able to skip them in the reassignment
                        #Get User ID'S
                        $URIGetUserID = $GraphURL+'/users/'+$AccessPackageAssignment.targetID
                        $queryGetUserID = Invoke-RestMethod -Method GET -Uri $URIGetUserID -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token;} -ErrorAction Stop
                        if (!($queryGetUserID.accountEnabled)) {
                            Write-Host -ForegroundColor Yellow -Object "WARNING: User $($DataOwner.description) will be skipped because the account is disabled"
                            $NonExistantUsers+=$AccessPackageAssignment.targetID
                            Continue
                        }
                    }
    
                    $URICreateAccessPackageAssignmentRequest = $GraphURL+"/IdentityGovernance/entitlementManagement/accessPackageAssignmentRequests"
                    
                    $BODYCreateAccessPackageAssignmentRequest =@"
                    {
                        "requestType": "AdminAdd",
                        "requestState": "Delivered",
                        "isValidationOnly": false,
                        "justification": "$justificationText",
                        "accessPackageAssignment":{
                            "targetId": "$($AccessPackageAssignment.targetID)",
                            "assignmentPolicyId":"$($AccessPackageAssignment.assignmentPolicyId)",
                            "accessPackageId":"$($AccessPackageAssignment.AccessPackageID)"
                        }
"@
                    if($ReAssignmentWithExpiration){
                        $StartTime=Get-Date ((get-date).AddHours(0)) -UFormat '+%Y-%m-%dT%H:%M:%SZ' 
                        $EndTime=get-date ((get-date).AddDays((get-random -Minimum $MinAssignmentTime -Maximum $MaxAssignmentTime))) -UFormat '+%Y-%m-%dT%H:%M:%SZ'
                        $BODYCreateAccessPackageAssignmentRequest +=@"
                        ,
                        "schedule":{
                            "startDateTime": "$StartTime",
                            "expiration": {
                                "@odata.type": "microsoft.graph.expirationPattern",
                                "endDateTime": "$EndTime",
                                "type": "AfterDateTime"
                            }
                        }
"@
                    }
                    $BODYCreateAccessPackageAssignmentRequest +=@"
                    }
"@
                    $QUERYCreateAccessPackageAssignmentRequest = Invoke-WebRequest -Method POST -Uri $URICreateAccessPackageAssignmentRequest -Body $BODYCreateAccessPackageAssignmentRequest -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction STOP
                    Write-Host -ForegroundColor GRAY -Object "INFO: Successfully reassigned the expiring Assignment with the ID $($AccessPackageAssignment.ID)"
                }
                catch {
                    $FailedReAssignments+=$AccessPackageAssignment
                    Write-Host -ForegroundColor Yellow -Object "WARNING: An Error occured while reassigning the expiring Assignment with the ID $($AccessPackageAssignment.ID) `n $($Error[0])"
                }

            }
        }
    }
}

if ($Mode -eq 'Report'){
    $ReportedAssignments | select-object -Property @{label='AssignmentID';expression={$_.id}},@{label='ActualAssignmentEndDate';expression={$_.schedule.expiration.endDateTime}},@{label='TargetObjectID';expression={$_.target.objectid}},@{label='TargetEmail';expression={$_.target.email}},@{label='AccessPackageName';expression={$_.accessPackage.displayname}} |export-csv ($ReportPath+"ExpiringAssignments_"+(get-date -Format FileDateTimeUniversal)+".csv") -NoClobber -Delimiter ';' -Encoding utf8
}

$ERrors|Export-CSV -Path ("C:\temp\AssingingErrors"+(get-date -Format FileDateTime )+".csv") -NoTypeInformation -Delimiter ';' -Encoding utf8