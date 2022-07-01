<#
.SYNOPSIS
To assign policies - that do not support group based assignments - to members of groups

.NOTES
Author:         Jakob Schaefer, thinformatics AG
Version:        1.0
Creation Date:  2022/06/30

.DESCRIPTION
...

.EXAMPLE
...
#>
#Vars to fill with Azure Resource Names
$KeyVaultName="OperationSecrets"
#The Names of the secrets stored in the Azure Key Vault
$SecretNameAppID="RB-AssignTeamsPolicies-AppID"
$SecretNameTenantID="RB-AssignTeamsPolicies-TenantID"
$SecretNameAppSecret="RB-AssignTeamsPolicies-AppSecret"
$SecretNameDelegatedUserName="RB-AssignTeamsPolicies-UserUPN"
$SecretNameDelegatedUserPassword="RB-AssignTeamsPolicies-UserPW"

#Hastable of all policies and their targets. Change the Name (App permission policy name) 
#and Target (ObjectID of the group where all members should receive this policy )
$PoliciesToAssign=@()
$hash =  @{
    Type = 'AppPermission'
    Command = 'Grant-CsTeamsAppPermissionPolicy'
    Name = 'Custom-FirstParty'
    Target = '80d4c83a-5209-4d29-8bbc-c9b470e232a7' #'ObjectID of the Group "RegularUsers"'
}
$PoliciesToAssign+= New-Object PSObject -Property $hash
$hash =  @{
    Type = 'AppPermission'
    Command = 'Grant-CsTeamsAppPermissionPolicy'
    Name = 'Custom-AllowAll'
    Target = '564b1869-68b4-4d23-8adb-692270ac7ebe' #'ObjectID of the Group "HighPrivilegedAccounts"'
}
$PoliciesToAssign+= New-Object PSObject -Property $hash
$hash =  @{
    Type = 'AppPermission'
    Command = 'Grant-CsTeamsAppPermissionPolicy'
    Name = 'Custom-SpecificApps'
    Target = 'a42de85c-7b10-4174-9f87-b6486c5fd4ec' #'ObjectID of the Group "RegulatedAccounts'"'
}
$PoliciesToAssign+= New-Object PSObject -Property $hash
#just add or remove hashes if you need to assign more ore less policies&/groups

#How many users to handle in one assignment batch job
$UsersCountInBatchAssignment=4900 #https://docs.microsoft.com/en-us/powershell/module/teams/new-csbatchpolicyassignmentoperation?view=teams-ps#description

#conntect to Azure Key Vault by using the AA Managed Identity to receive secrets
connect-AZAccount -Identity

$secretValueAppIDEncyrypted=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameAppID).SecretValue
$secretValueDelegatedUserNameEncyrypted=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameDelegatedUserName).SecretValue
$secretValueDelegatedUserPasswordEncyrypted=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameDelegatedUserPassword).SecretValue
$secretValueTenantIDEncrypted=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameTenantID).SecretValue
$secretValueAppSecretEncrypted=(Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretNameAppSecret).SecretValue

#SecureString to PlainText for AppID
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretValueAppIDEncyrypted)
$secretValueAppID = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#SecureString to PlainText for UserName
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretValueDelegatedUserNameEncyrypted)
$secretValueDelegatedUserName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#SecureString to PlainText for UserPassword
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretValueDelegatedUserPasswordEncyrypted)
$secretValueDelegatedUserPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#SecureString to PlainText for TenantID
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretValueTenantIDEncrypted)
$secretValueTenantID = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#SecureString to PlainText for AppSecret
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretValueAppSecretEncrypted)
$secretValueAppSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

#function to receive a token for authentication against the graph   
function Get-AppAuthCredentials{
    #Region Auth
        
    $clientId = $secretValueAppID
    $tenantId = $secretValueTenantID
    $clientSecret = $secretValueAppSecret  

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
}

#function to connect against the Teams API. This function recycle the example MSFT provided in the doc article:
#https://docs.microsoft.com/en-us/powershell/module/teams/connect-microsoftteams?view=teams-ps#example-4-connect-to-microsoftteams-using-accesstokens
function connect-TeamsSession{
        $tenantid = $secretValueTenantID
        $clientid = $secretValueAppID 
        $clientsecret = $secretValueAppSecret
        $username = $secretValueDelegatedUserName
        $password = $secretValueDelegatedUserPassword
    
        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $tenantid
        $body = "client_id={0}&scope=https://graph.microsoft.com/.default&username={1}&password={2}&grant_type=password&client_secret={3}" -f $clientid, $username, [System.Net.WebUtility]::UrlEncode($password), [System.Net.WebUtility]::UrlEncode($clientsecret)
        $graphtoken = Invoke-RestMethod $uri -Body $body -Method Post -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue | Select-object -ExpandProperty access_token
    
        $uri = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" -f $tenantid
        $body = "client_id={0}&scope=48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default&username={1}&password={2}&grant_type=password&client_secret={3}" -f $clientid, $username, [System.Net.WebUtility]::UrlEncode($password), [System.Net.WebUtility]::UrlEncode($clientsecret)
        $teamstoken = Invoke-RestMethod $uri -Body $body -Method Post -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue | Select-object -ExpandProperty access_token
    
        Connect-MicrosoftTeams -AccessTokens @($graphtoken, $teamstoken)
}


# The resource URI for connecting to Graph,
$resource = "https://graph.microsoft.com"
$GraphVersion = "/v1.0"
$GraphURL=$resource+$GraphVersion

#Region Auth
#request a token for Graph
$token=Get-AppAuthCredentials
#EndRegion Auth

foreach ($PolicySetup in $PoliciesToAssign){
    write-output "Processing GroupMembers of GroupID $($PolicySetup.Target)"
    #Region List GroupMembers
    #Receives all members of the group
    $URIGetGroupMembers=$GraphURL+"/groups/"+$($PolicySetup.Target)+"/members?$"+"select=id"
    $REQUESTGroupMembers=Invoke-RestMethod -Method GET -ContentType "application/json; charset=utf-8" -Headers @{Authorization="Bearer $token"; ConsistencyLevel="eventual"} -Uri $URIGetGroupMembers

    $AllGroupMembers= @()
    $AllGroupMembers+=$REQUESTGroupMembers.value

    $NextResults=$REQUESTGroupMembers.'@odata.nextLink'
    while ($null -ne $NextResults) {
        $AdditionalResults = Invoke-RestMethod -Method GET -Uri $NextResults -ContentType "application/json; charset=utf-8" -Headers @{Authorization = "Bearer "+$token} -ErrorAction STOP

        if ($NextResults){
            $NextResults = $AdditionalResults."@odata.nextLink"
            }
            $AllGroupMembers += $AdditionalResults.value     
    }
    #EndRegion List GroupMembers
    #Region Policy Assignment
    #Automated Connect to the Teams/Skype API configured in the functions
    
    connect-TeamsSession 
    $Count=0
    $BatchOperations=@()
        
    while($AllGroupMembers.count -gt $count){
        try{
            #build an assignmentjob for X users. X is defined by the var $UsersCountInBatchAssignment
            $BatchOperations+=new-csBAtchPolicyAssignmentOperation -PolicyType TeamsAppPermissionPolicy -PolicyName $PolicySetup.Name -Identity $($AllGroupMembers[$count..($count+$UsersCountInBatchAssignment)].id) -OperationName "Batch assignment $($PolicySetup.Name)" -ErrorAction Stop
            write-output "Successfully started assignment of Policy $($PolicySetup.Name) to user $count to $($count+$UsersCountInBatchAssignment). The Job ID is $($Batchoperations[-1].operationid)"
            $count=$count+$UsersCountInBatchAssignment
        }catch{
            write-output "Error creating batch assignment of Policy $($PolicySetup.Name) to user $count to $($count+$UsersCountInBatchAssignment)"
        } 
    }

    #EndRegion Policy Assignment
    disconnect-MicrosoftTeams

}
