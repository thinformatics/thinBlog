# This script will collect all Teams Users and identify direct Teams Policy Assignments. 
# The intention is to review and clear the direct assignments to have a clear and expactable situation within your Teams environment

#Available Policy Types:
#"TeamsAppPermissisonPolicy", "TeamsAppSetupPolicy", "TeamsCallingPolicy", "TeamsChannelsPolicy", "TeamsMeetingBroadCastPoliicy", "TeamsMeetingPolicy", "TeamsMessagingPolicy", "TeamsUpdateManagementPolicy", "TeamsUpgradePolicy"

#Fill this Var with all Policy Types you want to identify explicit assignments
$HandleThisPolicyTypes="TeamsAppSetupPolicy","TeamsCallingPolicy", "TeamsMeetingBroadcastPolicy", "TeamsMeetingPolicy", "TeamsMessagingPolicy"

Connect-MicrosoftTeams
$users=get-csonlineUser

$AllAssignedpolicies=@()
foreach($user in $users){
    $assignedPolicies=get-csuserpolicyassignment -identity $user.identity
    $hash=@{
        "User"= $user
        "AssignedPolicies"= $assignedpolicies
    }
    $AllAssignedpolicies+=New-Object PSObject -Property $hash
}
$DirectAssignments=@()

foreach($Assignment in $AllAssignedpolicies){
    $CheckTheseForDirectAssignments=$Assignment.AssignedPolicies |where {$handleThisPolicyTypes -eq $_.PolicyType}
    if($CheckTheseForDirectAssignments.PolicySource.AssignmentType -contains 'Direct' ){
        $DirectAssignments+=$Assignment
    }
}

#List results e.g. by with he following cmdlets
$DirectAssignments.User.userprincipalname

#List direct assignments for an identified user:
$userPrincipalName="UserAlias@YourDomain.com"
($DirectAssignments | where {$_.User.UserprincipalName -eq $userPrincipalName}).AssignedPolicies.PolicySource |where {$_.AssignmentType -eq 'Direct'}



