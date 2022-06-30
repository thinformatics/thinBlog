$AZResourceGroupName='JSF_Automation'
$AAName="TeamsOperationTasks"
$AALocation='germanywestcentral'
$AZKeyVaultName='OperationSecrets'
$AZSubscriptionID='c221eb8c-453d-480b-a809-d1ad3d853e2a'
$AZTenantID='763aefea-a45b-49f4-a4a4-30d135e944f5'

connect-azaccount -SubscriptionId $AZSubscriptionID -Tenant $AZTenantID
#create Automation Account with a System assigned managed identity
$AutomationAccount=New-AzAutomationAccount -Name $AAName -ResourceGroupName $AZResourceGroupName -Location $AALocation -AssignSystemIdentity
#install Teams Module (KeyVault Module is already there per default)
New-AzAutomationModule -Name "MicrosoftTeams" -ResourceGroupName $AZResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ContentLinkUri "https://www.powershellgallery.com/api/v2/package/MicrosoftTeams/4.5.0"

#create Key Vault
$KeyVault=New-AzKeyVault -Name $AZKeyVaultName -ResourceGroupName $AZResourceGroupName -Location $AALocation 
#did not found a cmdlet in the AZ Module for switching the KV Permission Model to RBAC, made this manually.
#Afterwards, i've also granted Key Vault Administrator Permissions to my account.

#Create Secrets 
$secret1=Set-AzKeyVaultSecret -Name "RB-AssignTeamsPolicies-TenantID" -VaultName $KeyVault.VaultName -SecretValue (ConvertTo-SecureString $AZTenantID -AsPlainText -Force)
$secret2=Set-AzKeyVaultSecret -Name "RB-AssignTeamsPolicies-AppID" -Vault $KeyVault.VaultName -SecretValue (ConvertTo-SecureString "*SANIZIZED*" -AsPlainText -Force) #we've creted this before with postman, check the screenshots
$secret3=Set-AzKeyVaultSecret -Name "RB-AssignTeamsPolicies-AppSecret" -Vault $KeyVault.VaultName -SecretValue (ConvertTo-SecureString "*SANIZIZED*"  -AsPlainText -Force)#we've creted this before with postman, check the screenshots
$secret4=Set-AzKeyVaultSecret -Name "RB-AssignTeamsPoliciest-UserUPN" -Vault $KeyVault.VaultName -SecretValue (ConvertTo-SecureString "*SANIZIZED*@jsflab.com" -AsPlainText -Force)
$secret5=Set-AzKeyVaultSecret -Name "RB-AssignTeamsPolicies-UserPW" -Vault $KeyVault.VaultName -SecretValue (ConvertTo-SecureString "*SANIZIZED*" -AsPlainText -Force)

#Allow AA to read secrets by assigning Permissions to the managed identity of the account
$SecretPath="/subscriptions/$($AZSubscriptionID)/resourceGroups/$($AZResourceGroupName)/providers/Microsoft.KeyVault/vaults/$($KeyVault.VaultName)/secrets/"
New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -Scope ($SecretPath+$($secret1.name)) -RoleDefinitionName "Key Vault Secrets User"
New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -Scope ($SecretPath+$($secret2.name)) -RoleDefinitionName "Key Vault Secrets User"
New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -Scope ($SecretPath+$($secret3.name)) -RoleDefinitionName "Key Vault Secrets User"
New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -Scope ($SecretPath+$($secret4.name)) -RoleDefinitionName "Key Vault Secrets User"
New-AzRoleAssignment -ObjectId $AutomationAccount.Identity.PrincipalId -Scope ($SecretPath+$($secret5.name)) -RoleDefinitionName "Key Vault Secrets User"