#Path to the csv which contains the user mappings, generated with the scriptcreate-pstimportCSV.ps1
$PSTImportMappingTableReport="C:\git\thinBlog\pst ex import\PSTImportMappingTableReport.csv"
#Path to the root folder which contains the xml files that contain the source mailbox config
$reportbasepath="C:\git\thinBlog\pst ex import\Export\"
#Path to a new Folder which will be used to store transcripts for the reapplying of settings
$TransscriptPath="C:\git\thinBlog\pst ex import\ReapplyTranscripts\"

#Region Functions
function reapply-mailboxRegionalSettings{
    param(
        $MailboxIdentity,
        $reportIdentifier
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxRegionalConfigurationFilePath=($reportbasepath+$reportIdentifier+"\MBXRegionalConfiguration_"+$reportIdentifier+".xml")

    try {
        $MbxRegionalConfigurationReport=Import-Clixml -Path $ExportMbxRegionalConfigurationFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid XML File for mailbox $([string]$mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxPermissionFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
        continue
    }
    
    #default settings which were applied when no language was defined
    if(!([string]$MbxRegionalConfigurationReport.Language)){
        [string]$MbxRegionalConfigurationReport.Language = "de-de"
    }
    if(!([string]$MbxRegionalConfigurationReport.Timeformat)){
        [string]$MbxRegionalConfigurationReport.Timeformat = "HH:mm"
    }
    if(!([string]$MbxRegionalConfigurationReport.dateformat)){
        [string]$MbxRegionalConfigurationReport.dateformat = "dd.MM.yyyy"
    }
    if(!([string]$MbxRegionalConfigurationReport.Timezone)){
        [string]$MbxRegionalConfigurationReport.Timezone = "W. Europe Standard Time"
    }
    try{
        #if a invalid language & time/dateformat is set an error occures. To avoid errors i set the dateformat to a specifig which is valid for most combinations
        get-mailbox ([string]$mbx.userprincipalname) | set-mailboxregionalconfiguration -Dateformat "yyyy-MM-dd" -Timeformat "HH:mm"
        #now i will reapply the original or default values
        get-mailbox ([string]$mbx.userprincipalname) | set-mailboxregionalconfiguration -Language ([string]$MbxRegionalConfigurationReport.Language) -Dateformat ([string]$MbxRegionalConfigurationReport.dateformat) -timezone ([string]$MbxRegionalConfigurationReport.timezone) -Timeformat ([string]$MbxRegionalConfigurationReport.Timeformat) -ErrorAction Stop | out-null
    }catch{
        Write-Host -ForegroundColor Red -Object "ERROR: error occured while applying mailbox regional settings for $([string]$mbx.primarysmtpaddress)"
        $Global:InModuleErrorOccured=$true
    }
}
function reapply-fullAccessPermissions{
    param(
        $MailboxIdentity,
        $reportIdentifier
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    
    $ExportMbxPermissionFilePath=($reportbasepath+$reportIdentifier+"\MailboxPermission_"+$reportIdentifier+".xml")

    try {
        $FullAccessPermissionReport=Import-Clixml -Path $ExportMbxPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid XML File for mailbox $([string]$mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxPermissionFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
    }

    foreach($PermissionEntry in $FullAccessPermissionReport){ 
        if (([string]$PermissionEntry.User) -notlike "*@*") {
            Write-Host -ForegroundColor Yellow -Object "Warning: Full Acess Permission for User will not be re-applied, because it's orphaned: $([string]$assignedentry.SamAccountName)"
            #this entry will be skipped
            continue
        }
        
        try{
            $NewPermissionObject=($MappingTable | where{$_.SourceUserPrincipalName -eq $PermissionEntry.User}).DestinationUserPrincipalName
            if(!$NewPermissionObject){
                continue
            }else{
                $assignedentry=get-mailbox -identity $NewPermissionObject -ErrorAction Stop
            }
        }catch{
            #No Mailbox found
        }

        try {
            add-mailboxpermission -identity ([string]$mbx.Identity) -User $assignedentry.UserPrincipalName -AccessRights FullAccess -Erroraction Stop -WarningAction SilentlyContinue |out-null
        }
        catch {
            Write-Host -ForegroundColor Red -Object "ERROR: Can't reapply permission for user with $($assignedentry.UserPrincipalName), please check if there is a valid AzureAD Counterpart defined in the mapping table"
            $Global:InModuleErrorOccured=$true
        }
    }
    
}
function reapply-MailboxForwardingSettings{
    param(
        $MailboxIdentity,
        $reportIdentifier
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxSettingsFilePath=($reportbasepath+$reportIdentifier+"\MBXSettings_"+$reportIdentifier+".xml")

    try {
        $MbxSettingsFWReport=Import-Clixml -Path $ExportMbxSettingsFilePath -ErrorAction Stop
    }catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid XML File for mailbox $($mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSettingsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
    }

    if ($MbxSettingsFWReport.DeliverToMailboxAndForward -OR $MbxSettingsFWReport.ForwardingAddress) {
        Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was enabled for the mailbox and will be re-applied."

        try {
            $NewForwardingRecipient = get-recipient $MbxSettingsFWReport.ForwardingAddress -ErrorAction Stop
            set-mailbox ([string]$mbx.Identity) -DelivertoMailboxAndForward $MbxSettingsFWReport.DeliverToMailboxAndForward -ForwardingAddress $NewForwardingRecipient.PrimarySmtpAddress -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid recipient in this environment who can be identified by the forwarding-entry: $($ForwardingEntry)"
            $Global:InModuleErrorOccured=$true
        }
             
    }else {
        Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was not enabled for the mailbox."
    }
}
function reapply-MailboxMessageCopyConfiguration{
    param(
        $MailboxIdentity,
        $reportIdentifier
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxSettingsFilePath=($reportbasepath+$reportIdentifier+"\MBXSettings_"+$reportIdentifier+".xml")

    try {
        $MbxSettingsMessageCopy=Import-Clixml -Path $ExportMbxSettingsFilePath -ErrorAction Stop
    }catch{
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid XML File for mailbox $($mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSettingsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
    }

    if ($MbxSettingsMessageCopy.MessageCopyForSentAsEnabled ) {
        Write-Host -ForegroundColor Gray -Object "INFO: Message Copy for Send As was enabled for the mailbox and will be re-applied."

        try {
            set-mailbox ([string]$mbx.Identity) -MessageCopyForSentAsEnabled $true -ErrorAction Stop -WarningAction SilentlyContinue | out-null
        }
        catch {
            Write-Host -ForegroundColor Red -Object "ERROR: Can't reapply MessageCopyForSentAsEnabled to $([string]$assignedentry.samaccountname)"  
            $Global:InModuleErrorOccured=$true
        }     
    }else {
        #Not woth a notification... Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was not enabled for the mailbox."
    }
    if ($MbxSettingsMessageCopy.MessageCopyForSendOnBehalfEnabled ) {
        Write-Host -ForegroundColor Gray -Object "INFO: Message Copy for Send on Behalf was enabled for the mailbox and will be re-applied."

        try {
            set-mailbox ([string]$mbx.Identity) -MessageCopyForSendOnBehalfEnabled $true -ErrorAction Stop -WarningAction SilentlyContinue | out-null
        }
        catch {
            Write-Host -ForegroundColor Red -Object "ERROR: Can't reapply MessageCopyForSendOnBehalfEnabled to $([string]$assignedentry.samaccountname)"  
            $Global:InModuleErrorOccured=$true
        }     
    }else {
        #Not woth a notification Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was not enabled for the mailbox."
    }
}
function reapply-sendaspermissions{
    param(
        $MailboxIdentity,
        $reportIdentifier
        #$OUSearchBase="OU=Hamburg,DC=ucc,DC=academy"
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportRecipientPermissionFilePath=($reportbasepath+$reportIdentifier+"\MBXRecipientPermissions_"+$reportIdentifier+".xml")

    try {
        $SendAsReport=Import-Clixml -Path $ExportRecipientPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid XML File for mailbox $([string]$mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSendAsPermissionsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
        #error info: can�t find valid xml 
        #and skip
    }

    foreach($PermissionEntry in $SendAsReport){
            if (([string]$PermissionEntry.Trustee) -like "NT AUTHORITY\SELF") {
                #Write-Host -ForegroundColor Yellow -Object "Warning: Send As Permission for User will not be re-applied, because it's orphaned: $([string]$assignedentry.SamAccountName)"
                #this entry will be skipped
                continue
            }

                $NewPermissionObject=($MappingTable | where{$_.SourceUserPrincipalName -eq $PermissionEntry.Trustee}).DestinationUserPrincipalName
                $assignedentry=get-mailbox $NewPermissionObject -ErrorAction Stop
                Write-Host -ForegroundColor Gray -Object "INFO: Send As Permission for User will be re-applied: $([string]$assignedentry.SamAccountName)"
                
                try {
                    add-recipientpermission ([string]$mbx.Identity) -Trustee $assignedentry.userprincipalname -AccessRights SendAs -ErrorAction Stop -WarningAction SilentlyContinue -confirm:$False | out-null
                }
                catch {
                    Write-Host -ForegroundColor Red -Object "ERROR: Can't reapply permission for user with SAMAccountName $([string]$assignedentry.SamAccountName), please check if there is a valid AzureAD Counterpart"  
                    $Global:InModuleErrorOccured=$true
                }
            
        }

}
#ENDRegion Functions

$MappingTable=import-csv -Path $PSTImportMappingTableReport -Delimiter ';'

#Connect to the destination environment
connect-exchangeonline -showBanner:$false

$namedexomailboxes=@()
$allexomailboxes=Get-Mailbox -resultsize unlimited
$CSV=Import-Csv -Path $PSTImportMappingTableReport -Delimiter ';'

foreach($entry in $csv){
    try{
        $destinationMailbox= $allexomailboxes | Where-Object {[string]$_.PrimarySmtpAddress -like [string]$entry.DestinationUserPrincipalName} -ErrorAction Stop

        Start-Transcript -Path ($TransscriptPath+"ReApplyTranscript_"+[string]$entry.DestinationUserPrincipalName+".txt")
        $ReapplyErrors=0
        $Global:InModuleErrorOccured=$false
        $ReapplyErrorDetails=@()
        Write-Host -ForegroundColor Gray -Object "INFO: START PostProcessing for User $([string]$entry.DestinationUserPrincipalName)"
        
        #Mailbox FullAccess Permissions
        try {
            write-host -ForegroundColor Gray -Object "INFO: START Task (1/5) for User $($entry.DestinationUserPrincipalName) - ReApply FullAccess Permissions"
            reapply-fullaccessPermissions -MailboxIdentity $entry.DestinationUserPrincipalName -reportIdentifier $entry.SourceUserPrincipalName -ErrorAction Stop
            Write-Host -ForegroundColor Gray -Object "INFO: END Task (1/5) for User $($entry.DestinationUserPrincipalName) - ReApply FullAccess Permissions"  
        }
        catch {
            $ReapplyErrors++
            Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying FullAccess permissions for Groups"
            Write-Host -ForegroundColor Red -Object $error[0]
        }

        #Mailbox Regional Settings
        try {
            write-host -ForegroundColor Gray -Object "INFO: START Task (2/5) for User $($entry.DestinationUserPrincipalName) - ReApply Mailbox Regional Settings"
            reapply-mailboxregionalsettings -MailboxIdentity $entry.DestinationUserPrincipalName -reportIdentifier $entry.SourceUserPrincipalName -ErrorAction Stop
            write-host -ForegroundColor Gray -Object "INFO: END Task (2/5) for User $($entry.DestinationUserPrincipalName) - ReApply Mailbox Regional Settings"
        }
        catch {
            $ReapplyErrors++
            Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying mailbox regional configuration"
            Write-Host -ForegroundColor Red -Object $error[0]
            
        }
        #Forwarding
        try {
            write-host -ForegroundColor Gray -Object "INFO: START Task (3/5) for User $($entry.DestinationUserPrincipalName) - ReApply Forwarding Settings"
            reapply-MailboxForwardingSettings -MailboxIdentity $entry.DestinationUserPrincipalName -reportIdentifier $entry.SourceUserPrincipalName -ErrorAction Stop
            write-host -ForegroundColor Gray -Object "INFO: END Task (3/5) for User $($entry.DestinationUserPrincipalName) - ReApply Forwarding Settings"
        }
        catch {
            $ReapplyErrors++
            Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying forwarding settings"
            Write-Host -ForegroundColor Red -Object $error[0]   
        }
        #Message Copy (SendAs & SendOnBehalf) Settings
        try {
            write-host -ForegroundColor Gray -Object "INFO: START Task (4/5) for User $($entry.DestinationUserPrincipalName) - ReApply MessageCopy Settings"
            reapply-MailboxMessageCopyConfiguration -MailboxIdentity $entry.DestinationUserPrincipalName -reportIdentifier $entry.SourceUserPrincipalName -ErrorAction Stop
            write-host -ForegroundColor Gray -Object "INFO: END Task (4/5) for User $($entry.DestinationUserPrincipalName) - ReApply MessageCopy Settings"
        }
        catch {
            $ReapplyErrors++
            Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying MessageCopy Settings"
            Write-Host -ForegroundColor Red -Object $error[0]
        }
        #Send As Permissions
        try {
            write-host -ForegroundColor Gray -Object "INFO: START Task (5/5) for User $($entry.DestinationUserPrincipalName) - ReApply Send As Permissions"
            reapply-sendaspermissions -MailboxIdentity $entry.DestinationUserPrincipalName -reportIdentifier $entry.SourceUserPrincipalName -ErrorAction Stop
            write-host -ForegroundColor Gray -Object "INFO: END Task (5/5) for User $($entry.DestinationUserPrincipalName) - ReApply Send As Permissions"
        }
        catch {
            $ReapplyErrors++
            Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying send as permissions"
            Write-Host -ForegroundColor Red -Object $error[0]        
        }

    }catch{
            Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid mailbox for CSV Entry $([string]$entry.EmailAddress)"
            Write-Host -ForegroundColor Red -Object $error[0]                    
    }
    Stop-Transcript
    if($ReapplyErrors -eq 0 -AND $Global:InModuleErrorOccured -eq $false){
        write-host -ForegroundColor Gray -Object "INFO: All tasks for these users were processed sucessfully"
    }else{
        Write-Host -ForegroundColor Yellow "WARNING: At least one error orruced while Reapplying Settings"
    }
    Write-Host -ForegroundColor Gray -Object "INFO: END PostProcessing for User $([string]$entry.UserPrincipalName)"
    Write-Host -ForegroundColor Gray -Object "-----------------------------------------------------"
}

