Param(
    [Parameter(Mandatory=$true)][string]$migrationBatchName,
    [Parameter(Mandatory=$false)][string]$csvpath,
    [Parameter(Mandatory=$false)][string]$mode, #CreateReports, CompleteMigrationBatch, Reapply, DownloadJobDetails
    [Parameter(Mandatory=$false)][boolean]$test,
    [Parameter(Mandatory=$false)][boolean]$enableArchive=$true
)


#group to change= SW-Exchange-Online
#ous rausnehmen/ändern
#TBD lets start here in EXO

#XML to BAtch Folder
#Log add to group
#CSVPath Fix


$GroupsToAdd=@()
$GroupsToAdd="SW-Exchange-Online"

$reportbasepath="C:\Batch\Powershell-Skripte\Exchange\Migration\Reports\"
$skippedItemsReportPath=$reportbasepath+"MigrationReports\SkippedItems\"
$MigrationReportPath=$reportbasepath+"MigrationReports\"
[string]$ExchangeServer="rez01sr0240.patrizia.ag"
[string]$ExchangeConnectionURI="http://"+$ExchangeServer+"/powershell"

if($test){
    [string]$ExchangeServer="ex01.ucc.academy"
    [string]$ExchangeConnectionURI="http://"+$ExchangeServer+"/powershell"
    $reportbasepath="C:\Temp\Migration\Reports\"
    $skippedItemsReportPath=$reportbasepath+"MigrationReports\SkippedItems\"
    $MigrationReportPath=$reportbasepath+"MigrationReports\"
}

#import module
Import-Module -Name ".\Modules\Migration_Modules.psm1" -DisableNameChecking -Force

$EXOPsession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeConnectionUri -Authentication Kerberos 
Import-PSSession $EXOPsession -DisableNameChecking -Prefix "EXOP" -AllowClobber | Out-Null 

if (!$mode -xor ($mode -like "CreateReports") ) {
    try {
        #TBD modulisieren Vergleich IMport MBX mit aktuellen Mailboxen
        $namedmailboxes=@()
        $allmailboxes=Get-EXOPMailbox -resultsize unlimited
        $CSV=Import-Csv -Path $csvpath
        foreach($entry in $csv){
            try{
                $namedmailboxes+= $allmailboxes | Where-Object {$_.EmailAddresses -like ("SMTP:"+[string]$entry.EMailAddress)} -ErrorAction Stop
                #now i have valid mailboxes
            }catch {
                Write-Host -ForegroundColor Red -Object "ERROR: Can´t find a valid mailbox for CSV Entry $([string]$entry.EMailAddress)"
                Write-Host -ForegroundColor Red -Object $error[0]
            }
        }
    } catch {
        write-host -Foregroundcolor Red -Object "ERROR: no valid mailbox found, check csv path"
        Write-Host -ForegroundColor Red -Object $error[0]    
    }

    Write-Host -ForegroundColor Gray -Object "INFO: Start - Create Mailbox Permission and Setting Reports"
    foreach($entry in $namedmailboxes){
        try {
            Write-Host -ForegroundColor Gray -Object "INFO: Starting to create Report Files for user $([string]$entry.primarysmtpaddress)"
            Report-MailboxDetails -MailboxIdentity $entry.Identity -ErrorAction Stop -reportpath $reportbasepath
            Write-Host -ForegroundColor Gray -Object "INFO: The XML Report Files were succesfully generated for user $([string]$entry.primarysmtpaddress)" #insert path here?
        }
        catch {
            
        }  
    }
    Remove-PSSession -Session $EXOPsession
    Write-Host -ForegroundColor Gray -Object "INFO: End - Create Mailbox Permission and Setting Reports"    
}


##now finish migration batch
#connect to EXO

#besser suchen nach migrationjobs aus dem batch und für jeden einzeln abschluss+permissions setzen machen. der count nicht abgeschlossener batches sollte gen 0 gehen. hierfür eine while schleife nutzen
#get-moverequest -batchname $batchname

if (!$mode -xor ($mode -like "CompleteMigrationBatch") -xor ($mode -like "Reapply")-xor ($mode -like "DownloadJobDetails")){
    Write-Host -ForegroundColor Gray -Object "ACTION: Please enter Admin Credentials to connect to Exchange Online"
    $sessionExchangeOnline=Connect-ExchangeOnlineShell
}

if (!$mode -xor ($mode -like "CompleteMigrationBatch") ) {

    #write-host nownewline ggf nutzen um fortschritt zu zeigen
    #ggf $error[0]
    Write-Host -ForegroundColor Gray -Object "INFO: Start - Finalize MigrationBatch $(get-date)"
    try {
    #TBD validate if the migbatch includes only mbx´s which were contained in the csv. 
        $tries=30
        $migrationbatch = get-migrationbatch -Identity $migrationBatchName
        $errorCount=0
        while (([string]$migrationbatch.Status -ne "completed") -XOR ($migrationbatch -ne "CompletedWithErrors") -XOR ($errorCount -le $tries)) { #set errorcount higher when using this prodctive, add timeout
            if ([string]$migrationbatch.Status-eq "completing") {
                Write-Host -ForegroundColor Gray -Object "INFO: Waiting for MigrationBatch completion, Migrationbatch Status: $([string]$migrationbatch.Status) ($errorcount/$tries)"
                Start-Sleep -Seconds 60
                $errorCount++            
            }
            elseif (([string]$migrationbatch.Status -eq "Corrupted") -OR ([string]$migrationbatch -eq "Failed")) {
                #permanent error
            }elseif (([string]$migrationbatch.Status -eq "SyncedwithErrors") <#-OR ($migrationbatch -eq "Failed")#>) {
                #please review the migrationbatch, i dont think that we should do anything here
                #maybe i should offer/include a resume here
                $notsyncedmoverequestcount= $migrationbatch.Totalcount - $migrationbatch.SyncedCount
                Write-Host -ForegroundColor Yellow -Object "WARNING: There are $notsyncedmoverequestcount Move Requests that couldn´t be finished. Please review the Migration Batch "
                Start-Sleep -Seconds 60
                $errorCount++  
                #TBD aks user to proceed nevertheless, now it´s a 

            }elseif([string]$migrationbatch.Status -eq "Synced"){
                Complete-MigrationBatch -Identity ([string]$migrationbatch.Identity) -ErrorAction Stop
                $errorCount=0
            }else{
                
                    Write-Host -ForegroundColor Gray -Object "INFO: Migrationbatch Status $([string]$migrationbatch.Status) (($errorcount)/($tries))"
                    Start-Sleep -Seconds 60
                    $errorCount++            
            }
            $migrationbatch = get-migrationbatch -Identity ([string]$migrationbatch.Identity)
        }
        Start-Sleep -Seconds 60
            
        if([string]$migrationbatch.Status -like "completed"){
            write-host -ForegroundColor Green -Object "INFO: The MigrationBatch $([string]$migrationbatch.Name) is now completed without errors"
        }elseif([string]$migrationbatch.Status -ne "completed"){
            write-host -ForegroundColor Yellow -Object "WARNING: The MigrationBatch $([string]$migrationbatch.Name) is completed with errors, please review the Migration Batch Details"
        }
    }
    #    Write-Host -ForegroundColor Gray -Object "The MigrationBatch $($migrationbatch.Identity)"

    catch {
        #erroraction retry?
        write-host -ForegroundColor Red -Object "ERROR: The MigrationBatch couldn´t be completed"
        Write-Host -ForegroundColor Red -Object $error[0]
    }
    Write-Host -ForegroundColor Gray -Object "INFO: End - Finalize MigrationBatch"
}
#now reapply settings and permissions
#in EXO


if (!$mode -xor ($mode -like "Reapply") ) {

    if($mode -like "Reapply"){
        $XMLConfirmation=Read-Host -Prompt "In this mode the creation of XML Files could not be validated. Please check that there are valid XML files for the affected users in the migration batch in the Report Location: $reportbasepath `r`nPlease insert 'y' to proceed"
        if (!$XMLConfirmation -like "y"){
            Exit
        }
    }
    if (($XMlExportError -gt 0)) {
        $XMLExportErrorConfirmation=Read-Host -Prompt "While creating the XML Files for Mailboxes at least one error occured.`r`nPlease insert 'y' to if you want to proceed nevertheless"                
        if (!$XMLExportErrorConfirmation -like "y"){
            Exit
        }
    }

    Write-Host -ForegroundColor Gray -Object "ACTION: Please enter Admin Credentials to connect to AzureAD"
    $sessionAzureAD=Connect-AzureAd
    if((get-migrationbatch $migrationBatchName).Status.toString() -eq "Completed"){
        $Proceed= $true
    }elseif((get-migrationbatch $migrationBatchName).Status.toString() -eq "CompletedWithErrors"){
        $PromptAnswer=Read-Host -Prompt "The Migration Batch was finished with errors. Please insert 'y' to if you want to proceed nevertheless"                
        if (!$PromptAnswer -like "y"){
            Exit
        }else{
            $Proceed= $true
        }
    }

    if($Proceed){
    Write-Host -ForegroundColor Gray -Object "INFO: Start - Re-Apply Permissions and Settings"

        try {
            #make module out of this validation
            $namedexomailboxes=@()
            $allexomailboxes=Get-Mailbox -resultsize unlimited
            $CSV=Import-Csv -Path $csvpath
            foreach($entry in $csv){
                try{
                    $namedexomailboxes+= $allexomailboxes | Where-Object {[string]$_.PrimarySmtpAddress -like [string]$entry.EmailAddress} -ErrorAction Stop
                    #now i have valid mailboxes
                }
            catch {
                    Write-Host -ForegroundColor Red -Object "ERROR: Can´t find a valid mailbox for CSV Entry $([string]$entry.EmailAddress)"
                    Write-Host -ForegroundColor Red -Object $error[0]                    
                }
            }
        }catch{
            # no valid mailbox found, check csv path    
        }

        foreach($entry in $namedexomailboxes){
            Start-Transcript -Path ($reportbasepath+"ReApplyTranscript_"+[string]$entry.primarysmtpaddress+".txt")
            [int32]$ReapplyErrors=0
            $Global:InModuleErrorOccured=$false
            $ReapplyErrorDetails=@()
            Write-Host -ForegroundColor Gray -Object "INFO: START PostProcessing for User $([string]$entry.UserPrincipalName)"
            #Mailbox FullAccess Permissions
            try {
                write-host -ForegroundColor Gray -Object "INFO: START Task (1/7) for User $([string]$entry.UserPrincipalName) - ReApply FullAccess Permissions for Groups"
                reapply-fullaccessPermissions -MailboxIdentity ([string]$entry.UserPrincipalName) -reportpath $reportbasepath -ErrorAction Stop
                Write-Host -ForegroundColor Gray -Object "INFO: END Task (1/7) for User $([string]$entry.UserPrincipalName) - ReApply FullAccess Permissions for Groups"
                
            }
            catch {
                $ReapplyErrors++
                Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying FullAccess permissions for Groups"
                
                Write-Host -ForegroundColor Red -Object $error[0]
            }

            #Mailbox SendOnBehalf Permissions
            try {
                write-host -ForegroundColor Gray -Object "INFO: START Task (2/7) for User $([string]$entry.UserPrincipalName) - ReApply Send On Behalf Permissions for Groups"
                reapply-sendonbehalfpermissions -MailboxIdentity ([string]$entry.UserPrincipalName) -reportpath $reportbasepath -ErrorAction Stop
                write-host -ForegroundColor Gray -Object "INFO: END Task (2/7) for User $([string]$entry.UserPrincipalName) - ReApply Send On Behalf Permissions for Groups"
            }
            catch {
                $ReapplyErrors++
                Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying SendOnBehalf permissions for Groups"
                Write-Host -ForegroundColor Red -Object $error[0]
                
            }

            #Mailbox Regional Configuration
            try {
                write-host -ForegroundColor Gray -Object "INFO: START Task (3/7) for User $([string]$entry.UserPrincipalName) - ReApply Mailbox Regional Settings"
                reapply-mailboxregionalsettings -MailboxIdentity ([string]$entry.UserPrincipalName) -reportpath $reportbasepath -ErrorAction Stop
                write-host -ForegroundColor Gray -Object "INFO: END Task (3/7) for User $([string]$entry.UserPrincipalName) - ReApply Mailbox Regional Settings"
            }
            catch {
                $ReapplyErrors++
                Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying mailbox regional configuration"
                Write-Host -ForegroundColor Red -Object $error[0]
                
            }

            #Send As
            try {
                
                write-host -ForegroundColor Gray -Object "INFO: START Task (4/7) for User $([string]$entry.UserPrincipalName) - ReApply Send As Permissions"
                reapply-sendaspermissions -MailboxIdentity ([string]$entry.UserPrincipalName) -reportpath $reportbasepath -ErrorAction Stop
                write-host -ForegroundColor Gray -Object "INFO: END Task (4/7) for User $([string]$entry.UserPrincipalName) - ReApply Send As Permissions"
            }
            catch {
                $ReapplyErrors++
                Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying send as permissions"
                Write-Host -ForegroundColor Red -Object $error[0]
                
            }
        #assign group memberships, related to the migration
            write-host -ForegroundColor Gray -Object "INFO: START Task (5/7) for User $([string]$entry.UserPrincipalName) - Add additional Group Memberships"
            foreach ($group in $GroupsToAdd){
                try {
                    $group=Get-ADGroup -Identity $group
                    Add-ADGroupMember -Identity $group -Members (get-azureaduser -ObjectID ([string]$entry.UserPrincipalName)).OnPremisesSecurityIdentifier -ErrorAction Stop
                    Write-Host -ForegroundColor Gray -Object "INFO: Success adding user to group $($group.Name)"
                }
                catch {
                    $ReapplyErrors++
                    Write-Host -ForegroundColor Red -Object "ERROR: Error adding user to groups"
                    Write-Host -ForegroundColor Red -Object $error[0]
                    
                }
            }
            write-host -ForegroundColor Gray -Object "INFO: END Task (5/7) for User $([string]$entry.UserPrincipalName) - Add additional Group Memberships"

            #Forwarding
            try {
                write-host -ForegroundColor Gray -Object "INFO: START Task (6/7) for User $([string]$entry.UserPrincipalName) - ReApply Forwarding Settings"
                reapply-MailboxForwardingSettings -MailboxIdentity ([string]$entry.UserPrincipalName) -reportpath $reportbasepath -ErrorAction Stop
                write-host -ForegroundColor Gray -Object "INFO: END Task (6/7) for User $([string]$entry.UserPrincipalName) - ReApply Forwarding Settings"
            }
            catch {
                $ReapplyErrors++
                Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying forwarding settings"
                Write-Host -ForegroundColor Red -Object $error[0]
                
            }

            #reapply-MailboxMessageCopyConfiguration
            try {
                write-host -ForegroundColor Gray -Object "INFO: START Task (7/7) for User $([string]$entry.UserPrincipalName) - ReApply MessageCopy Settings"
                reapply-MailboxMessageCopyConfiguration -MailboxIdentity ([string]$entry.UserPrincipalName) -reportpath $reportbasepath -ErrorAction Stop
                write-host -ForegroundColor Gray -Object "INFO: END Task (7/7) for User $([string]$entry.UserPrincipalName) - ReApply MessageCopy Settings"
            }
            catch {
                $ReapplyErrors++
                Write-Host -ForegroundColor Red -Object "ERROR: Error re-applying MessageCopy Settings"
                Write-Host -ForegroundColor Red -Object $error[0]
            }

            #Enable Archive for all User Mailboxes
            if ($enableArchive -AND  $entry.RecipientTypeDetails -eq "UserMailbox") {
                write-host -ForegroundColor Gray -Object "INFO: EnableArchive Parameter was set. Now enabling Mailbox Archive for User-Mailbox $([string]$entry.UserPrincipalName)"
                try {
                    enable-EXOPRemoteMailbox -Identity $entry.UserPrincipalName -Archive -ErrorAction Stop
                    "INFO: Enabling Mailbox Archive for $([string]$entry.UserPrincipalName) was successfull"
                }
                catch {
                    Write-Host -ForegroundColor Red -Object "ERROR: Error occured while enabling the mailbox archive"
                }
            }

            Stop-Transcript

            if($ReapplyErrors -eq 0 -AND $Global:InModuleErrorOccured -eq $false){
                write-host -ForegroundColor Gray -Object "INFO: All tasks for this users were processed sucessfully, the XML Report Files will be moved"
                $FilesIdentifier=([string]$entry.primarysmtpaddress+".*")
                $filesToMove=get-childitem -Path ($reportbasepath+"*"+$FilesIdentifier)
                $Weekfolder=New-Item -Path $reportbasepath -Name ("KW"+(Get-Weeknumber)) -ItemType Directory -Force
                $UserFolder=New-Item -Path $Weekfolder -Name ([string]$entry.primarysmtpaddress) -ItemType Directory -Force
                foreach($file in $filesToMove){
                    move-item -path $file.VersionInfo.FileName -Destination $UserFolder
                }
            }else{
                Write-Host -ForegroundColor Yellow "WARNING: At least one error orruced while Reapplying Settings, the XML Report Files will stay in the Root Folder to allow manual postprocessing. A additional XML was created which contains the detailed error informations"
#                $ReapplyErrorDetails | Export-Clixml ($reportbasepath+"ReApplyErrors_"+[string]$entry.primarysmtpaddress+".xml")
            }
            Write-Host -ForegroundColor Gray -Object "INFO: END PostProcessing for User $([string]$entry.UserPrincipalName)"
            Write-Host -ForegroundColor Gray -Object "-----------------------------------------------------"
        }
        
    }else {
        #migbatch not in status completed, check status or allow force when e.g. migbatchstatus completed with errors
    }
    Disconnect-AzureAD
}

if (!$mode -xor ($mode -like "DownloadJobDetails") ) {

    $moverequestsinbatch=get-moverequest -batchname ("MigrationService:"+$migrationbatchname)
    write-host -ForegroundColor Gray -Object "INFO: Start creating MigrationBatchReports, this will take a while"
    write-host ("MigrationService:"+$migrationbatchname)
    foreach($move in $moverequestsinbatch){
        Write-Host -ForegroundColor Gray -Object "INFO: Creating Migration Detail Report for $((get-recipient $move.Identity).PrimarySMTPAddress)"
        $moverequestdetails=Get-MigrationUserStatistics -Identity ((get-recipient $move.Identity).PrimarySMTPAddress) -IncludeReport -IncludeSkippedItems
        $moverequestdetails.Report | export-clixml ($MigrationReportPath+$move.Identity+".xml") 
        if($moverequestdetails.SkippedItemCount -gt 0){
            Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Items were skipped while migratiing this mailbox, Creating skipped item report for $((get-recipient $move.Identity).PrimarySMTPAddress)"
            foreach($item in $moverequestdetails.SkippedItems){
                $item | Out-File -FilePath ($skippedItemsReportPath+$move.Identity+".txt") -Append -Encoding Unicode
            }
        }
    }
    write-host -ForegroundColor Gray -Object "INFO: End creating MigrationBatchReports"
}

#disconnect EXO
if($sessionExchangeOnline){
    disconnect-ExchangeOnlineShell -SessionID $sessionExchangeOnline.ID | out-null
}



