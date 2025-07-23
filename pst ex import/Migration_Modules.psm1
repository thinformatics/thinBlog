function Report-MailboxDetails{
    param(
        $MailboxIdentity,
        $reportpath
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMlExportError=0
    
    #$ExportMbxCalendarConfigFilePath=($reportpath+"Calendarpermissions"+$mbx.primarysmtpaddress.address+".xml")
    $ExportMbxPermissionFilePath=($reportpath+"MailboxPermission_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxSendAsPermissionFilePath=($reportpath+"SendAsPermissions_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxSettingsFilePath=($reportpath+"MBXSettings_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxCalendarProcessingFilePath=($reportpath+"MBXCalendarProcessing_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxFolderStatisticsFilePath=($reportpath+"MBXFolderStatistics_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxFolderPermissionsFilePath=($reportpath+"MBXFolderPermissions_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxRegionalConfigurationFilePath=($reportpath+"MBXRegionalConfiguration_"+[string]$mbx.primarysmtpaddress+".xml")

    # Export der Postfach-Berechtigungen
    $permissions = Get-MailboxPermission ([string]$mbx.DistinguishedName) | Where-Object {[string]$_.AccessRights -eq "FullAccess" -and !$_.IsInherited}
    try {
        $permissions | Export-Clixml $ExportMbxPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox permissions for mailbox $Mailboxidentity, please investigate."
    }

    # Export des Calendar PRocessing
    $CalendarProcessing = Get-CalendarProcessing ([string]$mbx.DistinguishedName)
    try {
        $CalendarProcessing | Export-Clixml $ExportMbxCalendarProcessingFilePath -ErrorAction Stop
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the calendar procesing settings for mailbox $Mailboxidentity, please investigate."
    }
    
    
    # Ermittlung der Send-As-Zugriffsrechte
    <# nochmal separat betrachten
    $permissions_SendAs = Get-ADPermission ([string]$mbx.DistinguishedName) | Where-Object {([string]$_.ExtendedRights -like "Send-As") -and ($_.IsInherited -eq $false) -and -not ([string]$_.User -like "NT Authority\Self")}
    try {
        $permissions_SendAs | Export-Clixml $ExportMbxSendAsPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the send as permissions for mailbox $Mailboxidentity, please investigate."
    }
    #>

    # Export der Mailbox Funktionen
    try {
        $mbx | Export-Clixml $ExportMbxSettingsFilePath -ErrorAction Stop    
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox Settings for mailbox $Mailboxidentity, please investigate."
    }

    # Export Mailbox Folder Statistics
    # enthält z.B. Anzahl der beinhalteten Elemente
    $folderstatistics = Get-MailboxFolderStatistics -Identity ([string]$mbx.UserprincipalName)
    try {
        $folderstatistics | Export-Clixml  $ExportMbxFolderStatisticsFilePath -ErrorAction Stop    
    }
    catch {
        Write-Host -ForegroundColor Yellow -Object "There was an issue exporting the mailbox Statistics for mailbox $Mailboxidentity, please investigate. This is not a functional export"
    }
    
    #Get MailboxFolderPermissions and Count all Items
    foreach($folder in $folderstatistics){
        $MBXFolderPermission += Get-MailboxFolderPermission ([string]$mbx.PrimarySmtpAddress + ":" + ([string]$folder.FolderPath).Replace("/","\")) -erroraction silentlycontinue
        $countItems += $folder.ItemsInFolder
        $itemsize += $folder.FolderSize
    }
    try {
        $MBXFolderPermission | Export-Clixml $ExportMbxFolderPermissionsFilePath -ErrorAction Stop    
    }
    catch {
        Write-Host -ForegroundColor Yellow -Object "There was an issue exporting the mailbox folder permissions for mailbox $Mailboxidentity, please investigate. This is not a functional export"
    }

    #TBD Mailbox Regional Configuration
    $mailboxregionalconfiguration = Get-MailboxRegionalConfiguration -Identity ([string]$mbx.DistinguishedName)
    try {
        $mailboxregionalconfiguration | Export-Clixml $ExportMbxRegionalConfigurationFilePath -ErrorAction Stop    
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox regional configuration for mailbox $Mailboxidentity, please investigate."
    }
    
}

function reapply-fullaccessPermissions{
    param(
        $MailboxIdentity,
        $reportpath
        #$OUSearchBase="OU=Hamburg,DC=ucc,DC=academy" #parametrisieren ?! / weglassen, oder hohe ebene ermitteln / auslesen 
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    
    $ExportMbxPermissionFilePath=($reportpath+"MailboxPermission_"+[string]$mbx.primarysmtpaddress+".xml")

    try {
        $FullAccessPermissionReport=Import-Clixml -Path $ExportMbxPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can�t find a valid XML File for mailbox $([string]$mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxPermissionFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
    }

    foreach($PermissionEntry in $FullAccessPermissionReport){ # ist der level korrekt? nicht $fullaccesspermissionreport.irgendwas?
        if (([string]$PermissionEntry.User) -notlike "*\*") {
            Write-Host -ForegroundColor Yellow -Object "Warning: Send As Permission for User will not be re-applied, because it�s orphaned: $([string]$assignedentry.SamAccountName)"
            #this entry will be skipped
            continue
        }
        $domain,$SamAccountName=([string]$PermissionEntry.User).Split('\')
        $assignedentry=get-ADobject -Filter {samaccountname -like $SamAccountName} <#-SearchBase $OUSearchBase -SearchScope 2#> -Properties grouptype,samaccountname,objectSID
        if (($assignedentry.groupType)){
            Write-Host -ForegroundColor Gray -Object "INFO: Full Access Permission for Group will be re-applied: $([string]$assignedentry.SamAccountName)"
            #a group permission entry exists
            # this permission entry has to be reapplied

            $azureadcounterpart=get-azureadgroup -SearchString $assignedEntry.samaccountname |where-object {([string]$_.OnPremisesSecurityIdentifier) -eq ([string]$assignedEntry.objectSID) } #TBDP9 why can�t i filter directly on onpremisessecurityidentifier 
            try {
                add-mailboxpermission -identity ([string]$mbx.Identity) -User ([string]$azureadcounterpart.ObjectID) -AccessRights FullAccess -Erroraction Stop -WarningAction SilentlyContinue |out-null
                if(!$azureadcounterpart.MailEnabled ){
                    Write-Host -ForegroundColor Yellow -Object "ACTION: The Group $($azureadcounterpart.DisplayName) is not mail enabled. You will not able to use this permission. Please consider to mail enable it"
                }
            }
            catch {
                Write-Host -ForegroundColor Red -Object "ERROR: Can�t reapply permission for group with SAMAccountName $([string]$assignedentry.samaccountname), please check if there is a valid AzureAD Counterpart"
                $Global:InModuleErrorOccured=$true
            }
                
        }



        <#
        User RemoteMailbox
        msExchRecipientTypeDetails : 2147483648
        sAMAccountType             : 805306368

        global distribution group
        groupType      : 2
instanceType   : 4
sAMAccountType : 268435457


        local distribution group
        groupType      : 4
instanceType   : 4
sAMAccountType : 536870913

universal distribution group
groupType      : 2
instanceType   : 4
sAMAccountType : 268435457

universal security group
groupType      : -2147483640
instanceType   : 4
sAMAccountType : 268435456

local security group
groupType      : -2147483644
instanceType   : 4
sAMAccountType : 536870912

global security group
groupType      : -2147483646
instanceType   : 4
sAMAccountType : 268435456


        #>

    }
    
}
function reapply-mailboxregionalsettings{
    param(
        $MailboxIdentity,
        $reportpath
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxRegionalConfigurationFilePath=($reportpath+"MBXRegionalConfiguration_"+[string]$mbx.primarysmtpaddress+".xml")

    try {
        $MbxRegionalConfigurationReport=Import-Clixml -Path $ExportMbxRegionalConfigurationFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can�t find a valid XML File for mailbox $([string]$mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxPermissionFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
        #error info: can�t find valid xml 
        #and skip
    }
    
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
        get-mailbox ([string]$mbx.userprincipalname) | set-mailboxregionalconfiguration -Language ([string]$MbxRegionalConfigurationReport.Language) -Timeformat ([string]$MbxRegionalConfigurationReport.Timeformat)  -timezone ([string]$MbxRegionalConfigurationReport.timezone) -ErrorAction Stop | out-null
    }catch{
        Write-Host -ForegroundColor Red -Object "ERROR: error occured while applying mailbox regional settings for $([string]$mbx.primarysmtpaddress)"
        $Global:InModuleErrorOccured=$true
    }
    try{
        get-mailbox ([string]$mbx.userprincipalname) | set-mailboxregionalconfiguration -Dateformat ([string]$MbxRegionalConfigurationReport.dateformat) -ErrorAction Stop | out-null
    }catch{
        Write-Host -ForegroundColor Yellow -Object "Warning: error occured while applying mailbox regional dateformat for $([string]$mbx.primarysmtpaddress). $([string]$MbxRegionalConfigurationReport.dateformat) is not valid for language $([string]$MbxRegionalConfigurationReport.Language)"
    }

    

}

function reapply-sendonbehalfpermissions{
    param(
        $MailboxIdentity,
        $reportpath
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxSettingsFilePath=($reportpath+"MBXSettings_"+[string]$mbx.primarysmtpaddress+".xml")

    try {
        $MbxSettingsReport=Import-Clixml -Path $ExportMbxSettingsFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can�t find a valid XML File for mailbox $($mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSettingsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
        #error info: can�t find valid xml 
        #and skip
    }

    foreach($PermissionEntry in $MbxSettingsReport.GrantSendOnBehalfTo){
            $usercn=([string]$PermissionEntry.split("/")[-1])
            $assignedentry=get-ADobject -filter {cn -like $usercn} -Properties grouptype,samaccountname,objectSID
            if (($assignedentry.groupType)){
                Write-Host -ForegroundColor Gray -Object "INFO: Send on Behalf Permission for Group will be re-applied: $([string]$assignedentry.SamAccountName)"
                #a group permission entry exists
                # this permission entry has to be reapplied
    
                $azureadcounterpart=get-azureadgroup -SearchString ([string]$assignedEntry.samaccountname) |where-object {([string]$_.OnPremisesSecurityIdentifier) -eq ([string]$assignedEntry.objectSID) } #TBDP9 why can�t i filter directly on onpremisessecurityidentifier 
                try {
                    set-mailbox ([string]$mbx.Identity) -GrantSendOnBehalfTo @{Add=[string]$azureadcounterpart.ObjectID} -ErrorAction Stop -WarningAction SilentlyContinue | out-null
                    if(!$azureadcounterpart.MailEnabled ){
                        Write-Host -ForegroundColor Yellow -Object "ACTION: The Group $($azureadcounterpart.DisplayName) is not mail enabled. You will not able to use this permission. Please consider to mail enable it"
                    }
                }
                catch {
                    Write-Host -ForegroundColor Red -Object "ERROR: Can�t reapply permission for group with SAMAccountName $([string]$assignedentry.samaccountname), please check if there is a valid AzureAD Counterpart"  
                    $Global:InModuleErrorOccured=$true
                }
            }
        }
}

function reapply-sendaspermissions{
    param(
        $MailboxIdentity,
        $reportpath
        #$OUSearchBase="OU=Hamburg,DC=ucc,DC=academy"
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxSendAsPermissionFilePath=($reportpath+"SendAsPermissions_"+[string]$mbx.primarysmtpaddress+".xml")

    try {
        $SendAsReport=Import-Clixml -Path  $ExportMbxSendAsPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can�t find a valid XML File for mailbox $([string]$mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSendAsPermissionsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
        #error info: can�t find valid xml 
        #and skip
    }

    foreach($PermissionEntry in $SendAsReport){
            if (([string]$PermissionEntry.User) -notlike "*\*") {
                Write-Host -ForegroundColor Yellow -Object "Warning: Send As Permission for User will not be re-applied, because it�s orphaned: $([string]$assignedentry.SamAccountName)"
                #this entry will be skipped
                continue
            }
            $domain,$SamAccountName=([string]$PermissionEntry.User).Split('\')
            $assignedentry=get-ADobject -Filter {samaccountname -like $SamAccountName} <#-SearchBase $OUSearchBase -SearchScope 2#> -Properties grouptype,samaccountname,objectSID

            
                Write-Host -ForegroundColor Gray -Object "INFO: Send As Permission for User will be re-applied: $([string]$assignedentry.SamAccountName)"
                #a group permission entry exists
                # this permission entry has to be reapplied
                if (([string]$assignedentry.ObjectClass) -eq "user"){
                    $azureadcounterpart=get-azureaduser -SearchString ([string]$assignedEntry.samaccountname) |where-object {([string]$_.OnPremisesSecurityIdentifier) -eq ([string]$assignedEntry.objectSID) } #TBDP9 why can�t i filter directly on onpremisessecurityidentifier 
                }elseif (([string]$assignedentry.ObjectClass) -eq "group"){
                    $azureadcounterpart=get-azureadgroup -SearchString ([string]$assignedEntry.samaccountname) |where-object {([string]$_.OnPremisesSecurityIdentifier) -eq ([string]$assignedEntry.objectSID) } #TBDP9 why can�t i filter directly on onpremisessecurityidentifier 
                }
                
                try {
                    add-recipientpermission ([string]$mbx.Identity) -Trustee ([string]$azureadcounterpart.ObjectID) -AccessRights SendAs -ErrorAction Stop -WarningAction SilentlyContinue -confirm:$False | out-null
                    if(!$azureadcounterpart.MailEnabled -AND ([string]$assignedentry.ObjectClass) -eq "group"){
                        Write-Host -ForegroundColor Yellow -Object "ACTION: The Group $($azureadcounterpart.DisplayName) is not mail enabled. You will not able to use this permission. Please consider to mail enable it"
                    }
                }
                catch {
                    Write-Host -ForegroundColor Red -Object "ERROR: Can�t reapply permission for user with SAMAccountName $([string]$assignedentry.samaccountname), please check if there is a valid AzureAD Counterpart"  
                    $Global:InModuleErrorOccured=$true
                }
            
        }

}

function reapply-MailboxForwardingSettings{
    param(
        $MailboxIdentity,
        $reportpath
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxSettingsFilePath=($reportpath+"MBXSettings_"+[string]$mbx.primarysmtpaddress+".xml")

    try {
        $MbxSettingsFWReport=Import-Clixml -Path $ExportMbxSettingsFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can�t find a valid XML File for mailbox $($mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSettingsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
    }

    if ($MbxSettingsFWReport.DeliverToMailboxAndForward -OR $MbxSettingsFWReport.ForwardingAddress) {
        Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was enabled for the mailbox and will be re-applied."
        foreach($ForwardEntry in $MbxSettingsFWReport.ForwardingAddress){
            $usercn=([string]$ForwardEntry.split("/")[-1])
            $assignedentry=get-ADobject -filter {cn -like $usercn} -Properties grouptype,samaccountname,objectSID
            
            try {
                $azureadcounterpart=get-azureaduser -SearchString ([string]$assignedEntry.samaccountname) |where-object {([string]$_.OnPremisesSecurityIdentifier) -eq ([string]$assignedEntry.objectSID) } -ErrorAction Stop #TBDP9 why can�t i filter directly on onpremisessecurityidentifier     
            }
            catch {
                $azureadcounterpart=get-azureadgroup -SearchString ([string]$assignedEntry.samaccountname) |where-object {([string]$_.OnPremisesSecurityIdentifier) -eq ([string]$assignedEntry.objectSID) } -ErrorAction Stop
            }
            
            try {
                set-mailbox ([string]$mbx.Identity) -DelivertoMailboxAndForward $MbxSettingsFWReport.DeliverToMailboxAndForward -ForwardingAddress $azureadcounterpart.UserprincipalName -ErrorAction Stop -WarningAction SilentlyContinue | out-null
            }
            catch {
                Write-Host -ForegroundColor Red -Object "ERROR: Can�t reapply forwarding to $([string]$assignedentry.samaccountname), please check if there is a valid AzureAD Counterpart"  
                $Global:InModuleErrorOccured=$true
            }
            
        }        
    }else {
        Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was not enabled for the mailbox."
    }
}

function reapply-MailboxMessageCopyConfiguration{
    param(
        $MailboxIdentity,
        $reportpath
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMLImportErrorCount=0
    $ExportMbxSettingsFilePath=($reportpath+"MBXSettings_"+[string]$mbx.primarysmtpaddress+".xml")

    try {
        $MbxSettingsMessageCopy=Import-Clixml -Path $ExportMbxSettingsFilePath -ErrorAction Stop
    }
    catch {
        $XMLImportErrorCount++
        Write-Host -ForegroundColor Red -Object "ERROR: Can�t find a valid XML File for mailbox $($mbx.primarysmtpaddress). The expected path for the XML is: $ExportMbxSettingsFilePath. Please check the existence of a valid Report for this Mailbox to be able to reapply settings and permissions after migration batch finalization"
    }

    if ($MbxSettingsMessageCopy.MessageCopyForSentAsEnabled ) {
        Write-Host -ForegroundColor Gray -Object "INFO: Message Copy for Send As was enabled for the mailbox and will be re-applied."

        try {
            set-mailbox ([string]$mbx.Identity) -MessageCopyForSentAsEnabled $true -ErrorAction Stop -WarningAction SilentlyContinue | out-null
        }
        catch {
            Write-Host -ForegroundColor Red -Object "ERROR: Can�t reapply MessageCopyForSentAsEnabled to $([string]$assignedentry.samaccountname)"  
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
            Write-Host -ForegroundColor Red -Object "ERROR: Can�t reapply MessageCopyForSendOnBehalfEnabled to $([string]$assignedentry.samaccountname)"  
            $Global:InModuleErrorOccured=$true
        }     
    }else {
        #Not woth a notification Write-Host -ForegroundColor Gray -Object "INFO: Mailbox Forwarding was not enabled for the mailbox."
    }
}

function Get-WeekNumber([datetime]$DateTime = (Get-Date)) {
    $cultureInfo = [System.Globalization.CultureInfo]::CurrentCulture
    $cultureInfo.Calendar.GetWeekOfYear($DateTime,$cultureInfo.DateTimeFormat.CalendarWeekRule,$cultureInfo.DateTimeFormat.FirstDayOfWeek)
}