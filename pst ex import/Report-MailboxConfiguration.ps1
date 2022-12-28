$csvpath="c:\git\thinblog\pst ex import\mbxusers.csv"
$reportbasepath="c:\git\thinblog\pst ex import\Export\"

#Region Functions
function Report-MailboxDetails{
    param(
        $MailboxIdentity,
        $reportpath
    )

    $mbx=get-mailbox -Identity $MailboxIdentity
    $XMlExportError=0
    
    $ExportMbxPermissionFilePath=($reportpath+"MBXPermission_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxSettingsFilePath=($reportpath+"MBXSettings_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxCalendarProcessingFilePath=($reportpath+"MBXCalendarProcessing_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxFolderStatisticsFilePath=($reportpath+"MBXFolderStatistics_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxFolderPermissionsFilePath=($reportpath+"MBXFolderPermissions_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxRegionalConfigurationFilePath=($reportpath+"MBXRegionalConfiguration_"+[string]$mbx.primarysmtpaddress+".xml")
    $ExportMbxRecipientPermissionsFilePath=($reportpath+"MBXRecipientPermissions_"+[string]$mbx.primarysmtpaddress+".xml")

    # Export Mailbox Permissions
    $permissions = Get-MailboxPermission ([string]$mbx.DistinguishedName) | Where-Object {[string]$_.AccessRights -eq "FullAccess" -and !$_.IsInherited}
    try {
        $permissions | Export-Clixml $ExportMbxPermissionFilePath -ErrorAction Stop
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox permissions for mailbox $Mailboxidentity, please investigate."
    }

    # Export Calendar PRocessing
    $CalendarProcessing = Get-CalendarProcessing ([string]$mbx.DistinguishedName)
    try {
        $CalendarProcessing | Export-Clixml $ExportMbxCalendarProcessingFilePath -ErrorAction Stop
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the calendar procesing settings for mailbox $Mailboxidentity, please investigate."
    }
    
    
    #Export Mailbox Functions
    try {
        $mbx | Export-Clixml $ExportMbxSettingsFilePath -ErrorAction Stop    
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox Settings for mailbox $Mailboxidentity, please investigate."
    }

    # Export Mailbox Folder Statistics
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

    #Mailbox Regional Configuration
    $mailboxregionalconfiguration = Get-MailboxRegionalConfiguration -Identity ([string]$mbx.DistinguishedName)
    try {
        $mailboxregionalconfiguration | Export-Clixml $ExportMbxRegionalConfigurationFilePath -ErrorAction Stop    
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox regional configuration for mailbox $Mailboxidentity, please investigate."
    }

    #Mailbox Recipient Permissions
    $mailboxRecipientPermissions = RecipientPermission -Identity ([string]$mbx.DistinguishedName)
    try {
        $mailboxRecipientPermissions | Export-Clixml $ExportMbxRecipientPermissionsFilePath -ErrorAction Stop    
    }
    catch {
        $XMlExportError++
        Write-Host -ForegroundColor Red -Object "There was an issue exporting the mailbox recipient permissions for mailbox $Mailboxidentity, please investigate."
    }
    
}

#EndRegion Functions

#connect to source
Connect-exchangeOnline

try {
    $namedmailboxes=@()
    $allmailboxes=Get-Mailbox -resultsize unlimited
    $CSV=Import-Csv -Path $csvpath
    foreach($entry in $csv){
        try{
            $namedmailboxes+= $allmailboxes | Where-Object {$_.EmailAddresses -like ("SMTP:"+[string]$entry.EMailAddress)} -ErrorAction Stop
        }catch {
            Write-Host -ForegroundColor Red -Object "ERROR: Can't find a valid mailbox for CSV Entry $([string]$entry.EMailAddress)"
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
        $ExportPath=New-Item -Path $reportbasepath -ItemType Directory -Name $entry.primarysmtpaddress -Force
        Report-MailboxDetails -MailboxIdentity $entry.Identity -ErrorAction Stop -reportpath ($ExportPath.fullname+"\")
        Write-Host -ForegroundColor Gray -Object "INFO: The XML Report Files were succesfully generated for user $([string]$entry.primarysmtpaddress)"
    }
    catch {
        #insert error handling here
    }  
}

Write-Host -ForegroundColor Gray -Object "INFO: End - Create Mailbox Permission and Setting Reports"  

Disconnect-ExchangeOnline