#Requires -Modules ExchangeOnlineManagement
#https://practical365.com/targeted-collection-content-search/

$ComplianceCenterConnection=Connect-IPPSSession
$ExchangeOnlineConnection=Connect-ExchangeOnline

$csvPath="C:\git\thinBlog\ArchiveExport\MailboxList.csv"
$eDiscoveryCaseName="Search Archive Mailbox Content $(get-date -format "yyyyMMdd_HHmm")"
$eDiscoveryCaseDescription="Searches for all non-system Mailbox Folders within archive mailboxes"
$OneSearchForAll=$false

$MailboxList=Import-Csv -Path $csvPath -Delimiter ';'

$eDiscoverySearchCollection=@{}
$MailboxSearchString=""

function get-ArchiveMailboxFolderIDs {
    param (
        [Parameter(Mandatory=$true)][string]$MailboxUPN,
        [Parameter(Mandatory=$false)][bool]$excludeSystemFolders=$true
    )
    
    $FolderIDCollection=@()
    $searchString=""
    $SystemFolderNames="ExternalContacts","Files", "Recoverable Items", "Audits", "Calendar Logging", "Deletions", "DiscoveryHolds", "SearchDiscoveryHoldsFolder", "SearchDiscoveryHoldsUnindexedItemFolder", "Top of Information Store", "Purges", "SubstrateHolds", "Versions"
    #Check mailbox for activated archive
    $Mailbox=get-exoMailbox $mailboxupn -properties ArchiveStatus
    if($mailbox.archivestatus -eq 'Active'){
        $FoldersInArchiveMailbox=Get-EXOMailboxFolderStatistics -Identity $MailboxUPN -Archive -ErrorAction Stop        
    }else{
        Write-host -ForegroundColor YELLOW -object "[WARNING] The Archive Mailbox is not activated for $($mailboxupn)"
        return
    }
    if($excludeSystemFolders){
        $FoldersToSearchFor=$FoldersInArchiveMailbox |where {$_.Name -notin $SystemFolderNames}
    }else {
        $FoldersToSearchFor=$FoldersToSearchFor
    }

    #The following method of converting the Exchange Folder ID to an ID that is usable in the compliance search was copied from #https://practical365.com/targeted-collection-content-search/
    foreach ($Folder in $FoldersToSearchFor){
        $folderid=$Folder.FolderID
        $Encoding = [System.Text.Encoding]::GetEncoding("us-ascii")
        $Nibbler = $Encoding.GetBytes("0123456789ABCDEF")
        $FolderIdBytes = [Convert]::FromBase64String($folderId)
        $IndexIdBytes = New-Object byte[] 48
        $IndexIdIdx=0
        $FolderIdBytes | Select-object -skip 23 -First 24 | %{$indexIdBytes[$indexIdIdx++]=$nibbler[$_ -shr 4];$indexIdBytes[$indexIdIdx++]=$nibbler[$_ -band 0xF]}        
        $FolderIDCollection+=$($encoding.GetString($indexIdBytes))
    }

    foreach ($FolderID in $FolderIDCollection){
        $searchString+="folderid:"+$FolderID+" OR "
    }
    
    $cleanedSearchString=$searchString.TrimEnd(" OR ")

    $result=@{
        SearchString=$cleanedSearchString
        FolderNames=$FoldersToSearchFor.name
        MailboxUPN=$MailboxUPN
    }

    $result
}


$ComplianceCase=New-ComplianceCase -Name $eDiscoveryCaseName -CaseType eDiscovery -Description $eDiscoveryCaseDescription

if($OneSearchForAll){
    foreach ($mailbox in $MailboxList){
        $archiveMailboxFolderIDs=(get-ArchiveMailboxFolderIDs -MailboxUPN $mailbox.UPN -excludeSystemFolders $true).SearchString
        if($archiveMailboxFolderIDs){
            $MailboxSearchString+=($archiveMailboxFolderIDs + " OR ")    
        }
    }
    $MailboxSearchString=$MailboxSearchString.TrimEnd(" OR ")
    
    try {
        $NewSearch=New-ComplianceSearch -Name ("Archive Content of named Mailboxes") -Case $ComplianceCase.Name -ExchangeLocation All -ContentMatchQuery $MailboxSearchString -ErrorAction STOP
        Write-host -ForegroundColor GRAY -object "[INFO] Mailbox Search was started" 
        start-ComplianceSearch -Identity $NewSearch.Name -force    
    }
    catch {
        Write-host -ForegroundColor RED -object "[ERROR] Could not create a search for $($mailboxupn): $($errors[0])" 
    }    
}else{
    foreach ($mailbox in $MailboxList){
        $MailboxSearchString=(get-ArchiveMailboxFolderIDs -MailboxUPN $mailbox.UPN -excludeSystemFolders $true).SearchString
        try {
            if($MailboxSearchString){
                $NewSearch=New-ComplianceSearch -Name ("Archive Content of "+$($mailbox.UPN)) -Case $ComplianceCase.Name -ExchangeLocation $mailbox.UPN -ContentMatchQuery $MailboxSearchString -ErrorAction STOP
                Write-host -ForegroundColor GRAY -object "[INFO] Mailbox Search was started for $($mailbox.UPN)" 
                start-ComplianceSearch -Identity $NewSearch.Name -force
            }
        }
        catch {
            Write-host -ForegroundColor RED -object "[ERROR] Could not create a search for $($mailbox.UPN): $($errors[0])" 
    
        }
        
    }
}
