# Import PST Files to the Users Mailbox 
# Run this in a regular powershell, it will connect to EXO (ExchangeOnlineManagement)

$containerURL="https://scalablepstimport.blob.core.windows.net/pstimport"
$sastoken="?sp=racw&st=2022-11-25T09:23:1"

$CohortName="C1"
$PSTImportMappingTableReport="C:\git\thinBlog\pst ex import\PSTImportMappingTableReport.csv"

#import pst
$BadItemLimit = "500"
$LargeItemLimit = "500"
$PSTImportMappingTable = Import-Csv $PSTImportMappingTableReport -Delimiter ';'
$DestinationFolder = '/' # / = Top of InformationStore
$IncludeFolders= "/*"

$EXOSession = Connect-ExchangeOnline #
$ErrorOccured=@()
foreach ($entry in $PSTImportMappingTable) {
    $UserPSTCount = ($PSTImportMappingTable | where { $_.SourceUserPrincipalName -like $entry.SourceUserPrincipalName}).count
    try {
        Write-Host -ForegroundColor Gray -Object "INFO: Create Import $i/$($entry.PSTCount) for $($entry.DestinationUserPrincipalName)"
		#The default Syntax of the folder where the regular mailbox content in it after an ediscovery export is "primarysmtp@address.com (Primary)\Top of Information Store". This might be changed in other export scenrios
        New-MailboxImportRequest -Name ($CohortName + "_" + $entry.DestinationUserPrincipalName + "_Import_" + $i + "/" + $entry.PSTCount) -Mailbox $entry.DestinationUserPrincipalName -SourceRootFolder ($entry.SourceUserPrincipalName+ " (Primary)/Top of Information Store") -TargetRootFolder $DestinationFolder -IncludeFolders $IncludeFolders -BadItemLimit $BadItemLimit -LargeItemLimit $LargeItemLimit -AzureBlobStorageAccountUri ($containerURL + "/" + $entry.DestinationUserPrincipalName + "/" + $entry.PSTName ) -AzureSharedAccessSignatureToken $sastoken -AcceptLargeDataLoss -ErrorAction Stop -WarningAction SilentlyContinue #-ConflictResolutionOption forcecopy 
    }
    catch {
		Write-Host -ForegroundColor Red -Object "Error: Create Import $i/$($entry.PSTCount) for $($entry.DestinationUserPrincipalName)"
		$Error[0]
		$ErrorOccured+=$entry
		
	} 
}

disconnect-exchangeonline

<#
Get-MailboxImportRequest |where {$_.Status -eq "failed"} |Get-MailboxImportRequestStatistics |fl name,targetalias,message
#>