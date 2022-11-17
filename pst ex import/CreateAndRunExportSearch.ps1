$CaseName="MBXBulkExport"
$CaseDescription="This is Cohort X which we export today"
$ExportDG="MBXToMigrate@nkq6.onmicrosoft.com" #Exchange DistributionGroup which contains all users for which we want to export pst's
$SearchName="Members of $ExportDG"
#$PSTExportFolder="C:\git\thinBlog\pst ex import\Export\ExportedPSTs"
#$azcopypath="c:\temp\"

Connect-IPPSSession

#Ediscovery Case
$Case=New-compliancecase -Name $CaseName -CaseType eDiscovery -Description $CaseDescription
#EDiscovery Search within the case
$search=New-complianceSearch -Name $SearchName -Case $Case.Name -ExchangeLocation $ExportDG
#start the created search
start-ComplianceSearch -Identity $search.Name -force

#Wait until Search is completed. If you want to enable a max for the following look just uncmment the following both lines and the end of the until section
#$i=0
#$maxCounter=120
do {
    $search=get-compliancesearch -Identity $search.Name
    Start-Sleep -Seconds 10
    $i++    
} until (
    $search.status -eq 'completed' #(-OR $i -gt $maxCounter)
) 

#Preparing the PST Export
$ComplianceSearchAction=New-ComplianceSearchAction -SearchName $SearchName -Export -ExchangeArchiveFormat PerUserPst -IncludeCredential -FOrmat FxStream -scenario General

#doing the next step to contain the initial results which contain the sas key which we could use for downloading the exports via azcopy
$StoreInitialResults=$ComplianceSearchAction

#Wait until Export is completed. If you want to enable a max for the following look just uncmment the following both lines and the end of the until section
#$i=0
#$maxCounter=120
do {
    $ComplianceSearchAction=get-ComplianceSearchAction -Identity $ComplianceSearchAction.Identity
    Start-Sleep -Seconds 10
    $i++    
} until (
    $ComplianceSearchAction.status -eq 'completed' -OR $i -gt $maxCounter
)

<# Unfortunately from here on it's useless. I've tried to download to extract the Ediscovery Search Results via AZCopy to PST Files 
to get the max out of the automation, but i was't successfull. So you have to go to the compliance center manually and download the results manually :(.
If you know how to deal with .fs .meta files to create a pst file go on and use the following to download the results. 

$ResultsThatContainCreds=$StoreInitialResults.results.Split(';')
$SplitString=": "
$containerURL=([string]$ResultsThatContainCreds[0] -split $SplitString)[1]
$SasToken=([string]$ResultsThatContainCreds[1] -split $SplitString)[1]

Start-process -FilePath ($azcopypath+'azcopy.exe') -ArgumentList ('copy '+([string]$containerURL+[string]$sastoken)+' '+$PSTExportFolder+' --recursive') -Wait   
#>