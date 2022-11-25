$PSTExportFolder="C:\git\thinBlog\pst ex import\Export\ExportedPSTs"
$PSTImportMappingTableReport="C:\git\thinBlog\pst ex import\PSTImportMappingTableReport.csv"
$SourceDomain="nkq6.onmicrosoft.com"
$DestinationDomain="jsflab.com"

$PSTImportMappingTable = @()
$FolderstoProcess = Get-ChildItem -Path $PSTExportFolder -Directory
foreach ($folder in $FolderstoProcess) {
    $PSTsinFolder = Get-ChildItem -Path $folder.FullName -Depth 0 -Include "*.pst"
    foreach ($pst in $PSTsinFolder) {
        $PSTImportMappingTable += ([pscustomobject]@{SourceUserPrincipalName = $folder.Name.Replace($DestinationDomain, $SourceDomain); DestinationUserPrincipalName = $folder.Name.Replace($SourceDomain,$DestinationDomain); PSTName = ($pst.Name); PSTCount = $PSTsinFolder.count })    
    }
}

$PSTImportMappingTable | export-csv $PSTImportMappingTableReport -Delimiter ';' -Encoding unicode -NoTypeInformation -Force