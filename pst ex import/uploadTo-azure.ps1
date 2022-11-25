# Upload PST Files to Azure Blob Storage
# Run this in a regular powershell

<# preparation of files
$targetUPNDomain="@jsflab.com"
$pstRootPath="C:\git\thinBlog\pst ex import\Export\ExportedPSTs"
$folders=get-childitem -Path $pstRootPath -Directory
foreach ($folder in $folders){
    Rename-Item -Path $($folder.FullName) -NewName ($($folder.Name).Split('@')[0]+$targetUPNDomain)
}
#>

#Load Global "Settings"
$PSTExportFolder="C:\git\thinBlog\pst ex import\Export\ExportedPSTs"
$azcopypath="C:\git\thinBlog\pst ex import\azcopy\"
$containerURL="https://scalablepstimport.blob.core.windows.net/pstimport"
$sastoken="?sp=racw&st=2022-11-25T09:23:18Z..."

#upload items


#Copy PST´s of the users to Azure Blob
$sourcepaths=Get-ChildItem -Path $PSTExportFolder -Directory
$uploadFailed=@()
foreach ($sourcepath in $sourcepaths){
    try {
        Start-process -FilePath ($azcopypath+'azcopy.exe') -ArgumentList ('copy "'+$sourcepath.fullname+'" "'+([string]$containerURL+[string]$sastoken)+'" --recursive') -Wait   
        Write-Host -ForegroundColor Gray -Object "INFO: Processing $($sourcePath.Name) finished"
    }
    catch {
        $uploadFailed+=$sourcepath
        Write-Host -ForegroundColor Red -Object "ERROR: Processing $($sourcePath.Name) failed"
    }
}
