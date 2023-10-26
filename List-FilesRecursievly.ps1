$sourceFolder = "C:\Code\AD" # Replace with the path to your folder
$outputCsv = "C:\Code\AD\List_files.csv" # Replace with the path to your desired CSV output file

# Retrieve file details
$files = Get-ChildItem -Path $sourceFolder -File -Recurse | Select-Object FullName, CreationTime, Length, Name, Extension

# Export details to a CSV
$files | Export-Csv -Path $outputCsv -NoTypeInformation

Write-Output "File details exported to $outputCsv"
