# Script to combine datasets and remove duplicates

# Import both datasets
$dataset1 = Import-Csv -Path "d:\Trae\Datasets\dataset.csv"
$dataset2 = Import-Csv -Path "d:\Trae\Datasets\400 phising dataset.csv"

# Combine datasets
$combinedDataset = $dataset1 + $dataset2

# Remove duplicates based on URL
$uniqueDataset = $combinedDataset | Sort-Object -Property url -Unique

# Export combined dataset to a new CSV file
$uniqueDataset | Export-Csv -Path "d:\Trae\Datasets\combined_dataset.csv" -NoTypeInformation

# Count total entries
$totalCount = $uniqueDataset.Count

# Count phishing websites
$phishingCount = ($uniqueDataset | Where-Object { $_.is_phishing -eq '1' }).Count

# Count legitimate websites
$legitCount = ($uniqueDataset | Where-Object { $_.is_phishing -eq '0' }).Count

# Display results
Write-Host "Combined Dataset Statistics:"
Write-Host "---------------------------"
Write-Host "Total unique websites: $totalCount"
Write-Host "Phishing websites: $phishingCount"
Write-Host "Legitimate websites: $legitCount"

# Display counts from original datasets for verification
$dataset1Count = $dataset1.Count
$dataset2Count = $dataset2.Count
Write-Host "\nOriginal Dataset Statistics:"
Write-Host "---------------------------"
Write-Host "Dataset 1 count: $dataset1Count"
Write-Host "Dataset 2 count: $dataset2Count"
Write-Host "Total from original datasets: $($dataset1Count + $dataset2Count)"