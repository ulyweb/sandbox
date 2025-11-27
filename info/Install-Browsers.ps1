param(
    [switch]$launchingSandbox
)
# Set the preference to continue so one failure doesn't stop the others.
$ErrorActionPreference = 'Continue' 

$BrowserList = @(
    @{ Id = 'Google.Chrome'; Name = 'Google Chrome' }
    @{ Id = 'Brave.Brave'; Name = 'Brave Browser' }
    @{ Id = 'Mozilla.Firefox'; Name = 'Mozilla Firefox' }
)

Write-Host "Starting silent installation of required web browsers via winget..."
Write-Host "This process may take several minutes."

foreach ($Browser in $BrowserList) {
    Write-Host "Installing $($Browser.Name) (ID: $($Browser.Id))..."
    
    # Run winget with the corrected --scope flag and necessary options
    & winget install --id $($Browser.Id) --silent --accept-source-agreements --exact -e --scope machine
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$($Browser.Name) installation failed with exit code $LASTEXITCODE."
    } else {
        Write-Host "$($Browser.Name) installed successfully."
    }
}

Write-Host "`nAll browser installation attempts complete."
Start-Sleep -Seconds 5 # Give time to read the output before the window closes
