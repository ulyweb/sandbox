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
    
    # Corrected: Using the --scope flag
    & winget install --id $($Browser.Id) --silent --accept-source-agreements --exact -e --scope machine --force
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$($Browser.Name) installation failed with exit code $LASTEXITCODE."
    } else {
        Write-Host "$($Browser.Name) installed successfully."
    }
}

Write-Host "`nAll browser installation attempts complete."
# This closes the PowerShell window for the browser installation script.
Exit
