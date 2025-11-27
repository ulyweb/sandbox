param(
    [switch]$launchingSandbox
)
$ErrorActionPreference = 'Continue' # Use Continue to attempt all installations

Write-Host "Starting winget installation of Google Chrome..."
Write-Host "This process may take a few minutes."

# Run winget with verbose output to ensure it runs correctly and can be monitored
& winget install --id Google.Chrome --silent --accept-source-agreements --exact -e -Scope machine
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Google Chrome installation failed with exit code $LASTEXITCODE."
} else {
    Write-Host "Google Chrome installed successfully."
}

Write-Host "Installation script complete."
Start-Sleep -Seconds 5 # Give time to read the output before the window closes
