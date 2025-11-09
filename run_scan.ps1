# --- Paths / defaults ---
$JAR = "target\api-security-scanner-1.0-SNAPSHOT.jar"

# --- Clear credentials to force re-entry ---
Remove-Item Env:CLIENT_ID -ErrorAction SilentlyContinue
Remove-Item Env:CLIENT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:BANK_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:REQUESTING_BANK -ErrorAction SilentlyContinue
Remove-Item Env:INTERBANK_CLIENT -ErrorAction SilentlyContinue
Remove-Item Env:SELECTED_BANK -ErrorAction SilentlyContinue

# --- Load scanner.env if exists ---
if (Test-Path "scanner.env") {
    Write-Host "Loading scanner.env..."
    Get-Content "scanner.env" | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            $name = $matches[1]
            $value = $matches[2]
            Set-Item -Path "env:$name" -Value $value
        }
    }
}

# --- Bank selection ---
if (-not $env:SELECTED_BANK) {
    Write-Host "Select bank:"
    Write-Host "1 - Virtual Bank (vbank)"
    Write-Host "2 - Awesome Bank (abank)" 
    Write-Host "3 - Smart Bank (sbank)"
    $bankChoice = Read-Host "Enter choice (1-3)"
    
    switch ($bankChoice) {
        "1" { $env:SELECTED_BANK = "vbank" }
        "2" { $env:SELECTED_BANK = "abank" }
        "3" { $env:SELECTED_BANK = "sbank" }
        default { 
            Write-Error "Invalid choice. Using Virtual Bank as default."
            $env:SELECTED_BANK = "vbank"
        }
    }
}

# --- Set URLs based on selected bank ---
$OPENAPI = "https://$env:SELECTED_BANK.open.bankingapi.ru/openapi.json"
$BASEURL = "https://$env:SELECTED_BANK.open.bankingapi.ru"

Write-Host "Selected bank: $env:SELECTED_BANK"
Write-Host "OpenAPI: $OPENAPI"
Write-Host "Base URL: $BASEURL"

# --- If CLIENT_ID or CLIENT_SECRET missing, prompt ---
if (-not $env:CLIENT_ID) {
    $env:CLIENT_ID = Read-Host "Enter CLIENT_ID"
}

if (-not $env:CLIENT_SECRET) {
    Write-Host "Enter CLIENT_SECRET: " -NoNewline
    $secureSecret = Read-Host -AsSecureString
    # Правильное преобразование SecureString в plain text
    $env:CLIENT_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret))
}

# --- Request additional fields if missing ---
if (-not $env:REQUESTING_BANK) {
    $env:REQUESTING_BANK = Read-Host "Enter REQUESTING_BANK (default: team184)"
    if (-not $env:REQUESTING_BANK) { $env:REQUESTING_BANK = "team184" }
}

# --- Client number selection ---
if (-not $env:INTERBANK_CLIENT) {
    Write-Host "Select client number (1-10):"
    for ($i = 1; $i -le 10; $i++) {
        Write-Host "$i - $env:REQUESTING_BANK-$i"
    }
    $clientNumber = Read-Host "Enter client number (1-10)"
    
    if ($clientNumber -match "^\d+$" -and [int]$clientNumber -ge 1 -and [int]$clientNumber -le 10) {
        $env:INTERBANK_CLIENT = "$env:REQUESTING_BANK-$clientNumber"
    } else {
        Write-Error "Invalid client number. Using $env:REQUESTING_BANK-1 as default."
        $env:INTERBANK_CLIENT = "$env:REQUESTING_BANK-1"
    }
}

# --- Ensure we have required values ---
if (-not $env:CLIENT_ID) {
    Write-Error "ERROR: CLIENT_ID is required."
    pause
    exit 1
}

if (-not $env:CLIENT_SECRET) {
    Write-Error "ERROR: CLIENT_SECRET is required."
    pause
    exit 1
}

# --- Create scanner.env if it doesn't exist ---
if (-not (Test-Path "scanner.env")) {
    Write-Host "Creating scanner.env..."
    @"
SELECTED_BANK=$env:SELECTED_BANK
CLIENT_ID=$env:CLIENT_ID
CLIENT_SECRET=$env:CLIENT_SECRET
REQUESTING_BANK=$env:REQUESTING_BANK
INTERBANK_CLIENT=$env:INTERBANK_CLIENT
"@ | Out-File -FilePath "scanner.env" -Encoding ASCII
    
    Write-Host "scanner.env created with values:"
    Write-Host "SELECTED_BANK: $env:SELECTED_BANK"
    Write-Host "CLIENT_ID: $env:CLIENT_ID"
    Write-Host "REQUESTING_BANK: $env:REQUESTING_BANK" 
    Write-Host "INTERBANK_CLIENT: $env:INTERBANK_CLIENT"
}

# --- Obtain BANK_TOKEN if not set ---
if (-not $env:BANK_TOKEN) {
    Write-Host "Getting BANK_TOKEN..."
    try {
        $uri = "$BASEURL/auth/bank-token?client_id=$env:CLIENT_ID&client_secret=$env:CLIENT_SECRET"
        Write-Host "Request URL: $uri"
        $tokenResponse = Invoke-RestMethod -Method POST -Uri $uri
        $env:BANK_TOKEN = $tokenResponse.access_token
        Write-Host "BANK_TOKEN obtained successfully"
    } catch {
        Write-Error "Failed to obtain BANK_TOKEN: $_"
        Write-Host "Please check your CLIENT_ID and CLIENT_SECRET"
        pause
        exit 1
    }
}

# --- Set report title based on selected bank ---
$BANK_NAMES = @{
    "vbank" = "Virtual Bank"
    "abank" = "Awesome Bank" 
    "sbank" = "Smart Bank"
}
$REPORT_TITLE = "$($BANK_NAMES[$env:SELECTED_BANK]) API Security Report"

# --- Run scanner ---
Write-Host "Running scanner for $($BANK_NAMES[$env:SELECTED_BANK])..."
java -jar "$JAR" --openapi $OPENAPI --base-url $BASEURL --auth "bearer:$env:BANK_TOKEN" --requesting-bank $env:REQUESTING_BANK --client $env:INTERBANK_CLIENT --create-consent true --verbose

Write-Host "`nReports: reports\"
Write-Host "Note: Reports are saved in 'reports' folder and preserved between builds"
pause