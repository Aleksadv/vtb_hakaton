# --- Paths / defaults ---
$JAR = "target\api-security-scanner-1.0-SNAPSHOT.jar"
$OPENAPI = "https://vbank.open.bankingapi.ru/openapi.json"
$BASEURL = "https://vbank.open.bankingapi.ru"

# --- Clear credentials to force re-entry ---
Remove-Item Env:CLIENT_ID -ErrorAction SilentlyContinue
Remove-Item Env:CLIENT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:BANK_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:REQUESTING_BANK -ErrorAction SilentlyContinue
Remove-Item Env:INTERBANK_CLIENT -ErrorAction SilentlyContinue

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

if (-not $env:INTERBANK_CLIENT) {
    $env:INTERBANK_CLIENT = Read-Host "Enter INTERBANK_CLIENT (default: team184-1)" 
    if (-not $env:INTERBANK_CLIENT) { $env:INTERBANK_CLIENT = "team184-1" }
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
CLIENT_ID=$env:CLIENT_ID
CLIENT_SECRET=$env:CLIENT_SECRET
REQUESTING_BANK=$env:REQUESTING_BANK
INTERBANK_CLIENT=$env:INTERBANK_CLIENT
"@ | Out-File -FilePath "scanner.env" -Encoding ASCII
    
    Write-Host "scanner.env created with values:"
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

# --- Run scanner ---
Write-Host "Running scanner..."
java -jar "$JAR" --openapi $OPENAPI --base-url $BASEURL --auth "bearer:$env:BANK_TOKEN" --requesting-bank $env:REQUESTING_BANK --client $env:INTERBANK_CLIENT --create-consent true --verbose

Write-Host "`nReports: target\reports\"
pause