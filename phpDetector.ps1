
param(
    [Alias("h", "help")]
    [switch]$ShowHelp,

    [Alias("u")]
    [string]$Target,

    [ValidateSet("1", "2")]
    [string]$Level = "1"
)

$ErrorActionPreference = "Stop"

function Show-Usage {
@"
Usage:
  .\phpDetector.ps1 -h
  .\phpDetector.ps1 -u <URL|FILE> [-Level <1|2>]

Options:
  -h, -help       Show help menu
  -u <target>     Single URL or file containing URLs
  -Level <n>      Detection level (default: 1)

Detection levels:
  1  PHPSESSID and .php URL patterns
  2  Any occurrence of 'php' in headers or response body

Examples:
  .\phpDetector.ps1 -u https://example.com -Level 1
  .\phpDetector.ps1 -u webList.txt -Level 2
"@
}

# Handle help before target validation.
if ($ShowHelp) {
    Show-Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Target)) {
    Write-Host "Error: Specify a target using -u."
    Write-Host "Example: .\phpDetector.ps1 -u https://example.com -Level 1"
    exit 1
}

if ($Level -notin @("1", "2")) {
    Write-Host "Error: Level must be 1 or 2"
    Write-Host "Example: .\phpDetector.ps1 -u https://example.com -Level 1"
    exit 1
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Error: curl.exe is required."
    exit 1
}

if (Test-Path -LiteralPath $Target -PathType Leaf) {
    $Urls = Get-Content -LiteralPath $Target
}
else {
    $Urls = @($Target)
}

foreach ($Url in $Urls) {
    $Url = $Url.Trim()

    if ([string]::IsNullOrWhiteSpace($Url) -or $Url.StartsWith("#")) {
        continue
    }

    $HeadersFile = [System.IO.Path]::GetTempFileName()
    $BodyFile = [System.IO.Path]::GetTempFileName()

    try {
        & curl.exe -k -sS -L --max-time 20 `
            -D $HeadersFile `
            -o $BodyFile `
            $Url 2>$null

        if ($LASTEXITCODE -ne 0) {
            Write-Output "Scan failed: $Url"
            continue
        }

        $Headers = Get-Content -LiteralPath $HeadersFile -Raw
        $Body = Get-Content -LiteralPath $BodyFile -Raw
        $Content = "$Headers`n$Body"

        if ($Level -eq "1") {
            $Pattern = 'PHPSESSID|\.php([/?#"]|$)'
        }
        else {
            $Pattern = 'php'
        }

        if ($Content -match $Pattern) {
            Write-Output "PHP is detected on $Url"
        }
        else {
            Write-Output "PHP is not detected on $Url"
        }
    }
    catch {
        Write-Output "Scan failed: $Url"
    }
    finally {
        Remove-Item -LiteralPath $HeadersFile, $BodyFile `
            -Force -ErrorAction SilentlyContinue
    }
}
