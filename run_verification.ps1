# ZScope Docker Linux Verification Script for Windows
# Run this script from PowerShell to verify ZScope in a Linux container

param(
    [switch]$Build,
    [switch]$Clean,
    [string]$ApiKey = "",
    [string]$BaseUrl = "https://api.openai.com/v1",
    [string]$Model = "gpt-4"
)

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "ZScope Docker Linux Verification" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory if it doesn't exist
$outputDir = Join-Path $PSScriptRoot "output"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Green
}

# Clean up if requested
if ($Clean) {
    Write-Host "Cleaning up Docker resources..." -ForegroundColor Yellow
    docker-compose down -v 2>$null
    if (Test-Path $outputDir) {
        Remove-Item -Path "$outputDir\*" -Recurse -Force
        Write-Host "Cleaned output directory" -ForegroundColor Green
    }
    Write-Host "Cleanup complete!" -ForegroundColor Green
    exit 0
}

# Build Docker image if requested or if it doesn't exist
$imageExists = docker images -q zscope-linux:latest
if ($Build -or -not $imageExists) {
    Write-Host "Building Docker image..." -ForegroundColor Yellow
    docker-compose build
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Docker build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "Docker image built successfully!" -ForegroundColor Green
    Write-Host ""
}

# Prepare environment variables
$env:OPENAI_API_KEY = $ApiKey
$env:OPENAI_BASE_URL = $BaseUrl
$env:OPENAI_MODEL = $Model

# Run verification
Write-Host "Running verification in Linux container..." -ForegroundColor Yellow
Write-Host ""

if ($ApiKey) {
    Write-Host "Using provided API credentials for full analysis" -ForegroundColor Green
} else {
    Write-Host "No API key provided - running basic verification only" -ForegroundColor Yellow
    Write-Host "To run full analysis, use: .\run_verification.ps1 -ApiKey 'your-key-here'" -ForegroundColor Yellow
}
Write-Host ""

# Run the verification script
docker-compose run --rm zscope bash /app/verify_linux.sh

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host "Verification completed successfully!" -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output files are available in: $outputDir" -ForegroundColor Cyan
    
    # List output files
    if (Test-Path $outputDir) {
        $files = Get-ChildItem -Path $outputDir -Recurse -File
        if ($files) {
            Write-Host "Generated files:" -ForegroundColor Cyan
            foreach ($file in $files) {
                $relativePath = $file.FullName.Substring($outputDir.Length + 1)
                Write-Host "  - $relativePath" -ForegroundColor White
            }
        }
    }
} else {
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Red
    Write-Host "Verification failed!" -ForegroundColor Red
    Write-Host "=======================================" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Additional commands:" -ForegroundColor Cyan
Write-Host "  - Interactive shell:  docker-compose run --rm zscope bash" -ForegroundColor White
Write-Host "  - View logs:          docker-compose logs" -ForegroundColor White
Write-Host "  - Rebuild:            .\run_verification.ps1 -Build" -ForegroundColor White
Write-Host "  - Clean up:           .\run_verification.ps1 -Clean" -ForegroundColor White
Write-Host ""
