<#
.SYNOPSIS
    Professional Windows Authenticode signing pipeline for jockey.exe.

.DESCRIPTION
    Signs jockey.exe using Authenticode with RFC3161 timestamping, verifies
    the resulting signature, and outputs cryptographic metadata. Supports CI
    secrets (JOCKEY_SIGNING_CERTIFICATE, JOCKEY_SIGNING_CERTIFICATE_PASSWORD,
    JOCKEY_TIMESTAMP_URL) without leaking credentials.

.PARAMETER ExePath
    Path to jockey.exe (default: target\release\jockey.exe)

.PARAMETER CertificateBase64
    Base64-encoded PFX certificate string.

.PARAMETER CertificatePath
    Path to PFX certificate file.

.PARAMETER CertificatePassword
    Password for the certificate.

.PARAMETER TimestampServer
    RFC3161 timestamp URL (default: http://timestamp.digicert.com)

.PARAMETER Mandatory
    If specified, signing must succeed or the script exits with non-zero code.
#>

[CmdletBinding()]
param(
    [string]$ExePath = "target\release\jockey.exe",
    [string]$CertificateBase64 = $env:JOCKEY_SIGNING_CERTIFICATE,
    [string]$CertificatePath = "",
    [string]$CertificatePassword = $env:JOCKEY_SIGNING_CERTIFICATE_PASSWORD,
    [string]$TimestampServer = $env:JOCKEY_TIMESTAMP_URL,
    [switch]$Mandatory = $false
)

$ErrorActionPreference = "Stop"

if (-not $TimestampServer) {
    $TimestampServer = "http://timestamp.digicert.com"
}

Write-Host "============================================================"
Write-Host "JOCKEY Windows Authenticode Release Signing Pipeline"
Write-Host "============================================================"

# 1. Locate and verify executable
if (-not (Test-Path $ExePath)) {
    Write-Error "Target executable not found: $ExePath"
    exit 1
}

$fullExePath = (Resolve-Path $ExePath).Path
$exeItem = Get-Item $fullExePath
$sha256 = (Get-FileHash -Path $fullExePath -Algorithm SHA256).Hash
Write-Host "Executable Path: $fullExePath"
Write-Host "File Size:       $($exeItem.Length) bytes"
Write-Host "Initial SHA-256: $sha256"

# 2. Check certificate availability
$hasCert = $false
$tempCertPath = ""

if ($CertificatePath -and (Test-Path $CertificatePath)) {
    $hasCert = $true
} elseif ($CertificateBase64 -and $CertificateBase64.Trim().Length -gt 0) {
    try {
        $certBytes = [Convert]::FromBase64String($CertificateBase64.Trim())
        $tempCertPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "jockey_signing_$([System.Guid]::NewGuid().ToString('N')).pfx")
        [System.IO.File]::WriteAllBytes($tempCertPath, $certBytes)
        $CertificatePath = $tempCertPath
        $hasCert = $true
    } catch {
        Write-Error "Failed to decode base64 signing certificate: $_"
        exit 1
    }
}

if (-not $hasCert) {
    if ($Mandatory) {
        Write-Error "MANDATORY signing failed: No signing certificate provided. Official release builds must be signed."
        exit 1
    } else {
        Write-Host "NOTICE: No signing certificate provided." -ForegroundColor Yellow
        Write-Host "Artifact: Development / Non-Release Unsigned Binary" -ForegroundColor Yellow
        Write-Host "SHA-256:  $sha256"
        Write-Host "Status:   UNSIGNED_DEVELOPMENT_BUILD" -ForegroundColor Yellow
        exit 0
    }
}

# 3. Perform Authenticode Signing
try {
    Write-Host "Signing executable with certificate..."
    $securePass = $null
    if ($CertificatePassword) {
        $securePass = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
    }

    $cert = $null
    if ($securePass) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $securePass, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    } else {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
    }

    Write-Host "Signing with RFC3161 Timestamp Server: $TimestampServer"
    $signResult = Set-AuthenticodeSignature -FilePath $fullExePath -Certificate $cert -TimestampServer $TimestampServer -HashAlgorithm SHA256

    if (-not $signResult) {
        throw "Set-AuthenticodeSignature returned null"
    }

    Write-Host "Sign Result Status: $($signResult.Status)"
} catch {
    Write-Error "Signing execution failed: $_"
    exit 1
} finally {
    # Clean up temp cert securely
    if ($tempCertPath -and (Test-Path $tempCertPath)) {
        Remove-Item -Path $tempCertPath -Force -ErrorAction SilentlyContinue
    }
}

# 4. Verify resulting Authenticode Signature
$signature = Get-AuthenticodeSignature -FilePath $fullExePath
$finalSha256 = (Get-FileHash -Path $fullExePath -Algorithm SHA256).Hash

Write-Host "------------------------------------------------------------"
Write-Host "Signature Verification:"
Write-Host "  Status:         $($signature.Status)"
Write-Host "  Status Message: $($signature.StatusMessage)"
if ($signature.SignerCertificate) {
    Write-Host "  Signer Subject: $($signature.SignerCertificate.Subject)"
    Write-Host "  Signer Issuer:  $($signature.SignerCertificate.Issuer)"
    Write-Host "  Valid From:     $($signature.SignerCertificate.NotBefore)"
    Write-Host "  Valid To:       $($signature.SignerCertificate.NotAfter)"
    Write-Host "  Thumbprint:     $($signature.SignerCertificate.Thumbprint)"
}
if ($signature.TimeStamperCertificate) {
    Write-Host "  Timestamp By:   $($signature.TimeStamperCertificate.Subject)"
}
Write-Host "  Final SHA-256:  $finalSha256"
Write-Host "------------------------------------------------------------"

if ($signature.Status -ne "Valid") {
    if ($Mandatory) {
        Write-Error "Authenticode signature validation failed with status: $($signature.Status) ($($signature.StatusMessage))"
        exit 1
    } else {
        Write-Warning "Signature status is $($signature.Status) (self-signed or untrusted root in dev environment)."
    }
} else {
    Write-Host "SUCCESS: Executable successfully signed and verified!" -ForegroundColor Green
}

# Return 0 on success
exit 0
