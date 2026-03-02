<#
.SYNOPSIS
    Patches a shipped JRE to include the FIPS Audit Provider module.

.DESCRIPTION
    Creates a new JRE image that includes the com.demo.fips.audit module
    and registers FipsAuditProvider at JCA position 1 in java.security.

    After patching, EVERY application using this JRE will automatically
    have FIPS audit enabled -- no -javaagent, no JAVA_TOOL_OPTIONS, no
    command-line arguments of any kind.

    This is the recommended approach for monolith applications where a
    C++ executable bootstraps the JVM via JNI (JNI_CreateJavaVM) and
    JAVA_TOOL_OPTIONS / -javaagent cannot be used reliably.

.PARAMETER JdkHome
    Path to a full JDK 21 installation (must contain jmods/ directory).
    This is the BUILD tool -- not necessarily the app's JRE.

.PARAMETER TargetJre
    Path to the application's shipped JRE that will be replaced.

.PARAMETER AuditJar
    Path to the compiled fips-audit-provider.jar (with module-info.class).

.PARAMETER BcfipsJar
    Path to the unmodified bc-fips-2.0.0.jar (or later). Optional.
    If provided, the JAR is copied into <JRE>/lib/fips/ so the audit
    provider can load it at runtime via URLClassLoader (Layer 1 - BCFIPS
    oracle). The JAR is NOT modified, preserving its FIPS self-integrity
    checksum.

.PARAMETER BackupSuffix
    Suffix for the backup of the original JRE (default: ".backup").

.EXAMPLE
    .\patch-jre.ps1 `
        -JdkHome   "C:\Program Files\Java\jdk-21" `
        -TargetJre "C:\MyApp\jre" `
        -AuditJar  "C:\repos\jfips\auditor_app\target\fips-audit-provider.jar" `
        -BcfipsJar "C:\repos\jfips\auditor_app\target\dependency\bc-fips-2.0.0.jar"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$JdkHome,

    [Parameter(Mandatory)]
    [string]$TargetJre,

    [Parameter(Mandatory)]
    [string]$AuditJar,

    [string]$BcfipsJar,

    [string]$BackupSuffix = ".backup"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Validate inputs ----------------------------------------------------------

$jlink    = Join-Path $JdkHome "bin\jlink.exe"
$jmod     = Join-Path $JdkHome "bin\jmod.exe"
$jmodsDir = Join-Path $JdkHome "jmods"

if (-not (Test-Path $jlink))    { throw "jlink not found at $jlink - is JdkHome a full JDK?" }
if (-not (Test-Path $jmodsDir)) { throw "jmods/ not found at $jmodsDir - is JdkHome a full JDK?" }
if (-not (Test-Path $TargetJre)){ throw "Target JRE not found at $TargetJre" }
if (-not (Test-Path $AuditJar)) { throw "Audit JAR not found at $AuditJar" }
if ($BcfipsJar -and -not (Test-Path $BcfipsJar)) { throw "BCFIPS JAR not found at $BcfipsJar" }

# Verify the JAR is modular (has module-info.class)
$jarTool = Join-Path $JdkHome "bin\jar.exe"
$moduleCheck = & $jarTool --describe-module --file=$AuditJar 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "JAR does not appear to be a modular JAR (no module-info.class). Build with: mvn clean package"
}
Write-Host "[patch-jre] Module descriptor: $moduleCheck" -ForegroundColor Cyan

# -- Discover modules in the target JRE ---------------------------------------

$javaExe = Join-Path $TargetJre "bin\java.exe"
if (-not (Test-Path $javaExe)) {
    throw "java.exe not found in target JRE at $javaExe"
}

Write-Host "[patch-jre] Discovering modules in target JRE..." -ForegroundColor Cyan
$existingModules = & $javaExe --list-modules 2>&1 |
    ForEach-Object { ($_ -split '@')[0].Trim() } |
    Where-Object { $_ -ne "" }

Write-Host "[patch-jre] Found $($existingModules.Count) modules in target JRE"

# -- Build new JRE image ------------------------------------------------------

$outputJre = "$TargetJre.new"
if (Test-Path $outputJre) {
    Write-Host "[patch-jre] Removing previous output directory: $outputJre" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $outputJre
}

$allModules = ($existingModules + "com.demo.fips.audit") -join ","

Write-Host "[patch-jre] Running jlink to build new JRE image..." -ForegroundColor Cyan
Write-Host "[patch-jre]   module-path: $jmodsDir;$AuditJar"
Write-Host "[patch-jre]   add-modules: $allModules"
Write-Host "[patch-jre]   output:      $outputJre"

& $jlink `
    --module-path "$jmodsDir;$AuditJar" `
    --add-modules $allModules `
    --output "$outputJre" `
    --no-header-files `
    --no-man-pages `
    --strip-debug

if ($LASTEXITCODE -ne 0) {
    throw "jlink failed with exit code $LASTEXITCODE"
}

Write-Host "[patch-jre] jlink completed successfully" -ForegroundColor Green

# -- Patch java.security in the new image -------------------------------------

$securityFile = Join-Path $outputJre "conf\security\java.security"
if (-not (Test-Path $securityFile)) {
    throw "java.security not found at $securityFile"
}

Write-Host "[patch-jre] Patching java.security to register FipsAuditProvider at position 1..." -ForegroundColor Cyan

$content = Get-Content $securityFile -Raw

# Find existing provider lines and renumber them (shift by 1)
$lines = $content -split "`n"
$newLines = [System.Collections.Generic.List[string]]::new()
$providerInserted = $false

foreach ($line in $lines) {
    if ($line -match '^\s*security\.provider\.(\d+)\s*=\s*(.+)') {
        $num = [int]$Matches[1]
        $providerClass = $Matches[2].Trim()

        # Insert our provider before the first existing one
        if (-not $providerInserted) {
            $newLines.Add("security.provider.1=com.demo.fips.audit.FipsAuditProvider")
            $providerInserted = $true
        }

        # Skip if somehow already registered
        if ($providerClass -eq "com.demo.fips.audit.FipsAuditProvider") {
            continue
        }

        # Renumber: shift by 1
        $newLines.Add("security.provider.$($num + 1)=$providerClass")
    } else {
        $newLines.Add($line)
    }
}

# If no providers existed yet (unlikely), add ours
if (-not $providerInserted) {
    $newLines.Add("")
    $newLines.Add("# FIPS Audit Provider - auto-registered by patch-jre.ps1")
    $newLines.Add("security.provider.1=com.demo.fips.audit.FipsAuditProvider")
}

$newContent = $newLines -join "`n"
Set-Content -Path $securityFile -Value $newContent -NoNewline -Encoding UTF8

Write-Host "[patch-jre] java.security updated" -ForegroundColor Green

# -- Copy bc-fips JAR into lib/fips/ (Layer 1 - BCFIPS oracle) ----------------

if ($BcfipsJar) {
    $fipsLibDir = Join-Path $outputJre "lib\fips"
    New-Item -ItemType Directory -Path $fipsLibDir -Force | Out-Null
    Copy-Item $BcfipsJar (Join-Path $fipsLibDir (Split-Path $BcfipsJar -Leaf))
    Write-Host "[patch-jre] Copied $(Split-Path $BcfipsJar -Leaf) to $fipsLibDir" -ForegroundColor Green
    Write-Host "[patch-jre] Layer 1 (BCFIPS oracle) will be available at runtime" -ForegroundColor Green
} else {
    Write-Host "[patch-jre] No -BcfipsJar specified - Layer 1 (BCFIPS oracle) disabled" -ForegroundColor Yellow
    Write-Host "[patch-jre] Only Layer 2 (policy-file rules) will be active" -ForegroundColor Yellow
}

# -- Copy fips-policy.properties into the JRE ---------------------------------

$policySource = Join-Path (Split-Path $AuditJar) "..\src\main\resources\fips-policy.properties"
if (-not (Test-Path $policySource)) {
    # Try relative to the script
    $policySource = Join-Path $PSScriptRoot "auditor_app\src\main\resources\fips-policy.properties"
}

if (Test-Path $policySource) {
    $policyDest = Join-Path $outputJre "conf\fips-policy.properties"
    Copy-Item $policySource $policyDest
    Write-Host "[patch-jre] Copied fips-policy.properties to $policyDest" -ForegroundColor Green
}

# -- Copy fips-audit.properties (configuration) into the JRE ------------------

$auditConfigSource = Join-Path (Split-Path $AuditJar) "..\src\main\resources\fips-audit.properties"
if (-not (Test-Path $auditConfigSource)) {
    $auditConfigSource = Join-Path $PSScriptRoot "auditor_app\src\main\resources\fips-audit.properties"
}

if (Test-Path $auditConfigSource) {
    $auditConfigDest = Join-Path $outputJre "conf\fips-audit.properties"
    Copy-Item $auditConfigSource $auditConfigDest
    Write-Host "[patch-jre] Copied fips-audit.properties to $auditConfigDest" -ForegroundColor Green
    Write-Host "[patch-jre] Edit this file to change log path, stack depth, etc." -ForegroundColor Cyan
}

# -- Swap: backup original, move new into place --------------------------------

$backupPath = "$TargetJre$BackupSuffix"
if (Test-Path $backupPath) {
    Write-Host "[patch-jre] Removing previous backup: $backupPath" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $backupPath
}

Write-Host "[patch-jre] Backing up original JRE: $TargetJre -> $backupPath" -ForegroundColor Cyan
Rename-Item $TargetJre $backupPath

Write-Host "[patch-jre] Installing patched JRE: $outputJre -> $TargetJre" -ForegroundColor Cyan
Rename-Item $outputJre $TargetJre

# -- Verify --------------------------------------------------------------------

$newJava = Join-Path $TargetJre "bin\java.exe"
$verifyModules = & $newJava --list-modules 2>&1
$hasAuditModule = $verifyModules | Where-Object { $_ -match "com\.demo\.fips\.audit" }

if ($hasAuditModule) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " SUCCESS: JRE patched with FIPS Audit"   -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Module:   com.demo.fips.audit"
    Write-Host "Provider: com.demo.fips.audit.FipsAuditProvider (position 1)"
    Write-Host "Original: $backupPath"
    Write-Host ""
    if ($BcfipsJar) {
        $bcName = Split-Path $BcfipsJar -Leaf
        Write-Host "BCFIPS:   lib\fips\$bcName (Layer 1 oracle)"
    } else {
        Write-Host "BCFIPS:   NOT included (Layer 2 policy-file rules only)"
    }
    Write-Host ""
    Write-Host "Every application using this JRE will now have FIPS auditing"
    Write-Host "enabled automatically - no arguments, no env vars needed."
    Write-Host ""
} else {
    Write-Host "[patch-jre] WARNING: Module verification failed!" -ForegroundColor Red
    Write-Host "[patch-jre] The module may not have been linked correctly."
    Write-Host "[patch-jre] Check: $newJava --list-modules" 
}
