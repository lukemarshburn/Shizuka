# SPDX-License-Identifier: GPL-2.0-only
# Copies the unmodified stock Bluetooth files a native backend port needs from a
# connected phone into inputs/<model>-<build>/ (git-ignored), with device-side and
# local SHA-256 digests. Read-only on the phone except a temporary copy under
# /data/local/tmp when a file is only readable as root.
#
# Usage:  powershell -ExecutionPolicy Bypass -File tools\pull_stock_inputs.ps1 [-Serial <id>]
param([string]$Serial = '')

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Find-Adb {
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $winget = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools"
    foreach ($dir in @($winget, "$env:LOCALAPPDATA\Android\Sdk\platform-tools", "$env:ANDROID_SDK_ROOT\platform-tools", "$env:ANDROID_HOME\platform-tools")) {
        if ($dir -and (Test-Path "$dir\adb.exe")) { return "$dir\adb.exe" }
    }
    throw 'adb not found. Install Android platform-tools (e.g. winget install Google.PlatformTools) and reopen the terminal.'
}

$adb = Find-Adb
$base = @()
if ($Serial) { $base = @('-s', $Serial) }

function Invoke-Adb([string[]]$a) {
    $out = & $adb @base @a
    return @{ Code = $LASTEXITCODE; Out = ($out -join "`n").Trim() }
}
function Invoke-Sh([string]$cmd) { (Invoke-Adb @('shell', $cmd)).Out }

$devices = (& $adb devices) | Select-Object -Skip 1 | Where-Object { $_ -match "`tdevice$" }
if (-not $Serial -and @($devices).Count -ne 1) {
    throw "Expected exactly one authorized device, found $(@($devices).Count). Enable USB debugging, accept the prompt on the phone, or pass -Serial."
}

$props = [ordered]@{}
foreach ($p in 'ro.product.model', 'ro.product.device', 'ro.build.PDA', 'ro.build.display.id',
               'ro.build.fingerprint', 'ro.build.version.release', 'ro.build.version.sdk',
               'ro.board.platform', 'ro.soc.model', 'ro.hardware', 'ro.product.cpu.abi',
               'persist.bluetooth.a2dp_offload.cap', 'ro.bluetooth.a2dp_offload.supported') {
    $props[$p] = Invoke-Sh "getprop $p"
}
$model = $props['ro.product.model'] -replace '[^A-Za-z0-9]', ''
$build = $props['ro.build.PDA'] -replace '[^A-Za-z0-9]', ''
if (-not $model) { throw 'Could not read the device model.' }
if (-not $build) { $build = 'unknown' }
Write-Host "Device: $($props['ro.product.model']) build $($props['ro.build.PDA']) ($($props['ro.soc.model']))"

$hasRoot = (Invoke-Sh 'su -c id 2>/dev/null') -match 'uid=0'
if (-not $hasRoot) { Write-Warning 'Root not available (or su was denied on the phone). Root-only files will be skipped.' }

# Same roles as profiles/samsung-sm-s931z-dzif/profile.json; the APK folder is versioned per build.
$apk = Invoke-Sh 'ls -d /apex/com.android.bt/app/Bluetooth*/Bluetooth.apk 2>/dev/null | head -n 1'
$wanted = [ordered]@{
    '/apex/com.android.bt/lib64/libbluetooth_jni.so'            = 'required'
    '/vendor/lib64/btaudio_offload_if.so'                       = 'required'
    '/apex/com.android.bt/javalib/framework-bluetooth.jar'      = 'required'
    '/vendor/dsp/adsp/aptx_adaptive_enc_module.so.1'            = 'optional'
    # Audio-session HAL: Samsung's SEH build on DZIF; newer SoCs (e.g. SM8850) ship only the Qualcomm ones.
    '/vendor/lib64/libsehbluetooth_audio_session_aidl.so'       = 'hal'
    '/vendor/lib64/libbluetooth_audio_session_aidl.so'          = 'hal'
    '/vendor/lib64/libbluetooth_audio_session_aidl_qti.so'      = 'hal'
    '/vendor/lib64/android.hardware.bluetooth.audio-impl.so'    = 'optional'
    '/vendor/lib64/lib_bt_aptx.so'                              = 'optional'
}
if ($apk) { $wanted[$apk] = 'required' } else { Write-Warning 'Bluetooth.apk not found under /apex/com.android.bt/app/.' }

# Names may differ on a newer SoC: record every Bluetooth/aptX-looking vendor/APEX library for review.
# Windows PowerShell 5.1 drops embedded double quotes when calling adb, so remote commands use single quotes only.
$listing = Invoke-Sh 'ls -l /vendor/lib64 /apex/com.android.bt/lib64 /vendor/dsp/adsp /vendor/firmware 2>/dev/null | grep -iE ''bluetooth|btaudio|aptx|a2dp|hmt|bt_'''

$dest = Join-Path $repo "inputs\$model-$build"
New-Item -ItemType Directory -Force $dest | Out-Null
$tmp = '/data/local/tmp/shizuka-pull'
$records = @()

foreach ($path in $wanted.Keys) {
    $name = Split-Path $path -Leaf
    $local = Join-Path $dest $name
    $exists = Invoke-Sh "[ -e '$path' ] && echo yes"
    if ($exists -ne 'yes' -and $hasRoot) { $exists = Invoke-Sh "su -c '[ -e $path ] && echo yes'" }
    if ($exists -ne 'yes') {
        Write-Warning "missing ($($wanted[$path])): $path"
        $records += [ordered]@{ path = $path; role = $wanted[$path]; status = 'missing' }
        continue
    }
    $r = Invoke-Adb @('pull', $path, $local)
    $via = 'adb'
    if ($r.Code -ne 0 -and $hasRoot) {
        Invoke-Sh "su -c 'mkdir -p $tmp && cp $path $tmp/$name && chmod 644 $tmp/$name'" | Out-Null
        $r = Invoke-Adb @('pull', "$tmp/$name", $local)
        $via = 'root-copy'
    }
    if ($r.Code -ne 0) {
        Write-Warning "could not pull: $path"
        $records += [ordered]@{ path = $path; role = $wanted[$path]; status = 'unreadable' }
        continue
    }
    $remote = Invoke-Sh "sha256sum '$path' 2>/dev/null"
    if (-not $remote -and $hasRoot) { $remote = Invoke-Sh "su -c 'sha256sum $path'" }
    $remote = ($remote -split '\s+')[0]
    $sha = (Get-FileHash -Algorithm SHA256 $local).Hash.ToLower()
    $ok = ($remote -eq $sha)
    if (-not $ok) { Write-Warning "digest mismatch for $path (device $remote, local $sha)" }
    Write-Host ("pulled {0,-45} {1}" -f $name, $sha)
    $records += [ordered]@{ path = $path; local_file = $name; role = $wanted[$path]; sha256 = $sha;
                            device_sha256 = $remote; digest_match = $ok; via = $via; status = 'ok' }
}
if ($hasRoot) { Invoke-Sh "su -c 'rm -rf $tmp'" | Out-Null }

$manifest = [ordered]@{ schema = 1; collected = (Get-Date).ToString('o'); properties = $props; files = $records }
$manifest | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 (Join-Path $dest 'collected.json')
$listing | Out-File -Encoding utf8 (Join-Path $dest 'bluetooth-libraries.txt')

$missing = @($records | Where-Object { $_.role -eq 'required' -and $_.status -ne 'ok' }).Count
if (-not @($records | Where-Object { $_.role -eq 'hal' -and $_.status -eq 'ok' }).Count) {
    Write-Warning 'No Bluetooth audio-session HAL library was collected.'; $missing++
}
Write-Host "`nSaved to $dest"
if ($missing) { Write-Warning "$missing required file(s) not collected; see collected.json and bluetooth-libraries.txt."; exit 1 }
