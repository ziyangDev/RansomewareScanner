# ============================================================
# ransomware-cleanup.ps1
#  - PowerShell 7 + PnP.PowerShell (macOS OK)
#  - Default: scan ALL document libraries in each site
#  - Override: -LibraryTitle "Documents" to scan only one library
#  - Tenant mode: auto-discover all /sites via -admin endpoint
#  - Reports: per-site CSV + global CSV + run log
#  - Delete: unattended (no YES prompt). Still supports -WhatIf
# ============================================================

# ============================================================
# 使用方法（最常用的 4 条）
#
# 1）导入脚本（每次打开新的 pwsh 会话都要做一次）
# . ./ransomware-cleanup.ps1
#
# 2）全租户一键扫描（默认扫所有文档库，不删）
# Invoke-RansomwareCleanupTenant -SinceDays 7
#
# 3）全租户只扫某一个库（覆盖默认）
# Invoke-RansomwareCleanupTenant -SinceDays 7 -LibraryTitle "Documents"
#
# 4）全租户扫描并无人值守删除（不需要 YES）
# 强烈建议先用 -WhatIf 演练：
# Invoke-RansomwareCleanupTenant -SinceDays 7 -Delete -WhatIf
#
# 确认输出无误后再执行真实删除：
# Invoke-RansomwareCleanupTenant -SinceDays 7 -Delete
# ============================================================




# ===================== 配置区（请按你的环境修改） =====================
$Global:TenantName       = "xxx"  # for https://cstcoal.sharepoint.com/sites/$TenantName
$Global:ClientId         = "xxxx"  # Entra App Client ID
$Global:TenantIdOrDomain = "xxxx"  # Tenant ID

# 默认可疑扩展名（按你实际情况修改）
$Global:DefaultBadExt = @("luQjrLbhFZ")

# 报表输出目录（默认当前目录 reports）
$Global:ReportDir = Join-Path (Get-Location) "reports"

# 批量时节流（避免429）。0 表示不 sleep
$Global:ThrottleSecondsPerSite = 1
# =====================================================================


# ------------------ Helper: Ensure report dir ------------------
function Ensure-ReportDir {
    if (-not (Test-Path $Global:ReportDir)) {
        New-Item -ItemType Directory -Path $Global:ReportDir | Out-Null
    }
}

# ------------------ Helper: Connect to a SPO site ------------------
function Connect-SPOSitePnP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SiteUrl
    )
    Connect-PnPOnline -Url $SiteUrl -Interactive -ClientId $Global:ClientId -Tenant $Global:TenantIdOrDomain
}

# ------------------ Helper: List doc libraries in current site ------------------
function Get-DocumentLibraryTitles {
    [CmdletBinding()]
    param()
    Get-PnPList |
            Where-Object { $_.BaseType -eq "DocumentLibrary" -and -not $_.Hidden } |
            Select-Object -ExpandProperty Title
}

# ------------------ Core: Get suspicious files in ONE library ------------------
function Get-SuspiciousFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$LibraryTitle,
        [Parameter(Mandatory=$true)][int]$SinceDays,
        [Parameter(Mandatory=$true)][string[]]$BadExt
    )

    $since = (Get-Date).AddDays(-$SinceDays)

    # 只取需要字段
    $items = Get-PnPListItem `
    -List $LibraryTitle `
    -PageSize 2000 `
    -Fields "FileLeafRef","FileRef","Modified","FSObjType","Editor"

    # 构造扩展名正则：\.(a|b|c)$
    $regex = "\.(" + ($BadExt -join "|") + ")$"

    foreach ($i in $items) {
        if ($i["FSObjType"] -ne 0) { continue }  # 0=文件 1=文件夹

        $name = $i["FileLeafRef"]
        $ref  = $i["FileRef"]
        $mod  = [datetime]$i["Modified"]
        $ext  = ([IO.Path]::GetExtension($name)).TrimStart(".").ToLowerInvariant()

        $hit = ($mod -ge $since) -and (
        ($BadExt -contains $ext) -or
                ($name -match $regex)
        )

        if ($hit) {
            $editor = $null
            try { $editor = $i["Editor"].Email } catch {}

            [pscustomobject]@{
                Library  = $LibraryTitle
                Name     = $name
                Ext      = $ext
                Modified = $mod
                Editor   = $editor
                FileRef  = $ref
            }
        }
    }
}

# ------------------ Single site scan/delete ------------------
function Invoke-RansomwareCleanup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    # Operator 只输入 site name（/sites/ 后面的那段）
        [Parameter(Mandatory=$true)][string]$SiteName,

    # 最近多少天内修改的文件才纳入扫描
        [int]$SinceDays = 7,

    # 可疑扩展名
        [string[]]$BadExt = $Global:DefaultBadExt,

    # ✅ 推荐改法：不传 => 默认扫描所有文档库；传了 => 只扫该库
        [string]$LibraryTitle,

    # 不传：只扫描+报表；传了：删除（无人值守，不要 YES）
        [switch]$Delete
    )

    Ensure-ReportDir
    $stamp   = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $siteUrl = "https://$($Global:TenantName).sharepoint.com/sites/$SiteName"

    Write-Host "==> Connecting: $siteUrl"
    Connect-SPOSitePnP -SiteUrl $siteUrl

    # 默认：所有库；覆盖：指定库
    $libs = @()
    if ([string]::IsNullOrWhiteSpace($LibraryTitle)) {
        $libs = Get-DocumentLibraryTitles
    } else {
        $libs = @($LibraryTitle)
    }

    $siteResults = @()

    foreach ($lib in $libs) {
        Write-Host "==> Scanning library: $lib"
        try {
            $siteResults += Get-SuspiciousFiles -LibraryTitle $lib -SinceDays $SinceDays -BadExt $BadExt
        } catch {
            Write-Warning "Scan failed on library '$lib' : $($_.Exception.Message)"
        }
    }

    # 站点级 CSV（修复 SiteName 变量拼接问题：用 ${SiteName}）
    $siteCsvPath = Join-Path $Global:ReportDir "suspected_${SiteName}_${stamp}.csv"
    $siteResults | Sort-Object Modified -Descending | Export-Csv $siteCsvPath -NoTypeInformation

    Write-Host "==> Found $($siteResults.Count) suspicious files."
    Write-Host "==> Site report: $siteCsvPath"

    if (-not $Delete) {
        Write-Host "==> Dry-run only (no deletion). Re-run with -Delete to remove files."
        return $siteResults
    }

    if ($siteResults.Count -eq 0) {
        Write-Host "==> Nothing to delete."
        return $siteResults
    }

    Write-Host "==> Deleting $($siteResults.Count) files on site '$SiteName' (unattended)..."

    foreach ($r in $siteResults) {
        $target = $r.FileRef
        if ($PSCmdlet.ShouldProcess($target, "Remove-PnPFile")) {
            try {
                Remove-PnPFile -ServerRelativeUrl $r.FileRef -Force -Confirm:$false
                Write-Host "Deleted: $($r.FileRef)"
            } catch {
                Write-Warning "FAILED delete: $($r.FileRef) -- $($_.Exception.Message)"
            }
        }
    }

    Write-Host "==> Deletion completed for site '$SiteName'."
    return $siteResults
}

# ------------------ Tenant-wide: discover all /sites and scan/delete ------------------
function Invoke-RansomwareCleanupTenant {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [int]$SinceDays = 7,
        [string[]]$BadExt = $Global:DefaultBadExt,

    # ✅ 推荐改法：不传 => 默认扫描所有文档库；传了 => 只扫该库
        [string]$LibraryTitle,

    # 不传：只扫描+报表；传了：删除（无人值守，不要 YES）
        [switch]$Delete,

    # 全局汇总 CSV 输出路径（不传就放 reports 里）
        [string]$GlobalReportPath
    )

    Ensure-ReportDir
    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")

    if (-not $GlobalReportPath) {
        $GlobalReportPath = Join-Path $Global:ReportDir "suspected_TENANT_${stamp}.csv"
    }

    $runLogPath = Join-Path $Global:ReportDir "tenant_runlog_${stamp}.txt"
    "Run started: $(Get-Date)" | Out-File -FilePath $runLogPath -Encoding utf8

    # 1) 连接 Admin Center 拉取所有 /sites
    $adminUrl = "https://$($Global:TenantName)-admin.sharepoint.com"
    Write-Host "==> Connecting Admin Center: $adminUrl"
    Connect-PnPOnline -Url $adminUrl -Interactive -ClientId $Global:ClientId -Tenant $Global:TenantIdOrDomain

    Write-Host "==> Discovering all /sites..."
    try {
        $siteUrls = Get-PnPTenantSite -IncludeOneDriveSites:$false |
                Where-Object { $_.Url -match "/sites/" } |
                Select-Object -ExpandProperty Url
    } catch {
        throw "Failed to list tenant sites from admin center. Error: $($_.Exception.Message)"
    }

    $siteNames = foreach ($u in $siteUrls) {
        ($u -split "/sites/")[-1].TrimEnd("/")
    }

    Write-Host "==> Found $($siteNames.Count) sites under /sites."

    # 2) 逐站扫描（并汇总）
    $globalResults = @()

    foreach ($sn in $siteNames) {
        Write-Host ""
        Write-Host "==================== $sn ===================="

        if ($Global:ThrottleSecondsPerSite -gt 0) {
            Start-Sleep -Seconds $Global:ThrottleSecondsPerSite
        }

        try {
            $siteUrl = "https://$($Global:TenantName).sharepoint.com/sites/$sn"
            Connect-SPOSitePnP -SiteUrl $siteUrl

            # 默认：所有库；覆盖：指定库
            $libs = @()
            if ([string]::IsNullOrWhiteSpace($LibraryTitle)) {
                $libs = Get-DocumentLibraryTitles
            } else {
                $libs = @($LibraryTitle)
            }

            $siteResults = @()
            foreach ($lib in $libs) {
                Write-Host "==> Scanning library: $lib"
                try {
                    $siteResults += Get-SuspiciousFiles -LibraryTitle $lib -SinceDays $SinceDays -BadExt $BadExt
                } catch {
                    Write-Warning "Scan failed on library '$lib' : $($_.Exception.Message)"
                    "[$sn] Scan failed library '$lib' : $($_.Exception.Message)" | Out-File -FilePath $runLogPath -Append -Encoding utf8
                }
            }

            # 每站 CSV
            $siteCsv = Join-Path $Global:ReportDir "suspected_${sn}_${stamp}.csv"
            $siteResults | Sort-Object Modified -Descending | Export-Csv $siteCsv -NoTypeInformation
            Write-Host "==> Site suspicious: $($siteResults.Count). Report: $siteCsv"

            # 加入全局汇总（加 SiteName 字段）
            $globalResults += ($siteResults | ForEach-Object {
                [pscustomobject]@{
                    SiteName = $sn
                    Library  = $_.Library
                    Name     = $_.Name
                    Ext      = $_.Ext
                    Modified = $_.Modified
                    Editor   = $_.Editor
                    FileRef  = $_.FileRef
                }
            })

            # 删除（无人值守：不再 Read-Host）
            if ($Delete -and $siteResults.Count -gt 0) {
                Write-Host "==> Deleting $($siteResults.Count) files on site '$sn' (unattended)..."

                foreach ($r in $siteResults) {
                    $target = $r.FileRef
                    if ($PSCmdlet.ShouldProcess($target, "Remove-PnPFile")) {
                        try {
                            Remove-PnPFile -ServerRelativeUrl $r.FileRef -Force -Confirm:$false
                            Write-Host "Deleted: $($r.FileRef)"
                        } catch {
                            Write-Warning "FAILED delete: $($r.FileRef) -- $($_.Exception.Message)"
                            "[$sn] FAILED delete $($r.FileRef) -- $($_.Exception.Message)" | Out-File -FilePath $runLogPath -Append -Encoding utf8
                        }
                    }
                }
            }

        } catch {
            Write-Warning "Site failed: $sn -- $($_.Exception.Message)"
            "[$sn] Site failed: $($_.Exception.Message)" | Out-File -FilePath $runLogPath -Append -Encoding utf8
            continue
        }
    }

    # 3) 输出全局汇总 CSV
    $globalResults | Sort-Object Modified -Descending | Export-Csv $GlobalReportPath -NoTypeInformation

    Write-Host ""
    Write-Host "==> TENANT scan completed. Total suspicious files: $($globalResults.Count)"
    Write-Host "==> Global report: $GlobalReportPath"
    Write-Host "==> Run log: $runLogPath"

    return $globalResults
}
