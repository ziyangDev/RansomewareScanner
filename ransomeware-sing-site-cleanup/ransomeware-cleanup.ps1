# ===================== 配置区（请按你的环境修改） =====================
$Global:TenantName = "xxxx"  # for https://cstcoal.sharepoint.com/sites/$TenantName
$Global:ClientId   = "xxxx"  # Entra Appplication Client ID
$Global:TenantId = "xxxxxx"       # Tenant ID

# 默认库名
$Global:DefaultLibraryTitle = "Documents"

# 默认可疑扩展名
$Global:DefaultBadExt = @("luQjrLbhFZ")

# CSV 输出目录（默认当前目录下 reports）
$Global:ReportDir = Join-Path (Get-Location) "reports"
# =====================================================================

function Connect-SPOSitePnP {
    param(
        [Parameter(Mandatory=$true)][string]$SiteUrl
    )

    Connect-PnPOnline -Url $SiteUrl -Interactive -ClientId $Global:ClientId -Tenant $Global:TenantId
}

function Get-SuspiciousFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$LibraryTitle,
        [Parameter(Mandatory=$true)][int]$SinceDays,
        [Parameter(Mandatory=$true)][string[]]$BadExt
    )

    $since = (Get-Date).AddDays(-$SinceDays)

    $items = Get-PnPListItem -List $LibraryTitle -PageSize 2000 -Fields "FileLeafRef","FileRef","Modified","FSObjType","Editor"

    foreach ($i in $items) {
        if ($i["FSObjType"] -ne 0) { continue } # 0=文件

        $name = $i["FileLeafRef"]
        $ref  = $i["FileRef"]
        $mod  = [datetime]$i["Modified"]
        $ext  = ([IO.Path]::GetExtension($name)).TrimStart(".").ToLowerInvariant()

        # 命中条件：最近 N 天 +（扩展名在列表 或 文件名以这些扩展结尾）
        $regex = "\.(" + ($BadExt -join "|") + ")$"
        $hit = ($mod -ge $since) -and ( ($BadExt -contains $ext) -or ($name -match $regex) )

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

function Invoke-RansomwareCleanup {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    # Operator 只要输入 site name（sites/ 后面的那段），例如 Finance
        [Parameter(Mandatory=$true)][string]$SiteName,

    # 最近多少天内修改的文件才纳入扫描（避免误伤）
        [int]$SinceDays = 7,

    # 可疑扩展名
        [string[]]$BadExt = $Global:DefaultBadExt,

    # 扫描单个库（默认）还是全站所有文档库
        [switch]$AllLibraries,

    # 如果不传 -Delete：只扫描+出报告；传了才会删除
        [switch]$Delete
    )

    if (-not (Test-Path $Global:ReportDir)) { New-Item -ItemType Directory -Path $Global:ReportDir | Out-Null }

    $siteUrl = "https://$($Global:TenantName).sharepoint.com/sites/$SiteName"
    Write-Host "==> Connecting: $siteUrl"
    Connect-SPOSitePnP -SiteUrl $siteUrl

    $libs = @()
    if ($AllLibraries) {
        $libs = Get-PnPList | Where-Object { $_.BaseType -eq "DocumentLibrary" -and -not $_.Hidden } | Select-Object -ExpandProperty Title
    } else {
        $libs = @($Global:DefaultLibraryTitle)
    }

    $allResults = @()
    foreach ($lib in $libs) {
        Write-Host "==> Scanning library: $lib"
        try {
            $allResults += Get-SuspiciousFiles -LibraryTitle $lib -SinceDays $SinceDays -BadExt $BadExt
        } catch {
            Write-Warning "Scan failed on library '$lib' : $($_.Exception.Message)"
        }
    }

    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $csvPath = Join-Path $Global:ReportDir "suspected_${SiteName}_${stamp}.csv"
    $allResults | Sort-Object Modified -Descending | Export-Csv $csvPath -NoTypeInformation
    Write-Host "==> Found $($allResults.Count) suspicious files. Report: $csvPath"

    if (-not $Delete) {
        Write-Host "==> Dry-run only (no deletion). To delete, re-run with -Delete"
        return
    }

    if ($allResults.Count -eq 0) {
        Write-Host "==> Nothing to delete."
        return
    }

    # 二次确认（避免误删）
    $answer = Read-Host "CONFIRM DELETE on site '$SiteName' (type YES to proceed)"
    if ($answer -ne "YES") {
        Write-Host "==> Cancelled."
        return
    }

    foreach ($r in $allResults) {
        $target = "$($r.FileRef)"
        if ($PSCmdlet.ShouldProcess($target, "Remove-PnPFile")) {
            try {
                Remove-PnPFile -ServerRelativeUrl $r.FileRef -Force
                Write-Host "Deleted: $($r.FileRef)"
            } catch {
                Write-Warning "FAILED delete: $($r.FileRef) -- $($_.Exception.Message)"
            }
        }
    }

    Write-Host "==> Deletion completed for site '$SiteName'."
}

function Invoke-RansomwareCleanupBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string[]]$SiteNames,
        [int]$SinceDays = 7,
        [string[]]$BadExt = $Global:DefaultBadExt,
        [switch]$AllLibraries,
        [switch]$Delete
    )

    foreach ($sn in $SiteNames) {
        Write-Host ""
        Write-Host "==================== $sn ===================="
        Invoke-RansomwareCleanup -SiteName $sn -SinceDays $SinceDays -BadExt $BadExt -AllLibraries:$AllLibraries -Delete:$Delete
    }
}
