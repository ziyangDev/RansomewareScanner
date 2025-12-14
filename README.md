# RansomewareScanner
Scan the entire SP sites and delete the suspicious files
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
