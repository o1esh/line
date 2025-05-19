################################################################################
#                💻 Утилита Диагностики Windows v1.3 — Ghetto Edition           #
#                         Автор: o1esh                                         #
#                         🔥 Полная версия 700+ строк                          #
################################################################################

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

# Проверка прав администратора
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "🚫 Требуются права администратора! Запускаю с повышением..." -ForegroundColor Red
    Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$width = [Console]::WindowWidth
$global:ReportLog = @()
$script:sessionInfoLogged = $false

$logo = @'
                                                        $$\         $$\ $$\                     
                                                        $$ |        $$ |\__|                    
 $$$$$$$\  $$$$$$\   $$$$$$$\  $$$$$$\  $$$$$$$\   $$$$$$$ |        $$ |$$\ $$$$$$$\   $$$$$$\  
$$  _____|$$  __$$\ $$  _____|$$  __$$\ $$  __$$\ $$  __$$ |$$$$$$\ $$ |$$ |$$  __$$\ $$  __$$\ 
\$$$$$$\  $$$$$$$$ |$$ /      $$ /  $$ |$$ |  $$ |$$ /  $$ |\______|$$ |$$ |$$ |  $$ |$$$$$$$$ |
 \____$$\ $$   ____|$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ |        $$ |$$ |$$ |  $$ |$$   ____|
$$$$$$$  |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |  $$ |\$$$$$$$ |        $$ |$$ |$$ |  $$ |\$$$$$$$\ 
\_______/  \_______| \_______| \______/ \__|  \__| \_______|        \__|\__|\__|  \__| \_______|
'@

function Show-Header {
    Clear-Host
    $logoLines = $logo -split "`n"
    foreach ($line in $logoLines) {
        if ($width -ge 100) {
            $pad = [math]::Floor(($width - $line.Length) / 2)
            Write-Host (' ' * $pad + $line) -ForegroundColor Cyan
        } else {
            Write-Host $line -ForegroundColor Cyan
        }
    }
    Write-Host ('═' * $width) -ForegroundColor DarkCyan
    $now = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
    $timePad = [math]::Floor(($width - ("🕒 $now").Length) / 2)
    Write-Host (' ' * $timePad + "🕒 $now") -ForegroundColor Gray
    Write-Progress -Activity 'Загрузка информации' -Status 'Сканирование системы...' -PercentComplete 50
    Show-SystemInfo
    Write-Progress -Activity 'Загрузка информации' -Completed
    Write-Host ''
    Write-Host '⚠️ ВАЖНО: Перед проведением любых действий согласуйте их с пользователем.' -ForegroundColor Yellow
    Write-Host ''
}

function Show-Frame {
    param([string]$Title, [string[]]$Items)
    Write-Host ('┌' + '─' * ($width-2) + '┐') -ForegroundColor Magenta
    $pad = [math]::Floor(($width - $Title.Length - 2) / 2)
    Write-Host ('│' + (' ' * $pad) + $Title + (' ' * $pad) + '│') -ForegroundColor Yellow
    Write-Host ('├' + '─' * ($width-2) + '┤') -ForegroundColor Magenta
    foreach ($item in $Items) {
        if ($item.Length -gt ($width - 4)) {
            $item = $item.Substring(0, $width - 7) + "..."
        }
        $pad = [math]::Floor(($width - $item.Length - 2) / 2)
        Write-Host ('│' + ' ' * $pad + $item + ' ' * $pad + '│')
    }
    Write-Host ('└' + '─' * ($width-2) + '┘') -ForegroundColor Magenta
}

function Add-ToReport($entry) {
    $global:ReportLog += "[$(Get-Date -Format 'HH:mm:ss')] $entry"
}

function Show-Report {
    if (-not $ReportLog) {
        Show-Frame '📋 ОТЧЁТ' @('Нет действий для отчёта.')
    } else {
        Show-Frame '📋 ОТЧЁТ О ВЫПОЛНЕННЫХ ДЕЙСТВИЯХ' $ReportLog
        $desktopPath = [Environment]::GetFolderPath('Desktop')
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $reportFile = Join-Path $desktopPath "diagnostic_report_$timestamp.txt"
        try {
            $ReportLog | Out-File -FilePath $reportFile -Encoding UTF8
            Write-Host "✅ Отчёт сохранён автоматически в: $reportFile" -ForegroundColor Green
        } catch {
            Write-Host "❌ Не удалось сохранить отчёт: $_" -ForegroundColor Red
        }
    }
    Write-Host ''; Write-Host '📌 Нажми любую клавишу...' -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Main-Menu {
    $phrases = @(
        "💬 Не забудь — плохой админ не делает бэкапы!",
        "💬 CTRL + ALT + DEL спасли больше душ, чем психологи.",
        "💬 Всё работает? Отлично. Значит, ты зря пришёл. 😎",
        "💬 Удаление TEMP файлов — как отпуск для Windows.",
        "💬 Безопасность — это не антивирус, это паранойя.",
        "💬 У хорошего админа всё автоматом. Даже кофе.",
        "💬 if (падает == true) { reboot(); }",
        "💬 Нет доступа? Проверь права. Потом перезапусти. Потом зови меня.",
        "💬 Пинг есть — всё остальное неважно. 🤙",
        "💬 1С — это не программа, это стиль жизни и боль одновременно."
    )
    $quote = Get-Random -InputObject $phrases
    Write-Progress -Activity 'Подготовка главного меню' -Status 'Формирование опций...' -PercentComplete 70
    Show-Frame '🎛️ ГЛАВНОЕ МЕНЮ' @(
        "[1] 📋 Инфо о системе",
        "[2] 🔧 Диагностика",
        "[3] 📝 Сформировать отчёт",
        "[4] 🧹 Обслуживание ПК",
        "[5] 💽 Теневое копирование",
        "[6] 🔐 Активация Windows",
        "[7] 🛡 Аудит безопасности",
        "[8] 🛠 Быстрые инструменты",
        "[9] 🌐 Сетевые инструменты",
        "[10] 📦 Инструменты поддержки",
        "[0] ❌ Выйти",
        "",
        "$quote"
    )
    Write-Progress -Activity 'Подготовка главного меню' -Completed
}

function Show-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor
    $gpu = Get-CimInstance Win32_VideoController
    $mem = Get-CimInstance Win32_PhysicalMemory

    $totalMemGB = ($mem.Capacity | Measure-Object -Sum).Sum / 1GB
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeFormatted = "{0} д. {1} ч. {2} мин." -f $uptime.Days, $uptime.Hours, $uptime.Minutes

    $ipLocal = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "*" -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' }).IPAddress | Select-Object -First 1
    try {
        $ipExternal = (Invoke-RestMethod -Uri "http://ipinfo.io/ip" -UseBasicParsing).Trim()
    } catch {
        $ipExternal = 'Н/Д'
    }

    $lines = @(
        "💻 Имя ПК: $($env:COMPUTERNAME)",
        "🪟 ОС: $($os.Caption) $($os.OSArchitecture)",
        "🧠 Проц: $($cpu.Name.Trim())",
        "🎮 Видеокарта: $($gpu.Name.Trim())",
        "🧵 RAM: $([math]::Round($totalMemGB, 1)) ГБ",
        "🕐 Аптайм: $uptimeFormatted",
        "📶 Локальный IP: $ipLocal",
        "🌐 Внешний IP: $ipExternal"
    )
    Show-Frame '🧾 ИНФОРМАЦИЯ О СИСТЕМЕ' $lines
    if (-not $script:sessionInfoLogged) {
        Add-ToReport 'Просмотрена информация о системе'
        $script:sessionInfoLogged = $true
    }
}

function Run-Maintenance {
    Show-Frame '🧹 ОБСЛУЖИВАНИЕ ПК' @("Выполняется очистка и проверка...")

    $actions = @(
        { ipconfig /flushdns | Out-Null; "Очищен DNS-кеш" },
        { sfc /scannow | Out-Null; "Проверка целостности (SFC)" },
        { Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue; "Очистка TEMP" },
        { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; "Очистка корзины" },
        { cmd /c "echo Y | chkdsk C: /F" | Out-Null; "Проверка диска (chkdsk)" },
        { UsoClient StartScan | Out-Null; "Поиск обновлений Windows" }
    )

    $i = 0
    foreach ($action in $actions) {
        $i++
        Write-Progress -Activity 'Обслуживание' -PercentComplete ($i * 15)
        try {
            $msg = & $action
            Add-ToReport $msg
            Write-Host "✅ $msg" -ForegroundColor Green
        } catch {
            Write-Host "❌ Ошибка: $_" -ForegroundColor Red
        }
    }

    # Очистка TEMP всех пользователей
    Write-Progress -Activity 'Обслуживание' -Status 'Очистка TEMP профилей...' -PercentComplete 90
    $userProfiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -eq $false -and $_.Special -eq $false }
    foreach ($profile in $userProfiles) {
        $tempPath = Join-Path $profile.LocalPath 'AppData\Local\Temp'
        if (Test-Path $tempPath) {
            try {
                Remove-Item "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                Add-ToReport "Очищен TEMP: $tempPath"
            } catch {
                Add-ToReport "Ошибка очистки TEMP: $tempPath"
            }
        }
    }

    Write-Progress -Activity 'Обслуживание' -Completed
    Show-Frame '✅ ОБСЛУЖИВАНИЕ ЗАВЕРШЕНО' @('Все операции выполнены.')
    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Start-ShadowCopy {
    $drives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
    if (-not $drives) {
        Write-Host "❌ Нет доступных дисков!" -ForegroundColor Red
        return
    }
    
    $options = $drives | ForEach-Object { "$($_.DriveLetter): $($_.FileSystemLabel)" }
    Show-Frame '📀 ВЫБЕРИ ДИСК ДЛЯ ТЕНЕВОГО КОПИРОВАНИЯ' $options

    $selected = Read-Host "Введи букву диска (C/D/etc)"
    if ($selected -notmatch '^[A-Z]$') {
        Write-Host "❌ Некорректный ввод!" -ForegroundColor Red
        return
    }

    $drive = "${selected}:"
    if (-not (Test-Path $drive)) {
        Write-Host "❌ Диск $drive не существует!" -ForegroundColor Red
        return
    }

    try {
        vssadmin create shadow /for=$drive | Out-Null
        Add-ToReport "Создана теневая копия диска $drive"
        Write-Host "✅ Успешно!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Ошибка: $_" -ForegroundColor Red
    }
    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Start-SecurityAudit {
    Show-Frame '🛡 АУДИТ БЕЗОПАСНОСТИ' @("Проводится анализ конфигурации системы...")

    $firewall = Get-NetFirewallProfile | Select-Object Name, Enabled
    $uac = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue
    $antivirus = (Get-MpComputerStatus).AMServiceEnabled
    $accounts = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.PasswordRequired -eq $false }
    $remoteDesktop = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections

    $results = @()
    $results += "🛡 Брандмауэр:"
    $results += $firewall | ForEach-Object { "  - $($_.Name): $($_.Enabled)" }
    $results += ""
    $results += "🔐 UAC включён: $($uac.EnableLUA -eq 1)"
    $results += "🛡 Антивирус активен: $antivirus"
    $results += ""
    $results += "👤 Пользователи без пароля:"
    if ($accounts) {
        $results += $accounts.Name
    } else {
        $results += "  - Нет"
    }
    $results += ""
    $results += "🖥 RDP включён: $($remoteDesktop.fDenyTSConnections -eq 0)"

    Show-Frame '🔎 РЕЗУЛЬТАТ АУДИТА' $results
    Add-ToReport 'Проведён аудит безопасности'

    $runMiner = Read-Host '🧪 Хочешь проверить компьютер на скрытые майнеры? (Y/N)'
    if ($runMiner -eq 'Y') {
        Write-Host '🔍 Открываю страницу загрузки MinerSearch...' -ForegroundColor Cyan
        Start-Process "https://github.com/BlendLog/MinerSearch/releases"
        Add-ToReport 'Открыта ссылка на MinerSearch'
    }

    $fix = Read-Host '🔧 Хочешь автоматически исправить найденные проблемы? (Y/N)'
    if ($fix -eq 'Y') {
        Write-Host '🚀 Исправление запускается...' -ForegroundColor Cyan

        if ($uac.EnableLUA -ne 1) {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
            Add-ToReport 'UAC включён'
        }

        if ($remoteDesktop.fDenyTSConnections -ne 0) {
            Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
            Add-ToReport 'RDP включён'
        }

        if ($firewall | Where-Object { $_.Enabled -eq $false }) {
            Set-NetFirewallProfile -All -Enabled True
            Add-ToReport 'Брандмауэр включён'
        }

        Write-Host '✅ Исправления выполнены!' -ForegroundColor Green

        $revert = Read-Host '↩️ Хочешь откатить изменения? (Y/N)'
        if ($revert -eq 'Y') {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 0
            Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
            Disable-NetFirewallProfile -All
            Add-ToReport 'Изменения откатаны'
            Write-Host '🔁 Откат завершён!' -ForegroundColor Yellow
        }
    } else {
        Write-Host '⏭ Пропущено исправление' -ForegroundColor DarkYellow
    }

    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Show-QuickTools {
    $tools = @(
        "[1] 🔄 Перезапустить службу печати",
        "[2] 🧰 Открыть диспетчер устройств",
        "[3] 🚫 Отключить OneDrive автозапуск",
        "[4] 🗑 Очистить SoftwareDistribution",
        "[5] 💡 Проверить автозагрузку",
        "[6] 🗂 Открыть папку автозагрузки",
        "[7] 🔐 Управление учётными записями",
        "[8] 📡 Перезапустить сетевые адаптеры",
        "[9] 🧪 Быстрое сканирование Defender",
        "[0] 🔙 Назад"
    )
    Show-Frame '🛠 БЫСТРЫЕ ИНСТРУМЕНТЫ' $tools
    $choice = Read-Host '👉 Выбери инструмент'

    switch ($choice) {
        '1' { 
            Restart-Service -Name Spooler -Force
            Add-ToReport 'Перезапущена служба печати'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '2' { 
            Start-Process devmgmt.msc
            Add-ToReport 'Открыт диспетчер устройств'
        }
        '3' { 
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Value $null
            Add-ToReport 'Отключён автозапуск OneDrive'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '4' { 
            Remove-Item -Path "$env:windir\SoftwareDistribution\Download\*" -Recurse -Force
            Add-ToReport 'Очищена папка обновлений'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '5' { 
            Start-Process "taskmgr.exe" -ArgumentList "/7"
            Add-ToReport 'Открыт диспетчер задач (автозагрузка)'
        }
        '6' { 
            Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            Add-ToReport 'Открыта папка автозагрузки'
        }
        '7' { 
            Start-Process "netplwiz"
            Add-ToReport 'Открыто управление учётными записями'
        }
        '8' { 
            Get-NetAdapter | Restart-NetAdapter -Confirm:$false
            Add-ToReport 'Перезапущены сетевые адаптеры'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '9' { 
            Start-MpScan -ScanType QuickScan
            Add-ToReport 'Запущено быстрое сканирование Defender'
            Write-Host '✅ Сканирование начато!' -ForegroundColor Green
        }
        '0' { return }
        default { Write-Host '❌ Неверный выбор' -ForegroundColor Red }
    }
    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Start-EventLogScan {
    Show-Frame '🧾 АНАЛИЗ ЖУРНАЛОВ СОБЫТИЙ' @("Извлекаются последние ошибки системы...")

    $errors = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
        Where-Object { $_.LevelDisplayName -eq 'Error' } |
        Select-Object -First 5 | ForEach-Object {
            "[$($_.TimeCreated)] $($_.ProviderName): $($_.Message.Split("`n")[0])"
        }

    if (-not $errors) { $errors = @("⚠️ Ошибки не найдены") }

    Show-Frame '📉 ПОСЛЕДНИЕ ОШИБКИ' $errors
    Add-ToReport 'Проверен журнал событий System'

    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Start-NetworkTools {
    Show-Frame '🌐 СЕТЕВЫЕ ИНСТРУМЕНТЫ' @("Выполняется расширенный анализ сети...")

    $results = @()

    # Проверка DNS
    try {
        $dnsCheck = Resolve-DnsName google.com -ErrorAction Stop
        $results += "✅ DNS работает: $($dnsCheck.NameHost)"
    } catch {
        $results += "❌ DNS не отвечает"
    }

    # Проверка шлюза
    $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if (Test-Connection -ComputerName $gateway -Count 1 -Quiet) {
        $results += "✅ Шлюз доступен: $gateway"
    } else {
        $results += "❌ Шлюз недоступен: $gateway"
    }

    # Проверка HTTP
    try {
        Invoke-WebRequest -Uri "http://example.com" -UseBasicParsing -TimeoutSec 5 | Out-Null
        $results += "✅ HTTP подключение активно"
    } catch {
        $results += "❌ HTTP проверка не прошла"
    }

    # Сканирование подсети
    $subnet = ($gateway -split '\.')[0..2] -join '.'
    $results += "🔍 Поиск устройств в сети $subnet.0/24..."
    $alive = 1..254 | Where-Object { Test-Connection -ComputerName "$subnet.$_" -Count 1 -Quiet }

    foreach ($ip in $alive) {
        $hostname = try { ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { 'N/A' }
        $ports = @(80, 443, 3389) | Where-Object { Test-NetConnection -ComputerName $ip -Port $_ -InformationLevel Quiet }
        $portList = if ($ports) { $ports -join ', ' } else { 'нет открытых' }
        $results += "  - $ip ($hostname), порты: $portList"
    }

    Show-Frame '🌐 РЕЗУЛЬТАТ СКАНА' $results
    Add-ToReport 'Выполнен сетевой анализ'

    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Show-SupportTools {
    $items = @(
        '[1] 🖥 Сменить имя компьютера',
        '[2] 🌐 Сброс сетевых настроек',
        '[3] 🖨 Удалить все принтеры',
        '[4] 🔎 Включить Windows Search',
        '[5] 👤 Создать локального админа',
        '[0] 🔙 Назад'
    )
    Show-Frame '📦 ИНСТРУМЕНТЫ ПОДДЕРЖКИ' $items
    $input = Read-Host '👉 Выбери инструмент'

    switch ($input) {
        '1' {
            $newName = Read-Host 'Введи новое имя компьютера'
            Rename-Computer -NewName $newName -Force
            Add-ToReport "Имя компьютера изменено на: $newName"
            Write-Host '✅ Готово! Перезагрузите ПК.' -ForegroundColor Green
        }
        '2' {
            netsh winsock reset | Out-Null
            netsh int ip reset | Out-Null
            Add-ToReport 'Сброшены сетевые настройки'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '3' {
            Get-Printer | Remove-Printer -ErrorAction SilentlyContinue
            Add-ToReport 'Удалены все принтеры'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '4' {
            Set-Service -Name "WSearch" -StartupType Automatic
            Start-Service -Name "WSearch"
            Add-ToReport 'Включена служба поиска'
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '5' {
            $username = Read-Host 'Имя пользователя'
            $password = Read-Host 'Пароль' -AsSecureString
            New-LocalUser -Name $username -Password $password -FullName $username
            Add-LocalGroupMember -Group "Administrators" -Member $username
            Add-ToReport "Создан локальный админ: $username"
            Write-Host '✅ Готово!' -ForegroundColor Green
        }
        '0' { return }
        default { Write-Host '❌ Неверный выбор' -ForegroundColor Red }
    }
    Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

# Главный цикл
while ($true) {
    Show-Header
    Main-Menu
    $choice = Read-Host '👇 Выбери действие'

    switch ($choice) {
        '1' { Show-SystemInfo }
        '2' { 
            $cpuLoad = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
            $mem = Get-CimInstance Win32_OperatingSystem
            $memUsage = [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize * 100, 1)
            $services = Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic' } | Select-Object -First 5
            $servicesList = if ($services) { $services.DisplayName -join "`n  - " } else { "Нет" }

            $results = @(
                "📊 CPU: $([math]::Round($cpuLoad,1))%",
                "💾 RAM: ${memUsage}%",
                "⚠️ Остановленные службы:",
                "  - $servicesList"
            )
            Show-Frame '🔧 ДИАГНОСТИКА' $results
            Add-ToReport 'Выполнена диагностика системы'
            Write-Host "`n📌 Нажми любую клавишу..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        '3' { Show-Report }
        '4' { Run-Maintenance }
        '5' { Start-ShadowCopy }
        '6' { 
            Write-Host '🔐 Запуск активации Windows...' -ForegroundColor Cyan
            Start-Process powershell -ArgumentList '-NoExit', '-Command', 'irm https://get.activated.win | iex'
            Add-ToReport 'Запущен скрипт активации'
        }
        '7' { Start-SecurityAudit }
        '8' { Show-QuickTools }
        '9' { Start-NetworkTools }
        '10' { Show-SupportTools }
        '0' { 
            Write-Host '👋 Выход из программы. Удачи!' -ForegroundColor Cyan
            exit 
        }
        default { 
            Write-Host '❌ Неверный ввод!' -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}