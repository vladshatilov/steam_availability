#Requires -Version 7.0
<#
.SYNOPSIS
    netmon: показывает, кто именно сломался: сетевая карта/роутер, провайдер, зарубежный канал/РКН,
    Cloudflare (замедление ТСПУ), Steam (web или CM-серверы подключения).
    Подробности в README.md рядом со скриптом.

.EXAMPLE
    pwsh -File netmon.ps1                          # интерактивное меню (по умолчанию)
    pwsh -File netmon.ps1 -Mode Check              # быстрая проверка: 3 цикла + итог "что работает, что нет"
    pwsh -File netmon.ps1 -Mode Snapshot [-Deep]   # сохранить маршруты/конфиг сети (+ pathping)
    pwsh -File netmon.ps1 -Mode Monitor [-DurationMin 60]
    pwsh -File netmon.ps1 -Mode Report -Hours 24   # отчёт за последние 24 часа
    pwsh -File netmon.ps1 -Mode Diff
    pwsh -File netmon.ps1 -Mode AutostartOn        # запускать мониторинг при входе в Windows (AutostartOff - выключить)
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Check', 'Monitor', 'Snapshot', 'Report', 'Diff', 'AutostartOn', 'AutostartOff', 'Cleanup')]
    [string]$Mode = 'Menu',
    [string]$OutDir = (Join-Path $PSScriptRoot 'data'),
    [int]$IntervalSec = 15,
    [int]$CfBigEvery = -1,            # качать 256 КБ с Cloudflare раз в N циклов; -1 = из $Cfg
    [int]$DurationMin = 0,
    [int]$Hours = 0,                  # для Report: за сколько последних часов (0 = 7 дней или -Since)
    [datetime]$Since = (Get-Date).AddDays(-7),
    [int]$RetentionDays = -1,         # хранить данные N дней; -1 = из $Cfg, 0 = не чистить
    [switch]$Deep,
    [switch]$NoPause                  # не ждать Enter в конце (для запуска из планировщика)
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------------------------------------------
# Настройки
# ----------------------------------------------------------------------------------------------------------------
$Cfg = @{
    RuPing          = @('77.88.8.8', '77.88.8.1')                     # Яндекс DNS: точно внутри РФ
    IntlPing        = @('1.1.1.1', '8.8.8.8', '9.9.9.9')              # Cloudflare, Google, Quad9
    DnsNames        = @('ya.ru', 'store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com')
    RuHttp          = @('https://ya.ru/', 'https://vk.com/')
    IntlHttp        = @('https://www.google.com/generate_204', 'https://github.com/')
    CfHttp          = @('https://www.cloudflare.com/cdn-cgi/trace', 'https://1.1.1.1/cdn-cgi/trace')
    CfBig           = 'https://speed.cloudflare.com/__down?bytes=262144'   # 256 КБ; ТСПУ режет CF после ~16 КБ
    CfBigTimeoutMs  = 6000
    CfBigEvery      = 10        # качать 256 КБ раз в N циклов (1 = каждый цикл). При 15 с: 1 -> ~1.5 ГБ/сутки, 10 -> ~150 МБ/сутки.
                                # Пока Cloudflare в состоянии CF_* (сбой), качается каждый цикл, чтобы точно поймать конец сбоя
    SteamHttp       = @(
        'https://store.steampowered.com/',
        'https://api.steampowered.com/ISteamWebAPIUtil/GetServerInfo/v1/',
        'https://steamcommunity.com/'
    )
    SteamCmFallback = @('cmp1-fra1.steamserver.net:27018', 'cmp1-fra2.steamserver.net:27020', 'cmp2-fra2.steamserver.net:27018')
    IspHop          = ''        # IP первого хопа провайдера; пусто = определить автоматически через tracert
    PublicIpEvery   = 20        # проверять внешний IP каждые N циклов (и после каждого восстановления)
    TraceCooldownS  = 300       # не чаще одного tracert на цель за N секунд
    RetentionDays   = 10        # удалять CSV, трассировки, снапшоты и строки events.log старше N дней (0 = не удалять)
    KeepSnapshots   = 3         # сколько последних снапшотов хранить всегда, независимо от возраста
}

$ScriptPath = $PSCommandPath
$StartupLink = Join-Path ([Environment]::GetFolderPath('Startup')) 'netmon-monitor.lnk'
$Retention = if ($RetentionDays -ge 0) { $RetentionDays } else { $Cfg.RetentionDays }
$CfBigStep = [Math]::Max(1, $(if ($CfBigEvery -gt 0) { $CfBigEvery } else { $Cfg.CfBigEvery }))

$VerdictHelp = [ordered]@{
    'OK'                = 'всё работает'
    'LINK_DOWN'         = 'пропал линк на сетевой карте / нет маршрута по умолчанию: кабель, порт роутера, драйвер, перезагрузка роутера'
    'LAN_ROUTER'        = 'линк есть, но роутер не отвечает на ping: роутер завис/перегружен'
    'PROVIDER_EDGE'     = 'роутер жив, но не отвечает даже первый хоп провайдера: участок до провайдера (WAN/PPPoE роутера, линия, оборудование провайдера). Смотрите лог роутера'
    'PROVIDER_UPSTREAM' = 'роутер и первый хоп провайдера живы, но ни РФ, ни зарубеж не доступны: сессия цела, ломается сеть провайдера дальше'
    'PROVIDER'          = 'роутер жив, ни РФ, ни зарубеж не доступны (первый хоп провайдера не пингуется, уточнить нельзя)'
    'DNS'               = 'IP-адреса пингуются, но DNS не резолвит: DNS провайдера/роутера'
    'INTL_DOWN'         = 'РФ работает, зарубеж нет: внешний канал провайдера или ограничения ТСПУ/РКН'
    'CF_DOWN'           = 'зарубеж работает, Cloudflare нет'
    'CF_THROTTLE'       = 'Cloudflare отвечает, но 256 КБ не качаются за 6 с: типичное замедление ТСПУ (обрыв после ~16 КБ)'
    'STEAM_ALL'         = 'зарубеж работает, а Steam целиком (web + CM) нет: Steam лежит или блокировка'
    'STEAM_CM'          = 'CM-серверы Steam недоступны по TCP: клиент Steam уходит в "нет соединения", магазин может работать'
    'STEAM_WEB'         = 'store/community/api не открываются, CM-серверы доступны'
    'LOSS'              = 'часть проверок не прошла (потери/единичные таймауты)'
    'NO_DATA'           = 'монитор не работал (сон ПК, закрыт скрипт)'
}

$CatNames = [ordered]@{
    GW         = 'Роутер (шлюз)'
    ISP        = 'Первый хоп провайдера'
    DNS        = 'DNS'
    RU_PING    = 'РФ: ping (Яндекс)'
    RU_HTTP    = 'РФ: сайты (ya.ru, vk.com)'
    INTL_PING  = 'Зарубеж: ping (1.1.1.1, 8.8.8.8, 9.9.9.9)'
    INTL_HTTP  = 'Зарубеж: сайты (google, github)'
    CF_HTTP    = 'Cloudflare'
    CF_BIG     = 'Cloudflare 256 КБ (замедление ТСПУ)'
    STEAM_HTTP = 'Steam: магазин / community / API'
    STEAM_CM   = 'Steam: серверы подключения клиента (CM)'
}

$HardVerdicts = @('LINK_DOWN', 'LAN_ROUTER', 'PROVIDER_EDGE', 'PROVIDER_UPSTREAM', 'PROVIDER', 'DNS', 'INTL_DOWN')

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$EventsFile = Join-Path $OutDir 'events.log'
$TracesDir = Join-Path $OutDir 'traces'

# HttpClient без прокси (проверяем реальный путь) и без keep-alive (каждый раз новый TCP+TLS, чтобы DPI был виден)
$Handler = [System.Net.Http.HttpClientHandler]::new()
$Handler.UseProxy = $false
$Handler.AllowAutoRedirect = $false
$Http = [System.Net.Http.HttpClient]::new($Handler)
$Http.Timeout = [TimeSpan]::FromSeconds(8)
$Http.DefaultRequestHeaders.ConnectionClose = $true
$Http.DefaultRequestHeaders.UserAgent.ParseAdd('Mozilla/5.0 (Windows NT 10.0; Win64; x64) netmon/1.0')
$Http.DefaultRequestHeaders.CacheControl = [System.Net.Http.Headers.CacheControlHeaderValue]::new()
$Http.DefaultRequestHeaders.CacheControl.NoCache = $true

# Запуск консольной утилиты с сохранением вывода в UTF-8 файл.
# Утилиты Windows пишут кто в UTF-8, кто в OEM (cp866), кто в ANSI (cp1251) - берём сырые байты и определяем сами.
# Это scriptblock, а не функция, чтобы его можно было отдать в ThreadJob.
$SaveNativeOutput = {
    param([string]$FilePath, [string]$Exe, [string[]]$ArgList)
    $psi = [Diagnostics.ProcessStartInfo]::new($Exe)
    foreach ($arg in $ArgList) { $psi.ArgumentList.Add($arg) }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::Latin1      # Latin1 = байты 1:1
    $psi.StandardErrorEncoding = [Text.Encoding]::Latin1
    $proc = [Diagnostics.Process]::Start($psi)
    $errTask = $proc.StandardError.ReadToEndAsync()
    $raw = $proc.StandardOutput.ReadToEnd() + $errTask.GetAwaiter().GetResult()
    $proc.WaitForExit()
    $bytes = [Text.Encoding]::Latin1.GetBytes($raw)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    } catch {
        $best = ''
        $bestScore = -1
        foreach ($cp in 866, 1251) {
            $candidate = [Text.Encoding]::GetEncoding($cp).GetString($bytes)
            $score = [regex]::Matches($candidate, '[А-Яа-яЁё]').Count
            if ($score -gt $bestScore) { $best = $candidate; $bestScore = $score }
        }
        $text = $best
    }
    [IO.File]::WriteAllText($FilePath, $text, [Text.UTF8Encoding]::new($true))
}

# ----------------------------------------------------------------------------------------------------------------
# Утилиты
# ----------------------------------------------------------------------------------------------------------------
function Write-NetEvent([string]$Text, [string]$Color = 'Cyan') {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Text
    Add-Content -Path $EventsFile -Value $line -Encoding utf8
    Write-Host "  >> $line" -ForegroundColor $Color
}

function Get-ShortError([Exception]$Ex) {
    $parts = @()
    $cur = $Ex
    while ($cur) { $parts += "$($cur.GetType().Name): $($cur.Message)"; $cur = $cur.InnerException }
    $text = $parts -join ' | '
    switch -Regex ($text) {
        'TaskCanceled|OperationCanceled|timed? ?out|Timeout' { return 'timeout' }
        'forcibly closed|reset by peer|ConnectionReset|10054' { return 'reset' }
        'refused|10061' { return 'refused' }
        'No such host|NameResolution|11001|nodename|Name or service' { return 'dns' }
        'Authentication|SSL|TLS|certificate|handshake' { return 'tls' }
        'unreachable|10051|10065' { return 'unreachable' }
        'unexpected EOF|0 bytes from the transport' { return 'eof' }
    }
    $msg = ($parts | Select-Object -Last 1) -replace '\s+', ' '
    if ($msg.Length -gt 80) { $msg = $msg.Substring(0, 80) }
    return $msg
}

function Test-PrivateIp([string]$Ip) {
    return $Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.)'
}

function Get-ActiveRoute {
    $best = $null
    $bestMetric = [int]::MaxValue
    foreach ($route in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        $ifMetric = (Get-NetIPInterface -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
        if (($route.RouteMetric + $ifMetric) -lt $bestMetric) { $best = $route; $bestMetric = $route.RouteMetric + $ifMetric }
    }
    if (-not $best) { return $null }
    $adapter = Get-NetAdapter -InterfaceIndex $best.ifIndex -ErrorAction SilentlyContinue
    $dns = (Get-DnsClientServerAddress -InterfaceIndex $best.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
        Select-Object -First 1
    return [pscustomobject]@{
        IfIndex     = $best.ifIndex
        Alias       = $best.InterfaceAlias
        Description = $adapter.InterfaceDescription
        Gateway     = $best.NextHop
        Dns         = $dns
    }
}

function ConvertFrom-Tracert([string[]]$Lines) {
    $hops = foreach ($line in $Lines) {
        if ($line -match '^\s*(\d+)\s+\S') {
            $hopNo = [int]$Matches[1]
            $ipMatch = [regex]::Match($line, '(\d{1,3}(?:\.\d{1,3}){3})\]?\s*$')
            [pscustomobject]@{ Hop = $hopNo; Ip = $(if ($ipMatch.Success) { $ipMatch.Groups[1].Value } else { '*' }) }
        }
    }
    return , @($hops)
}

function Find-IspHop([string[]]$TraceLines, [string]$Gateway) {
    if ($Cfg.IspHop) { return $Cfg.IspHop }
    $hops = ConvertFrom-Tracert $TraceLines
    return ($hops | Where-Object { $_.Ip -ne '*' -and $_.Ip -ne $Gateway -and -not (Test-PrivateIp $_.Ip) } | Select-Object -First 1).Ip
}

function Test-Pingable([string]$Target) {
    $pinger = [System.Net.NetworkInformation.Ping]::new()
    foreach ($attempt in 1..3) {
        try { if ($pinger.Send($Target, 1000).Status -eq 'Success') { return $true } } catch { }
    }
    return $false
}

function Get-PublicIp {
    foreach ($url in 'https://api.ipify.org', 'https://www.cloudflare.com/cdn-cgi/trace', 'https://ifconfig.me/ip') {
        try {
            $cts = [Threading.CancellationTokenSource]::new(5000)
            $text = $Http.GetStringAsync($url, $cts.Token).GetAwaiter().GetResult()
            if ($text -match '(?m)^(?:ip=)?(\d{1,3}(?:\.\d{1,3}){3})\s*$') { return $Matches[1] }
        } catch { }
    }
    return ''
}

function Get-SteamCmEndpoints {
    $cache = Join-Path $OutDir 'steam_cm.json'
    try {
        $cts = [Threading.CancellationTokenSource]::new(8000)
        $raw = $Http.GetStringAsync('https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0', $cts.Token).GetAwaiter().GetResult()
        $list = ($raw | ConvertFrom-Json).response.serverlist
        $ws = $list | Where-Object type -EQ 'websockets' | Group-Object dc | ForEach-Object { $_.Group[0].endpoint } | Select-Object -First 3
        $nf = $list | Where-Object type -EQ 'netfilter' | Select-Object -First 2 -ExpandProperty endpoint
        $endpoints = @(@($ws) + @($nf) | Where-Object { $_ })
        if ($endpoints.Count) {
            $endpoints | ConvertTo-Json | Set-Content -Path $cache -Encoding utf8
            return $endpoints
        }
    } catch {
        Write-Host "  Не удалось получить список CM Steam ($(Get-ShortError $_.Exception)), беру кэш/fallback" -ForegroundColor Yellow
    }
    if (Test-Path $cache) { return @(Get-Content $cache -Raw | ConvertFrom-Json) }
    return $Cfg.SteamCmFallback
}

function Start-Trace([string]$Target, [string]$Reason) {
    New-Item -ItemType Directory -Force -Path $TracesDir | Out-Null
    $safe = $Target -replace '[^\w\.-]', '_'
    $file = Join-Path $TracesDir ('{0:yyyyMMdd_HHmmss}_{1}_{2}.txt' -f (Get-Date), $Reason, $safe)
    $null = Start-ThreadJob -ScriptBlock $SaveNativeOutput -ArgumentList $file, 'tracert.exe', @('-d', '-w', '800', '-h', '25', $Target)
    return $file
}

function Read-Number([string]$Prompt, [int]$Default) {
    $answer = Read-Host "$Prompt [$Default]"
    $number = 0
    if ([int]::TryParse($answer, [ref]$number) -and $number -gt 0) { return $number }
    return $Default
}

function Test-OwnConsole {
    # true, если окно консоли создано именно для этого процесса (запуск через Win+R, ярлык, автозагрузку)
    # и закроется сразу после выхода. Из открытого терминала или .bat к консоли подключено >= 2 процессов.
    try {
        if (-not ('NetmonConsole' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class NetmonConsole {
    [DllImport("kernel32.dll")]
    public static extern uint GetConsoleProcessList(uint[] processList, uint processCount);
}
'@
        }
        $buffer = [uint32[]]::new(16)
        return [NetmonConsole]::GetConsoleProcessList($buffer, 16) -le 1
    } catch {
        return $false
    }
}

function Invoke-Cleanup([int]$Days, [switch]$Loud) {
    if ($Days -le 0) { if ($Loud) { Write-Host 'Очистка отключена (RetentionDays = 0)' }; return }
    $border = (Get-Date).AddDays(-$Days)
    $removed = 0
    $oldFiles = @(Get-ChildItem $OutDir -Filter 'cycles_*.csv' -File -ErrorAction SilentlyContinue)
    if (Test-Path $TracesDir) { $oldFiles += Get-ChildItem $TracesDir -File }
    foreach ($file in $oldFiles | Where-Object LastWriteTime -LT $border) { Remove-Item $file.FullName -Force; $removed++ }

    $snapRoot = Join-Path $OutDir 'snapshots'
    if (Test-Path $snapRoot) {
        $oldSnaps = Get-ChildItem $snapRoot -Directory | Sort-Object Name -Descending |
            Select-Object -Skip $Cfg.KeepSnapshots | Where-Object LastWriteTime -LT $border
        foreach ($snap in $oldSnaps) { Remove-Item $snap.FullName -Recurse -Force; $removed++ }
    }

    $trimmed = 0
    if (Test-Path $EventsFile) {
        $lines = @(Get-Content $EventsFile)
        $kept = @($lines | Where-Object {
            -not ($_ -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)') -or
            [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null) -ge $border
        })
        if ($kept.Count -lt $lines.Count) {
            $trimmed = $lines.Count - $kept.Count
            Set-Content -Path $EventsFile -Value $kept -Encoding utf8
        }
    }
    if ($removed -or $trimmed) {
        Write-NetEvent ("CLEANUP старше {0} дн.: удалено файлов/папок {1}, строк events.log {2}" -f $Days, $removed, $trimmed) 'DarkGray'
    } elseif ($Loud) {
        Write-Host "Нечего удалять: всё моложе $Days дн."
    }
}

function Get-AutostartState {
    return Test-Path $StartupLink
}

function Enable-Autostart {
    $pwshPath = (Get-Command pwsh -ErrorAction Stop).Source
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($StartupLink)
    $link.TargetPath = $pwshPath
    $link.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Monitor -OutDir "{1}"' -f $ScriptPath, $OutDir
    $link.WorkingDirectory = Split-Path $ScriptPath
    $link.WindowStyle = 7      # окно свёрнуто
    $link.Description = 'netmon: мониторинг сети, Steam и Cloudflare'
    $link.Save()
    Write-Host "Автозапуск включён: $StartupLink" -ForegroundColor Green
    Write-Host 'При входе в Windows мониторинг стартует в свёрнутом окне. Остановить: развернуть окно и нажать Q.'
}

function Disable-Autostart {
    if (Test-Path $StartupLink) { Remove-Item $StartupLink -Force; Write-Host 'Автозапуск выключен' -ForegroundColor Green }
    else { Write-Host 'Автозапуск и так выключен' }
}

function Wait-OrQuit([int]$Ms, [bool]$CanReadKeys) {
    # true = пользователь нажал Q / Esc / Ctrl+C
    $sw = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($CanReadKeys) {
            while ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                $isCtrlC = $key.Key -eq 'C' -and ($key.Modifiers -band [ConsoleModifiers]::Control)
                if ($key.Key -in 'Q', 'Escape' -or $isCtrlC) { return $true }
            }
        }
        if ($sw.ElapsedMilliseconds -ge $Ms) { break }
        Start-Sleep -Milliseconds 200
    } while ($true)
    return $false
}

# ----------------------------------------------------------------------------------------------------------------
# Snapshot / Diff
# ----------------------------------------------------------------------------------------------------------------
function Save-Snapshot([switch]$WithPathping) {
    $dir = Join-Path $OutDir ('snapshots\{0:yyyyMMdd_HHmmss}' -f (Get-Date))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host "Снапшот сети -> $dir" -ForegroundColor Cyan

    & $SaveNativeOutput (Join-Path $dir 'route_print.txt') 'route.exe' @('print')
    & $SaveNativeOutput (Join-Path $dir 'ipconfig_all.txt') 'ipconfig.exe' @('/all')
    & $SaveNativeOutput (Join-Path $dir 'mtu.txt') 'netsh.exe' @('interface', 'ipv4', 'show', 'subinterfaces')
    & $SaveNativeOutput (Join-Path $dir 'winhttp_proxy.txt') 'netsh.exe' @('winhttp', 'show', 'proxy')
    Get-NetIPConfiguration -Detailed | Out-String -Width 250 | Set-Content (Join-Path $dir 'netipconfiguration.txt') -Encoding utf8BOM
    Get-NetAdapter | Format-Table -AutoSize ifIndex, Name, InterfaceDescription, Status, LinkSpeed, MacAddress |
        Out-String -Width 250 | Set-Content (Join-Path $dir 'adapters.txt') -Encoding utf8BOM
    Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String -Width 250 | Set-Content (Join-Path $dir 'dns_servers.txt') -Encoding utf8BOM

    $route = Get-ActiveRoute
    $cms = Get-SteamCmEndpoints
    $cmHost = ($cms | Select-Object -First 1) -replace ':\d+$', ''
    $targets = @('77.88.8.8', '1.1.1.1', '8.8.8.8', 'store.steampowered.com', 'speed.cloudflare.com', $cmHost)

    Write-Host "  tracert к $($targets -join ', ') (параллельно, до ~1.5 мин)..."
    $jobs = @(foreach ($tgt in $targets) {
        $file = Join-Path $dir ('tracert_{0}.txt' -f ($tgt -replace '[^\w\.-]', '_'))
        Start-ThreadJob -ScriptBlock $SaveNativeOutput -ArgumentList $file, 'tracert.exe', @('-d', '-w', '800', '-h', '25', $tgt)
    })
    if ($WithPathping) {
        Write-Host '  pathping к 1.1.1.1 и Steam CM (несколько минут)...'
        $jobs += foreach ($tgt in @('1.1.1.1', $cmHost)) {
            $file = Join-Path $dir ('pathping_{0}.txt' -f ($tgt -replace '[^\w\.-]', '_'))
            Start-ThreadJob -ScriptBlock $SaveNativeOutput -ArgumentList $file, 'pathping.exe', @('-n', '-q', '50', '-w', '500', $tgt)
        }
    }
    $publicIp = Get-PublicIp
    $jobs | Wait-Job | Remove-Job

    $summary = [ordered]@{
        Time      = '{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)
        Interface = $route.Alias
        Adapter   = $route.Description
        Gateway   = $route.Gateway
        Dns       = $route.Dns
        IspHop    = Find-IspHop (Get-Content (Join-Path $dir 'tracert_77.88.8.8.txt')) $route.Gateway
        PublicIp  = $publicIp
        SteamCm   = $cms
    }
    $summary | ConvertTo-Json | Set-Content (Join-Path $dir 'summary.json') -Encoding utf8
    Write-Host ''
    foreach ($key in $summary.Keys) { Write-Host ('  {0,-10} {1}' -f $key, ($summary[$key] -join ', ')) }
    return [pscustomobject]$summary
}

function Compare-Snapshots {
    $snaps = @(Get-ChildItem (Join-Path $OutDir 'snapshots') -Directory -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 2)
    if ($snaps.Count -lt 2) { Write-Host 'Нужно минимум 2 снапшота (пункт "Снапшот" в меню)'; return }
    $old, $new = $snaps
    Write-Host "Сравнение $($old.Name) -> $($new.Name)" -ForegroundColor Cyan

    $sumOld = Get-Content (Join-Path $old.FullName 'summary.json') -Raw | ConvertFrom-Json
    $sumNew = Get-Content (Join-Path $new.FullName 'summary.json') -Raw | ConvertFrom-Json
    foreach ($field in 'Interface', 'Gateway', 'Dns', 'IspHop', 'PublicIp') {
        $changed = "$($sumOld.$field)" -ne "$($sumNew.$field)"
        $mark = if ($changed) { '  <-- изменилось' } else { '' }
        Write-Host ('  {0,-10} {1,-18} -> {2}{3}' -f $field, $sumOld.$field, $sumNew.$field, $mark) -ForegroundColor $(if ($changed) { 'Yellow' } else { 'Gray' })
    }
    foreach ($file in Get-ChildItem $new.FullName -Filter 'tracert_*.txt') {
        $oldFile = Join-Path $old.FullName $file.Name
        if (-not (Test-Path $oldFile)) { continue }
        $hopsOld = ConvertFrom-Tracert (Get-Content $oldFile)
        $hopsNew = ConvertFrom-Tracert (Get-Content $file.FullName)
        $maxHop = [Math]::Max($hopsOld.Count, $hopsNew.Count)
        $diff = foreach ($idx in 0..($maxHop - 1)) {
            $ipOld = if ($idx -lt $hopsOld.Count) { $hopsOld[$idx].Ip } else { '' }
            $ipNew = if ($idx -lt $hopsNew.Count) { $hopsNew[$idx].Ip } else { '' }
            if ($ipOld -ne $ipNew) { '    hop {0,2}: {1,-16} -> {2}' -f ($idx + 1), $ipOld, $ipNew }
        }
        if ($diff) { Write-Host "  $($file.Name): маршрут изменился" -ForegroundColor Yellow; $diff | Write-Host }
        else { Write-Host "  $($file.Name): без изменений ($($hopsNew.Count) хопов)" }
    }
}

# ----------------------------------------------------------------------------------------------------------------
# Проверки
# ----------------------------------------------------------------------------------------------------------------
function Initialize-Context($Summary, [string]$Label = 'START') {
    $route = Get-ActiveRoute
    if (-not $route) { throw 'Нет маршрута по умолчанию: сетевой линк отсутствует (кабель/Wi-Fi/роутер). Подключитесь к сети и запустите снова' }
    if ($route.Description -match 'VPN|TAP|WireGuard|Wintun|Tunnel|Fortinet|Cisco|Proton|Outline|sing-box|Clash') {
        Write-Host "ВНИМАНИЕ: маршрут по умолчанию идёт через '$($route.Description)' - проверки пойдут через VPN, а не напрямую" -ForegroundColor Red
    }
    $ispHop = if ($Summary.IspHop) { $Summary.IspHop } else { $Cfg.IspHop }
    $ctx = [pscustomobject]@{
        IfIndex     = $route.IfIndex
        Alias       = $route.Alias
        Gateway     = $route.Gateway
        Dns         = $route.Dns
        GwPingable  = Test-Pingable $route.Gateway
        IspHop      = $ispHop
        IspPingable = [bool]($ispHop -and (Test-Pingable $ispHop))
        SteamCm     = @($Summary.SteamCm)
        PublicIp    = $Summary.PublicIp
        Cycle       = 0
        LastVerdict = 'START'
        LastLink    = 'Up'
        LastTrace   = @{}
    }
    if (-not $ctx.GwPingable) { Write-Host "Роутер $($ctx.Gateway) не отвечает на ping: проверка роутера отключена" -ForegroundColor Yellow }
    if ($ispHop -and -not $ctx.IspPingable) { Write-Host "Первый хоп провайдера $ispHop не отвечает на ping: PROVIDER_EDGE/UPSTREAM различать не будем" -ForegroundColor Yellow }
    Write-NetEvent ("{0} iface='{1}' gw={2} dns={3} isp_hop={4} public_ip={5} steam_cm={6}" -f
        $Label, $ctx.Alias, $ctx.Gateway, $ctx.Dns, $ispHop, $ctx.PublicIp, ($ctx.SteamCm -join ','))
    return $ctx
}

function Start-Check([string]$Cat, [string]$Kind, [string]$Target) {
    $chk = [pscustomobject]@{
        Cat = $Cat; Kind = $Kind; Target = $Target; Task = $null; Client = $null; Cts = $null
        Sw = [Diagnostics.Stopwatch]::StartNew(); DoneMs = $null; Ok = $false; Ms = $null; Err = ''
    }
    try {
        switch ($Kind) {
            'ping' { $chk.Task = [System.Net.NetworkInformation.Ping]::new().SendPingAsync($Target, 1500) }
            'tcp' {
                $hostName, $port = $Target -split ':'
                $chk.Client = [System.Net.Sockets.TcpClient]::new()
                $chk.Task = $chk.Client.ConnectAsync($hostName, [int]$port)
            }
            'http' { $chk.Task = $Http.GetAsync($Target, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead) }
            'big' {
                $chk.Cts = [Threading.CancellationTokenSource]::new($Cfg.CfBigTimeoutMs)
                $chk.Task = $Http.GetByteArrayAsync($Target, $chk.Cts.Token)
            }
        }
    } catch { $chk.Err = Get-ShortError $_.Exception }
    return $chk
}

function Complete-Check($Chk) {
    if (-not $Chk.Task) { return }
    try {
        if (-not $Chk.Task.IsCompleted) { $Chk.Err = 'timeout'; return }
        $value = $Chk.Task.GetAwaiter().GetResult()
        switch ($Chk.Kind) {
            'ping' {
                if ("$($value.Status)" -eq 'Success') { $Chk.Ok = $true; $Chk.Ms = [int]$value.RoundtripTime }
                else { $Chk.Err = "$($value.Status)".ToLower() }
            }
            'http' {
                $code = [int]$value.StatusCode
                $value.Dispose()
                if ($code -lt 500) { $Chk.Ok = $true } else { $Chk.Err = "http$code" }
            }
            default { $Chk.Ok = $true }
        }
    } catch {
        $Chk.Err = Get-ShortError $_.Exception
    } finally {
        if ($Chk.Client) { $Chk.Client.Dispose() }
        if ($Chk.Cts) { $Chk.Cts.Dispose() }
    }
    if ($Chk.Ok -and $null -eq $Chk.Ms) { $Chk.Ms = $Chk.DoneMs }
}

function Invoke-DnsChecks([string]$Server) {
    foreach ($name in $Cfg.DnsNames) {
        $chk = [pscustomobject]@{ Cat = 'DNS'; Kind = 'dns'; Target = $name; Ok = $false; Ms = $null; Err = '' }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $params = @{ Name = $name; Type = 'A'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
            if ($Server) { $params.Server = $Server }      # явный сервер = мимо кэша Windows
            $answer = Resolve-DnsName @params
            if ($answer | Where-Object { $_.IP4Address }) { $chk.Ok = $true; $chk.Ms = [int]$sw.ElapsedMilliseconds }
            else { $chk.Err = 'noanswer' }
        } catch {
            $chk.Err = 'dns:' + (Get-ShortError $_.Exception)
        }
        $chk
    }
}

function Format-Cat($Checks) {
    $items = @($Checks | Where-Object { $_ })     # @($null) дал бы массив из одного элемента
    if (-not $items.Count) { return '-' }
    $okItems = @($items | Where-Object Ok)
    $text = '{0}/{1}' -f $okItems.Count, $items.Count
    $msList = @($okItems | Where-Object { $null -ne $_.Ms } | ForEach-Object Ms)
    if ($msList.Count) { $text += ' {0}ms' -f [int](($msList | Measure-Object -Average).Average) }
    return $text
}

function Invoke-Cycle($Ctx) {
    $now = Get-Date
    $route = Get-ActiveRoute
    $adapter = Get-NetAdapter -InterfaceIndex $Ctx.IfIndex -ErrorAction SilentlyContinue
    $link = if ($adapter) { "$($adapter.Status)" } else { 'Missing' }
    $dnsServer = if ($route -and $route.Dns) { $route.Dns } else { $Ctx.Dns }

    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($chk in Invoke-DnsChecks $dnsServer) { $checks.Add($chk) }

    $async = [System.Collections.Generic.List[object]]::new()
    if ($Ctx.GwPingable) { $async.Add((Start-Check 'GW' 'ping' $Ctx.Gateway)) }
    if ($Ctx.IspPingable) { $async.Add((Start-Check 'ISP' 'ping' $Ctx.IspHop)) }
    foreach ($tgt in $Cfg.RuPing) { $async.Add((Start-Check 'RU_PING' 'ping' $tgt)) }
    foreach ($tgt in $Cfg.IntlPing) { $async.Add((Start-Check 'INTL_PING' 'ping' $tgt)) }
    foreach ($tgt in $Cfg.RuHttp) { $async.Add((Start-Check 'RU_HTTP' 'http' $tgt)) }
    foreach ($tgt in $Cfg.IntlHttp) { $async.Add((Start-Check 'INTL_HTTP' 'http' $tgt)) }
    foreach ($tgt in $Cfg.CfHttp) { $async.Add((Start-Check 'CF_HTTP' 'http' $tgt)) }
    # Прореживание: первый цикл, каждый N-й и все циклы, пока длится сбой Cloudflare
    $cfBigDue = $Ctx.Cycle -le 1 -or (($Ctx.Cycle - 1) % $CfBigStep) -eq 0 -or $Ctx.LastVerdict -match 'CF_'
    if ($cfBigDue) { $async.Add((Start-Check 'CF_BIG' 'big' $Cfg.CfBig)) }
    foreach ($tgt in $Cfg.SteamHttp) { $async.Add((Start-Check 'STEAM_HTTP' 'http' $tgt)) }
    foreach ($tgt in $Ctx.SteamCm) { $async.Add((Start-Check 'STEAM_CM' 'tcp' $tgt)) }

    # ждём завершения всех (максимум ~9 с), фиксируя время ответа каждой проверки
    $waitSw = [Diagnostics.Stopwatch]::StartNew()
    do {
        $pending = 0
        foreach ($chk in $async) {
            if (-not $chk.Task -or $null -ne $chk.DoneMs) { continue }
            if ($chk.Task.IsCompleted) { $chk.DoneMs = [int]$chk.Sw.ElapsedMilliseconds } else { $pending++ }
        }
        if ($pending -eq 0) { break }
        Start-Sleep -Milliseconds 25
    } while ($waitSw.ElapsedMilliseconds -lt 9000)
    foreach ($chk in $async) { Complete-Check $chk; $checks.Add($chk) }

    $byCat = @{}
    foreach ($grp in $checks | Group-Object Cat) { $byCat[$grp.Name] = @($grp.Group) }
    $noneOk = { param($cat) $byCat.ContainsKey($cat) -and -not ($byCat[$cat] | Where-Object Ok) }
    $someOk = { param($cat) $byCat.ContainsKey($cat) -and [bool]($byCat[$cat] | Where-Object Ok) }

    $verdict = $null
    if ($link -ne 'Up' -or -not $route) { $verdict = 'LINK_DOWN' }
    elseif (& $noneOk 'GW') { $verdict = 'LAN_ROUTER' }
    elseif ((& $noneOk 'RU_PING') -and (& $noneOk 'INTL_PING') -and (& $noneOk 'RU_HTTP')) {
        $verdict = if (-not $Ctx.IspPingable) { 'PROVIDER' } elseif (& $someOk 'ISP') { 'PROVIDER_UPSTREAM' } else { 'PROVIDER_EDGE' }
    }
    elseif ((& $noneOk 'DNS') -and (& $someOk 'RU_PING')) { $verdict = 'DNS' }
    elseif (((& $someOk 'RU_PING') -or (& $someOk 'RU_HTTP')) -and (& $noneOk 'INTL_PING') -and (& $noneOk 'INTL_HTTP')) { $verdict = 'INTL_DOWN' }
    else {
        $flags = @()
        if (& $noneOk 'CF_HTTP') { $flags += 'CF_DOWN' } elseif (& $noneOk 'CF_BIG') { $flags += 'CF_THROTTLE' }
        if ((& $noneOk 'STEAM_HTTP') -and (& $noneOk 'STEAM_CM')) { $flags += 'STEAM_ALL' }
        elseif (& $noneOk 'STEAM_CM') { $flags += 'STEAM_CM' }
        elseif (& $noneOk 'STEAM_HTTP') { $flags += 'STEAM_WEB' }
        $explained = @('CF_HTTP', 'CF_BIG', 'STEAM_HTTP', 'STEAM_CM') | Where-Object { & $noneOk $_ }
        if ($checks | Where-Object { -not $_.Ok -and $_.Cat -notin $explained }) { $flags += 'LOSS' }
        $verdict = if ($flags) { $flags -join '+' } else { 'OK' }
    }

    $fails = ($checks | Where-Object { -not $_.Ok } | ForEach-Object {
        $short = $_.Target -replace '^https?://', '' -replace '/.*$', ''
        '{0}:{1}={2}' -f $_.Cat, $short, $_.Err
    }) -join '; '

    $row = [ordered]@{
        Time  = '{0:yyyy-MM-dd HH:mm:ss}' -f $now
        Iface = $(if ($route) { $route.Alias } else { '' })
        Link  = $link
    }
    foreach ($cat in 'GW', 'ISP', 'DNS', 'RU_PING', 'INTL_PING', 'RU_HTTP', 'INTL_HTTP', 'CF_HTTP', 'CF_BIG', 'STEAM_HTTP', 'STEAM_CM') {
        $row[$cat] = Format-Cat $byCat[$cat]
    }
    $row.Verdict = $verdict
    $row.Fails = $fails
    return [pscustomobject]$row
}

function Save-CycleRow($Row) {
    $csv = Join-Path $OutDir ('cycles_{0:yyyyMMdd}.csv' -f (Get-Date))
    $Row | Export-Csv -Path $csv -Append -NoTypeInformation -Encoding utf8
}

function Get-TraceTargets([string]$Verdict, $Ctx) {
    $targets = @{}
    foreach ($flag in $Verdict -split '\+') {
        switch -Regex ($flag) {
            '^LAN_ROUTER$' { $targets[$Ctx.Gateway] = $flag }
            '^PROVIDER' { $targets['77.88.8.8'] = $flag }
            '^INTL_DOWN$|^LOSS$' { $targets['8.8.8.8'] = $flag }
            '^CF_' { $targets['speed.cloudflare.com'] = $flag }
            '^STEAM_(CM|ALL)$' { $targets[(($Ctx.SteamCm | Select-Object -First 1) -replace ':\d+$', '')] = $flag }
            '^STEAM_(WEB|ALL)$' { $targets['store.steampowered.com'] = $flag }
        }
    }
    return $targets
}

function Update-State($Ctx, $Row) {
    if ($Row.Link -ne $Ctx.LastLink) {
        Write-NetEvent "LINK $($Ctx.LastLink) -> $($Row.Link) (адаптер ifIndex $($Ctx.IfIndex))" 'Magenta'
        $Ctx.LastLink = $Row.Link
    }
    $recovered = $Ctx.LastVerdict -ne 'OK' -and $Ctx.LastVerdict -ne 'START' -and $Row.Verdict -eq 'OK'
    if ($Row.Verdict -ne $Ctx.LastVerdict) {
        $color = if ($Row.Verdict -eq 'OK') { 'Green' } else { 'Red' }
        Write-NetEvent "VERDICT $($Ctx.LastVerdict) -> $($Row.Verdict) | $($Row.Fails)" $color
        if ($Row.Verdict -ne 'OK' -and $Row.Verdict -ne 'LINK_DOWN') {
            $targets = Get-TraceTargets $Row.Verdict $Ctx
            foreach ($tgt in $targets.Keys) {
                $last = $Ctx.LastTrace[$tgt]
                if ($last -and ((Get-Date) - $last).TotalSeconds -lt $Cfg.TraceCooldownS) { continue }
                $Ctx.LastTrace[$tgt] = Get-Date
                $file = Start-Trace $tgt $targets[$tgt]
                Write-NetEvent "TRACE $tgt -> $file" 'DarkCyan'
            }
        }
        $Ctx.LastVerdict = $Row.Verdict
    }
    if ($recovered -or ($Ctx.Cycle % $Cfg.PublicIpEvery -eq 0)) {
        $ip = Get-PublicIp
        if ($ip -and $ip -ne $Ctx.PublicIp) {
            Write-NetEvent "PUBLIC_IP $($Ctx.PublicIp) -> $ip (переподнялась сессия/NAT у провайдера или роутера)" 'Magenta'
            $Ctx.PublicIp = $ip
        }
    }
    Get-Job -State Completed -ErrorAction SilentlyContinue | Remove-Job
}

function Write-CycleLine($Row) {
    $color = if ($Row.Verdict -eq 'OK') { 'Green' } elseif ($Row.Verdict -in $HardVerdicts) { 'Red' } else { 'Yellow' }
    $line = '{0} {1,-20} gw {2,-9} ru {3,-9} intl {4,-9} dns {5,-5} cf {6,-9} cf256k {7,-9} steam {8,-9} cm {9}' -f
        $Row.Time.Substring(11), $Row.Verdict, $Row.GW, $Row.RU_PING, $Row.INTL_PING, $Row.DNS.Split(' ')[0],
        $Row.CF_HTTP, $Row.CF_BIG, $Row.STEAM_HTTP, $Row.STEAM_CM
    Write-Host $line -ForegroundColor $color
    if ($Row.Verdict -ne 'OK' -and $Row.Fails) { Write-Host "         $($Row.Fails)" -ForegroundColor DarkGray }
}

function Show-Status($Rows, [string]$Title) {
    # Итоговая таблица "что работает, что нет" по набору циклов
    $items = @($Rows)
    if (-not $items.Count) { return }
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host " $Title (циклов: $($items.Count), $($items[0].Time) .. $($items[-1].Time))" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan

    $linkDown = @($items | Where-Object { $_.Link -ne 'Up' }).Count
    $linkState, $linkColor = if ($linkDown -eq 0) { 'РАБОТАЕТ', 'Green' } elseif ($linkDown -eq $items.Count) { 'НЕ РАБОТАЕТ', 'Red' } else { 'ЧАСТИЧНО', 'Yellow' }
    Write-Host ('  {0,-42} {1,-12} {2,4}/{3,-4}' -f 'Сетевая карта (линк)', $linkState, ($items.Count - $linkDown), $items.Count) -ForegroundColor $linkColor

    foreach ($cat in $CatNames.Keys) {
        $okSum = 0
        $totalSum = 0
        $msList = @()
        foreach ($row in $items) {
            if ("$($row.$cat)" -match '^(\d+)/(\d+)(?: (\d+)ms)?') {
                $okSum += [int]$Matches[1]
                $totalSum += [int]$Matches[2]
                if ($Matches[3]) { $msList += [int]$Matches[3] }
            }
        }
        if (-not $totalSum) {
            Write-Host ('  {0,-42} {1}' -f $CatNames[$cat], 'не проверялось') -ForegroundColor DarkGray
            continue
        }
        $state, $color = if ($okSum -eq $totalSum) { 'РАБОТАЕТ', 'Green' } elseif ($okSum -eq 0) { 'НЕ РАБОТАЕТ', 'Red' } else { 'ЧАСТИЧНО', 'Yellow' }
        $avg = if ($msList.Count) { '~{0} ms' -f [int](($msList | Measure-Object -Average).Average) } else { '' }
        Write-Host ('  {0,-42} {1,-12} {2,4}/{3,-4} {4}' -f $CatNames[$cat], $state, $okSum, $totalSum, $avg) -ForegroundColor $color
    }

    Write-Host "`n  Вердикты:" -ForegroundColor Cyan
    foreach ($grp in $items | Group-Object Verdict | Sort-Object Count -Descending) {
        $color = if ($grp.Name -eq 'OK') { 'Green' } elseif ($grp.Name -in $HardVerdicts) { 'Red' } else { 'Yellow' }
        Write-Host ('    {0} - {1} из {2} циклов' -f $grp.Name, $grp.Count, $items.Count) -ForegroundColor $color
        foreach ($flag in $grp.Name -split '\+') {
            if ($flag -ne 'OK' -and $VerdictHelp.Contains($flag)) { Write-Host "        $flag`: $($VerdictHelp[$flag])" }
        }
    }
    $failSamples = $items | Where-Object { $_.Fails } | Select-Object -Last 3
    if ($failSamples) {
        Write-Host "`n  Последние ошибки:" -ForegroundColor Cyan
        foreach ($row in $failSamples) { Write-Host "    $($row.Time.Substring(11)) $($row.Fails)" -ForegroundColor DarkGray }
    }
}

function Invoke-QuickCheck([int]$Cycles = 3) {
    $route = Get-ActiveRoute
    if (-not $route) {
        Write-Host 'Нет маршрута по умолчанию: сетевой линк отсутствует (LINK_DOWN). Кабель / Wi-Fi / роутер' -ForegroundColor Red
        return
    }
    Write-Host 'Подготовка: поиск первого хопа провайдера, список серверов Steam, внешний IP...' -ForegroundColor Cyan
    $traceLines = & tracert.exe -d -w 700 -h 6 '77.88.8.8'
    $summary = [pscustomobject]@{
        IspHop   = Find-IspHop $traceLines $route.Gateway
        SteamCm  = Get-SteamCmEndpoints
        PublicIp = Get-PublicIp
    }
    $ctx = Initialize-Context $summary 'CHECK'
    Write-Host 'Прогревочный цикл...'
    $null = Invoke-Cycle $ctx
    $rows = foreach ($num in 1..$Cycles) {
        $row = Invoke-Cycle $ctx
        Save-CycleRow $row
        Write-CycleLine $row
        $row
        if ($num -lt $Cycles) { Start-Sleep -Seconds 5 }
    }
    Show-Status $rows 'Итог быстрой проверки'
}

function Start-Monitor([int]$Minutes = 0) {
    $startTime = Get-Date
    $canReadKeys = -not [Console]::IsInputRedirected
    Invoke-Cleanup $Retention
    # при автозапуске сеть может ещё не подняться: ждём маршрут по умолчанию
    if (-not (Get-ActiveRoute)) {
        Write-Host 'Нет сети (маршрута по умолчанию), жду подключения... (Q - выход)' -ForegroundColor Yellow
        Write-NetEvent 'WAIT нет маршрута по умолчанию при старте' 'Yellow'
        while (-not (Get-ActiveRoute)) {
            if (Wait-OrQuit 10000 $canReadKeys) { return }
        }
        Start-Sleep -Seconds 5
    }
    $summary = Save-Snapshot
    $ctx = Initialize-Context $summary
    Write-Host 'Прогревочный цикл (не пишется в лог: первый запуск HttpClient/TLS даёт ложные таймауты)...'
    $null = Invoke-Cycle $ctx
    $limitText = if ($Minutes) { "$Minutes мин" } else { 'до остановки' }
    Write-Host "Мониторинг каждые $IntervalSec с ($limitText), Cloudflare 256 КБ - раз в $CfBigStep цикл(ов). Данные: $OutDir" -ForegroundColor Cyan
    Write-Host 'Остановить: Q, Esc или Ctrl+C - в конце будет итоговый отчёт' -ForegroundColor Cyan

    $sessionRows = [System.Collections.Generic.List[object]]::new()
    $monitorStart = Get-Date
    $cleanupDay = (Get-Date).Date
    if ($canReadKeys) { [Console]::TreatControlCAsInput = $true }
    try {
        while ($true) {
            $loopSw = [Diagnostics.Stopwatch]::StartNew()
            if ((Get-Date).Date -ne $cleanupDay) { Invoke-Cleanup $Retention; $cleanupDay = (Get-Date).Date }
            $ctx.Cycle++
            $row = Invoke-Cycle $ctx
            Save-CycleRow $row
            $sessionRows.Add($row)
            Write-CycleLine $row
            Update-State $ctx $row
            if ($Minutes -and ((Get-Date) - $monitorStart).TotalMinutes -ge $Minutes) { break }
            if (Wait-OrQuit ($IntervalSec * 1000 - $loopSw.ElapsedMilliseconds) $canReadKeys) { break }
        }
    } finally {
        if ($canReadKeys) { [Console]::TreatControlCAsInput = $false }
        Write-NetEvent 'STOP' 'Cyan'
    }
    Show-Report $startTime -Brief
    Show-Status $sessionRows 'Итог за сеанс мониторинга'
}

# ----------------------------------------------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------------------------------------------
function Show-Report([datetime]$From, [switch]$Brief) {
    $rows = @(Get-ChildItem $OutDir -Filter 'cycles_*.csv' | Sort-Object Name | ForEach-Object { Import-Csv $_.FullName } |
        ForEach-Object { $_ | Add-Member -NotePropertyName Ts -NotePropertyValue ([datetime]::ParseExact($_.Time, 'yyyy-MM-dd HH:mm:ss', $null)) -PassThru } |
        Where-Object { $_.Ts -ge $From } | Sort-Object Ts)
    if (-not $rows.Count) { Write-Host "Нет данных мониторинга с $From в $OutDir"; return }

    $gapSec = [Math]::Max(60, $IntervalSec * 4)
    $incidents = [System.Collections.Generic.List[object]]::new()
    $current = $null
    $prevTs = $null
    $stats = @{}
    foreach ($row in $rows) {
        if ($prevTs -and ($row.Ts - $prevTs).TotalSeconds -gt $gapSec) {
            if ($current) { $incidents.Add($current); $current = $null }
            $incidents.Add([pscustomobject]@{ Start = $prevTs; End = $row.Ts; Verdict = 'NO_DATA'; Cycles = 0; Sample = '' })
        }
        $stats[$row.Verdict] = 1 + [int]$stats[$row.Verdict]
        if ($row.Verdict -eq 'OK') {
            if ($current) { $current.End = $row.Ts; $incidents.Add($current); $current = $null }
        } elseif ($current -and $current.Verdict -eq $row.Verdict) {
            $current.Cycles++
        } else {
            if ($current) { $current.End = $row.Ts; $incidents.Add($current) }
            $current = [pscustomobject]@{ Start = $row.Ts; End = $null; Verdict = $row.Verdict; Cycles = 1; Sample = $row.Fails }
        }
        $prevTs = $row.Ts
    }
    if ($current) { $current.End = $prevTs; $incidents.Add($current) }

    Write-Host ("`nПериод: {0:yyyy-MM-dd HH:mm} .. {1:yyyy-MM-dd HH:mm}, циклов: {2}" -f $rows[0].Ts, $rows[-1].Ts, $rows.Count) -ForegroundColor Cyan
    Write-Host "`nРаспределение вердиктов:" -ForegroundColor Cyan
    $stats.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        '  {0,-28} {1,6} циклов  {2,6:P1}' -f $_.Key, $_.Value, ($_.Value / $rows.Count)
    } | Write-Host

    Write-Host "`nИнциденты (последние 60):" -ForegroundColor Cyan
    if (-not $incidents.Count) { Write-Host '  нет' -ForegroundColor Green }
    $incidents | Select-Object -Last 60 | ForEach-Object {
        $dur = $_.End - $_.Start
        $color = if ($_.Verdict -eq 'NO_DATA') { 'DarkGray' } elseif ($_.Verdict -in $HardVerdicts) { 'Red' } else { 'Yellow' }
        Write-Host ('  {0:MM-dd HH:mm:ss} - {1:HH:mm:ss}  {2,8}  {3,-24} {4}' -f $_.Start, $_.End, $dur.ToString('hh\:mm\:ss'), $_.Verdict, $_.Sample) -ForegroundColor $color
    }

    Write-Host "`nСобытия монитора (линк, внешний IP, старт/стоп):" -ForegroundColor Cyan
    if (Test-Path $EventsFile) {
        Get-Content $EventsFile | Where-Object {
            $_ -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)' -and [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null) -ge $From -and
            $_ -match '^\S+ \S+ (LINK|PUBLIC_IP|START|CHECK|STOP)\b'
        } | ForEach-Object { "  $_" } | Write-Host
    }

    Write-Host "`nWindows: подключения/отключения сети (NetworkProfile 10000/10001):" -ForegroundColor Cyan
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NetworkProfile/Operational'; Id = 10000, 10001; StartTime = $From } -ErrorAction Stop |
            Sort-Object TimeCreated | ForEach-Object {
                $state = if ($_.Id -eq 10001) { 'ОТКЛЮЧЕНА' } else { 'подключена' }
                '  {0:yyyy-MM-dd HH:mm:ss} {1,-10} {2}' -f $_.TimeCreated, $state, $_.Properties[0].Value
            } | Write-Host
    } catch { Write-Host '  нет событий' }

    if (-not $Brief) {
        Show-Status @($rows[-1]) 'Последнее зафиксированное состояние'
        Show-Status $rows 'Сводка за весь период'
    }
}

# ----------------------------------------------------------------------------------------------------------------
# Menu
# ----------------------------------------------------------------------------------------------------------------
function Show-Menu {
    while ($true) {
        Write-Host ''
        Write-Host '================ netmon: диагностика сети / Steam / РКН ================' -ForegroundColor Cyan
        Write-Host '  1  Быстрая проверка (~1 мин): что работает, что нет'
        Write-Host '  2  Снапшот сети: сохранить маршруты и конфиг (~1.5 мин)'
        Write-Host '  3  Снапшот + pathping: потери на каждом хопе (~5-7 мин)'
        Write-Host '  4  Мониторинг до остановки (Q / Esc / Ctrl+C), в конце отчёт'
        Write-Host '  5  Мониторинг на N минут, в конце отчёт'
        Write-Host '  6  Отчёт за последние N часов'
        Write-Host '  7  Сравнить маршруты двух последних снапшотов'
        Write-Host '  8  Открыть папку с данными'
        $autostartText = if (Get-AutostartState) { 'ВКЛЮЧЁН - выбрать, чтобы выключить' } else { 'выключен - выбрать, чтобы включить' }
        Write-Host "  9  Автозапуск мониторинга при входе в Windows (сейчас: $autostartText)"
        $retentionText = if ($Retention -gt 0) { "старше $Retention дн." } else { 'отключена' }
        Write-Host "  10 Очистить старые данные ($retentionText; при мониторинге - автоматически раз в сутки)"
        Write-Host '  0  Выход'
        $choice = (Read-Host 'Выберите пункт').Trim()
        try {
            switch ($choice) {
                '1' { Invoke-QuickCheck 3 }
                '2' { $null = Save-Snapshot }
                '3' { $null = Save-Snapshot -WithPathping }
                '4' { Start-Monitor 0 }
                '5' { Start-Monitor (Read-Number 'Сколько минут мониторить' 30) }
                '6' { Show-Report (Get-Date).AddHours(-(Read-Number 'За сколько последних часов' 24)) }
                '7' { Compare-Snapshots }
                '8' { Invoke-Item $OutDir }
                '9' { if (Get-AutostartState) { Disable-Autostart } else { Enable-Autostart } }
                '10' { Invoke-Cleanup $Retention -Loud }
                '0' { return }
                default { Write-Host 'Нет такого пункта' -ForegroundColor Yellow; continue }
            }
        } catch {
            Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        }
        $null = Read-Host "`nEnter - вернуться в меню"
    }
}

$failed = $false
try {
    switch ($Mode) {
        'Menu' { Show-Menu }
        'Check' { Invoke-QuickCheck 3 }
        'Snapshot' { $null = Save-Snapshot -WithPathping:$Deep }
        'Diff' { Compare-Snapshots }
        'Report' { Show-Report $(if ($Hours -gt 0) { (Get-Date).AddHours(-$Hours) } else { $Since }) }
        'Monitor' { Start-Monitor $DurationMin }
        'AutostartOn' { Enable-Autostart }
        'AutostartOff' { Disable-Autostart }
        'Cleanup' { Invoke-Cleanup $Retention -Loud }
    }
} catch {
    $failed = $true
    Write-Host "Ошибка: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
} finally {
    # окно, открытое только под этот скрипт, иначе закроется сразу и результат не будет виден
    $needPause = ($Mode -ne 'Menu' -or $failed) -and -not $NoPause -and -not [Console]::IsInputRedirected
    if ($needPause -and (Test-OwnConsole)) { $null = Read-Host "`nEnter - закрыть окно" }
}
if ($failed) { exit 1 }
