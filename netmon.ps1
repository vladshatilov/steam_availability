#Requires -Version 7.4
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
    pwsh -File netmon.ps1 -Mode Report -Hours 24 [-Out report.txt]
    pwsh -File netmon.ps1 -Mode Diff
    pwsh -File netmon.ps1 -Mode AutostartOn        # запускать мониторинг при входе в Windows (AutostartOff - выключить)
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Check', 'Monitor', 'Snapshot', 'Report', 'Diff', 'AutostartOn', 'AutostartOff', 'Cleanup')]
    [string]$Mode = 'Menu',
    [string]$OutDir = (Join-Path $PSScriptRoot 'data'),
    [ValidateRange(5, 3600)]
    [int]$IntervalSec = 15,
    [int]$CfBigEvery = -1,            # качать 256 КБ с Cloudflare раз в N циклов; -1 = из $Cfg
    [int]$DurationMin = 0,
    [int]$Hours = 0,                  # для Report: за сколько последних часов (0 = 7 дней или -Since)
    [datetime]$Since = (Get-Date).AddDays(-7),
    [string]$Out = '',                # для Report: сохранить отчёт в файл
    [int]$RetentionDays = -1,         # хранить данные N дней; -1 = из $Cfg, 0 = не чистить
    [switch]$Deep,
    [switch]$NoNotify,                # не показывать уведомления Windows при сбоях
    [switch]$NoPause                  # не ждать Enter в конце (для запуска из планировщика)
)

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------------------------------------------
# Настройки
# ----------------------------------------------------------------------------------------------------------------
$Cfg = @{
    RuPing          = @('77.88.8.8', '77.88.8.1')                     # Яндекс DNS: точно внутри РФ
    IntlPing        = @('1.1.1.1', '8.8.8.8', '9.9.9.9')              # Cloudflare, Google, Quad9
    Ipv6Ping        = @('2001:4860:4860::8888', '2606:4700:4700::1111')   # проверяется, только если есть глобальный IPv6
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
    # Steam иногда отдаёт CM в Далласе/Гонконге; клиент из РФ к ним не ходит. Берём только эти дата-центры (префикс поля dc)
    SteamCmDcs      = @('sto', 'fra', 'ams', 'waw', 'hel', 'vie', 'lhr', 'par', 'mad')
    SteamCmFallback = @('cmp1-fra1.steamserver.net:27018', 'cmp1-fra2.steamserver.net:27020', 'cmp2-sto1.steamserver.net:27022')
    IspHop          = ''        # IP первого хопа провайдера; пусто = определить автоматически через tracert
    PublicIpEvery   = 20        # проверять внешний IP каждые N циклов (и после восстановления от серьёзного сбоя)
    TraceCooldownS  = 300       # не чаще одного tracert на цель за N секунд
    TracesPerFlag   = 2         # сколько целей трассировать на один флаг вердикта
    LossMinFails    = 2         # LOSS: столько разных проверок не прошло в одном цикле, или одна и та же два цикла подряд
    ReprobeEvery    = 40        # раз в N циклов заново проверять, не начали ли роутер/хоп провайдера отвечать на ping
    Notify          = $true     # уведомления Windows о сбое и восстановлении
    NotifyHardAfter = 2         # серьёзный сбой (провайдер, роутер, DNS, зарубеж): уведомить после N циклов подряд
    NotifySoftAfter = 4         # Cloudflare / Steam / IPv6: после N циклов подряд (~1 мин)
    ReportMinLoss   = 2         # в отчёте не показывать инциденты LOSS короче N циклов
    RetentionDays   = 10        # удалять CSV, трассировки, снапшоты, отчёты и строки events.log старше N дней (0 = не удалять)
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
    'CF_THROTTLE'       = 'Cloudflare отвечает, но 256 КБ не качаются за 6 с (зависание после части данных): типичное замедление ТСПУ'
    'STEAM_ALL'         = 'зарубеж работает, а Steam целиком (web + CM) нет: Steam лежит или блокировка'
    'STEAM_CM'          = 'CM-серверы Steam недоступны по TCP: клиент Steam уходит в "нет соединения", магазин может работать'
    'STEAM_WEB'         = 'store/community/api не открываются, CM-серверы доступны'
    'IPV6'              = 'IPv4 работает, IPv6 нет: проблема IPv6 у провайдера или роутера'
    'LOSS'              = 'не прошло несколько проверок или одна и та же два цикла подряд (потери/таймауты)'
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
    IPV6       = 'IPv6: ping (Google, Cloudflare)'
}

$HardVerdicts = @('LINK_DOWN', 'LAN_ROUTER', 'PROVIDER_EDGE', 'PROVIDER_UPSTREAM', 'PROVIDER', 'DNS', 'INTL_DOWN')

# Какие категории проверок объясняет каждый флаг вердикта (для трассировок и LOSS)
$FlagCats = @{
    CF_DOWN     = @('CF_HTTP', 'CF_BIG')
    CF_THROTTLE = @('CF_BIG')
    STEAM_ALL   = @('STEAM_HTTP', 'STEAM_CM')
    STEAM_CM    = @('STEAM_CM')
    STEAM_WEB   = @('STEAM_HTTP')
    IPV6        = @('IPV6')
}

$SocketErrorCodes = @{
    ConnectionReset    = 'reset'
    ConnectionAborted  = 'reset'
    TimedOut           = 'timeout'
    ConnectionRefused  = 'refused'
    HostNotFound       = 'dns'
    NoData             = 'dns'
    TryAgain           = 'dns'
    NetworkUnreachable = 'unreachable'
    HostUnreachable    = 'unreachable'
    NetworkDown        = 'unreachable'
}

$HttpRequestErrors = @{
    NameResolutionError   = 'dns'
    SecureConnectionError = 'tls'
    ResponseEnded         = 'eof'
    ProxyTunnelError      = 'proxy'
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$EventsFile = Join-Path $OutDir 'events.log'
$TracesDir = Join-Path $OutDir 'traces'
$ReportsDir = Join-Path $OutDir 'reports'

# HttpClient без прокси (проверяем реальный путь) и без keep-alive (каждый раз новый TCP+TLS, чтобы DPI был виден)
$Handler = [System.Net.Http.HttpClientHandler]::new()
$Handler.UseProxy = $false
$Handler.AllowAutoRedirect = $false
$Http = [System.Net.Http.HttpClient]::new($Handler)
$Http.Timeout = [TimeSpan]::FromSeconds(8)
$Http.DefaultRequestHeaders.ConnectionClose = $true
$Http.DefaultRequestHeaders.UserAgent.ParseAdd('Mozilla/5.0 (Windows NT 10.0; Win64; x64) netmon/1.1')
$Http.DefaultRequestHeaders.CacheControl = [System.Net.Http.Headers.CacheControlHeaderValue]::new()
$Http.DefaultRequestHeaders.CacheControl.NoCache = $true

# Загрузка с подсчётом полученных байт: при замедлении ТСПУ видно, на каком объёме соединение "замёрзло"
if (-not ('NetmonDownload' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public static class NetmonDownload {
    public static async Task<long> Run(HttpClient client, string url, long[] progress, CancellationToken token) {
        using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        using var stream = await resp.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        var buffer = new byte[16384];
        int read;
        while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false)) > 0) {
            Interlocked.Add(ref progress[0], read);
        }
        return Interlocked.Read(ref progress[0]);
    }
}
'@
}

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
function Write-NetEvent([string]$Text, [string]$Color = 'Cyan', [string]$Time = '') {
    # $Time: время цикла из строки CSV, чтобы события совпадали со строками cycles_*.csv
    $stamp = if ($Time) { $Time } else { '{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date) }
    $line = '{0} {1}' -f $stamp, $Text
    Add-Content -Path $EventsFile -Value $line -Encoding utf8
    Write-Host "  >> $line" -ForegroundColor $Color
}

function Get-ShortError([Exception]$Ex) {
    # Классификация по типам и кодам ошибок, а не по тексту: на русской Windows тексты локализованы
    $chain = [System.Collections.Generic.List[Exception]]::new()
    for ($cur = $Ex; $cur; $cur = $cur.InnerException) { $chain.Add($cur) }

    $inTls = [bool]($chain | Where-Object {
        $_ -is [System.Security.Authentication.AuthenticationException] -or
        ($_ -is [System.Net.Http.HttpRequestException] -and "$($_.HttpRequestError)" -eq 'SecureConnectionError')
    })
    foreach ($item in $chain) {
        if ($item -is [System.Net.Sockets.SocketException] -and ($code = $SocketErrorCodes["$($item.SocketErrorCode)"])) {
            if ($code -eq 'reset' -and $inTls) { return 'tls_reset' }     # обрыв во время TLS-рукопожатия: типичный DPI по SNI
            return $code
        }
    }
    foreach ($item in $chain) {
        if ($item -is [System.OperationCanceledException] -or $item -is [System.TimeoutException]) { return 'timeout' }
    }
    foreach ($item in $chain) {
        if ($item -is [System.Net.Http.HttpRequestException] -and ($code = $HttpRequestErrors["$($item.HttpRequestError)"])) { return $code }
    }
    if ($inTls) { return 'tls' }

    # запасной вариант для английских текстов (PingException и прочее без кодов)
    $text = ($chain | ForEach-Object { "$($_.GetType().Name): $($_.Message)" }) -join ' | '
    switch -Regex ($text) {
        'timed? ?out|Timeout' { return 'timeout' }
        'forcibly closed|reset by peer|10054' { return 'reset' }
        'refused|10061' { return 'refused' }
        'No such host|11001|nodename' { return 'dns' }
        'unreachable|10051|10065' { return 'unreachable' }
        'unexpected EOF|0 bytes from the transport' { return 'eof' }
    }
    $last = $chain[$chain.Count - 1]
    $msg = ('{0}: {1}' -f $last.GetType().Name, $last.Message) -replace '\s+', ' '
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

function Test-RouteChanged($Ctx, $Route) {
    return [bool]($Route -and ($Route.IfIndex -ne $Ctx.IfIndex -or "$($Route.Gateway)" -ne "$($Ctx.Gateway)"))
}

function Test-Ipv6Available {
    # маршрут ::/0 бывает и без глобального адреса (как сейчас у многих провайдеров) - тогда IPv6 не проверяем
    $routes = @(Get-NetRoute -DestinationPrefix '::/0' -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object NextHop -NE '::')
    foreach ($route in $routes) {
        $global = Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -match '^[23][0-9a-f]{3}:' -and $_.AddressState -eq 'Preferred' }
        if ($global) { return $true }
    }
    return $false
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

function Resolve-IspHop([string]$Gateway) {
    # короткий tracert (6 хопов), чтобы найти первый хоп провайдера за несколько секунд
    if ($Cfg.IspHop) { return $Cfg.IspHop }
    $traceLines = & tracert.exe -d -w 700 -h 6 '77.88.8.8'
    return Find-IspHop $traceLines $Gateway
}

function Test-Pingable([string]$Target) {
    $pinger = [System.Net.NetworkInformation.Ping]::new()
    try {
        foreach ($attempt in 1..3) {
            try { if ($pinger.Send($Target, 1000).Status -eq 'Success') { return $true } } catch { }
        }
        return $false
    } finally {
        $pinger.Dispose()
    }
}

function Get-PublicIp {
    foreach ($url in 'https://api.ipify.org', 'https://www.cloudflare.com/cdn-cgi/trace', 'https://ifconfig.me/ip') {
        $cts = [Threading.CancellationTokenSource]::new(5000)
        try {
            $text = $Http.GetStringAsync($url, $cts.Token).GetAwaiter().GetResult()
            if ($text -match '(?m)^(?:ip=)?(\d{1,3}(?:\.\d{1,3}){3})\s*$') { return $Matches[1] }
        } catch { } finally { $cts.Dispose() }
    }
    return ''
}

function Select-SteamCmEndpoints($ServerList, [string[]]$DcPrefixes) {
    # до 3 websockets-CM из разных ближних дата-центров + до 2 netfilter (UDP/TCP 27017+)
    $near = @($ServerList | Where-Object { $_.endpoint -and $_.dc -and (($_.dc -replace '\d+$', '') -in $DcPrefixes) })
    $ws = @($near | Where-Object type -EQ 'websockets' | Group-Object dc | ForEach-Object { $_.Group[0] } | Select-Object -First 3)
    $nf = @($near | Where-Object type -EQ 'netfilter' | Select-Object -First 2)
    return @(@($ws) + @($nf) | ForEach-Object { [pscustomobject]@{ endpoint = $_.endpoint; dc = $_.dc; type = $_.type } })
}

function Get-SteamCmEndpoints {
    $cache = Join-Path $OutDir 'steam_cm.json'
    $cts = [Threading.CancellationTokenSource]::new(8000)
    try {
        $raw = $Http.GetStringAsync('https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0', $cts.Token).GetAwaiter().GetResult()
        $list = @(($raw | ConvertFrom-Json).response.serverlist)
        $selected = @(Select-SteamCmEndpoints $list $Cfg.SteamCmDcs)
        if ($selected.Count) {
            ConvertTo-Json -InputObject $selected | Set-Content -Path $cache -Encoding utf8
            return @($selected.endpoint)
        }
        $dcs = ($list.dc | Select-Object -Unique) -join ','
        Write-Host "  Steam отдал CM только в дальних дата-центрах ($dcs), беру кэш/fallback" -ForegroundColor Yellow
    } catch {
        Write-Host "  Не удалось получить список CM Steam ($(Get-ShortError $_.Exception)), беру кэш/fallback" -ForegroundColor Yellow
    } finally {
        $cts.Dispose()
    }
    if (Test-Path $cache) {
        # старый формат кэша (просто строки без dc) отбрасывается фильтром
        $cached = @(Select-SteamCmEndpoints @(Get-Content $cache -Raw | ConvertFrom-Json) $Cfg.SteamCmDcs)
        if ($cached.Count) { return @($cached.endpoint) }
    }
    return $Cfg.SteamCmFallback
}

function Get-CheckHost($Check) {
    return $Check.Target -replace '^https?://', '' -replace '/.*$', '' -replace ':\d+$', ''
}

function Start-Trace([string]$Target, [string]$Reason) {
    New-Item -ItemType Directory -Force -Path $TracesDir | Out-Null
    $safe = $Target -replace '[^\w\.-]', '_'
    $file = Join-Path $TracesDir ('{0:yyyyMMdd_HHmmss}_{1}_{2}.txt' -f (Get-Date), $Reason, $safe)
    $job = Start-ThreadJob -ScriptBlock $SaveNativeOutput -ArgumentList $file, 'tracert.exe', @('-d', '-w', '800', '-h', '25', $Target)
    return [pscustomobject]@{ File = $file; Job = $job }
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
    foreach ($dir in $TracesDir, $ReportsDir) {
        if (Test-Path $dir) { $oldFiles += Get-ChildItem $dir -File }
    }
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

function Enter-MonitorLock {
    # один мониторинг на папку данных: второй экземпляр писал бы в те же CSV и events.log
    $fullPath = [IO.Path]::GetFullPath($OutDir).TrimEnd('\').ToLowerInvariant()
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($fullPath))).Substring(0, 16)
    $mutex = [Threading.Mutex]::new($false, "Local\netmon-monitor-$hash")
    try {
        $acquired = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $acquired = $true      # прошлый экземпляр упал, не освободив блокировку
    }
    if ($acquired) { return $mutex }
    $mutex.Dispose()
    return $null
}

function New-Notifier {
    if ($NoNotify -or -not $Cfg.Notify) { return $null }
    try {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $icon = [System.Windows.Forms.NotifyIcon]::new()
        $icon.Icon = [System.Drawing.SystemIcons]::Information
        $icon.Text = 'netmon'
        $icon.Visible = $true
        return $icon
    } catch {
        Write-Host "  Уведомления Windows недоступны: $($_.Exception.Message)" -ForegroundColor DarkGray
        return $null
    }
}

function Send-Notification($Notifier, [string]$Title, [string]$Text, [string]$Kind = 'Warning') {
    if (-not $Notifier) { return }
    try { $Notifier.ShowBalloonTip(10000, $Title, $Text, [System.Windows.Forms.ToolTipIcon]::$Kind) } catch { }
}

# ----------------------------------------------------------------------------------------------------------------
# Snapshot / Diff
# ----------------------------------------------------------------------------------------------------------------
function Start-Snapshot([switch]$WithPathping) {
    # Быстрая часть (конфиг) синхронно, трассировки - в фоновых ThreadJob. Дописывает Complete-Snapshot
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
    # имя файла -> цель; CM пишется в постоянный tracert_steam_cm.txt, чтобы Diff мог сравнить снапшоты
    $targets = [ordered]@{
        '77.88.8.8'              = '77.88.8.8'
        '1.1.1.1'                = '1.1.1.1'
        '8.8.8.8'                = '8.8.8.8'
        'store.steampowered.com' = 'store.steampowered.com'
        'speed.cloudflare.com'   = 'speed.cloudflare.com'
    }
    if ($cmHost) { $targets['steam_cm'] = $cmHost }

    Write-Host "  tracert к $($targets.Values -join ', ') (параллельно, до ~1.5 мин)..."
    $jobs = @(foreach ($name in $targets.Keys) {
        Start-ThreadJob -ScriptBlock $SaveNativeOutput -ArgumentList (Join-Path $dir "tracert_$name.txt"), 'tracert.exe', @('-d', '-w', '800', '-h', '25', $targets[$name])
    })
    if ($WithPathping) {
        Write-Host '  pathping к 1.1.1.1 и Steam CM (несколько минут)...'
        $pathTargets = [ordered]@{ '1.1.1.1' = '1.1.1.1' }
        if ($cmHost) { $pathTargets['steam_cm'] = $cmHost }
        $jobs += foreach ($name in $pathTargets.Keys) {
            Start-ThreadJob -ScriptBlock $SaveNativeOutput -ArgumentList (Join-Path $dir "pathping_$name.txt"), 'pathping.exe', @('-n', '-q', '50', '-w', '500', $pathTargets[$name])
        }
    }
    return [pscustomobject]@{ Dir = $dir; Jobs = $jobs; Route = $route; SteamCm = $cms; PublicIp = '' }
}

function Complete-Snapshot($Pending, [switch]$Wait) {
    # без -Wait: $null, пока трассировки ещё идут
    if (-not $Wait -and ($Pending.Jobs | Where-Object { $_.State -in 'NotStarted', 'Running' })) { return $null }
    $Pending.Jobs | Wait-Job | Remove-Job -Force
    if (-not $Pending.PublicIp) { $Pending.PublicIp = Get-PublicIp }
    $route = $Pending.Route
    $traceFile = Join-Path $Pending.Dir 'tracert_77.88.8.8.txt'
    $summary = [ordered]@{
        Time      = '{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date)
        Interface = $route.Alias
        Adapter   = $route.Description
        Gateway   = $route.Gateway
        Dns       = $route.Dns
        IspHop    = $(if (Test-Path $traceFile) { Find-IspHop (Get-Content $traceFile) $route.Gateway } else { $Cfg.IspHop })
        PublicIp  = $Pending.PublicIp
        SteamCm   = $Pending.SteamCm
    }
    $summary | ConvertTo-Json | Set-Content (Join-Path $Pending.Dir 'summary.json') -Encoding utf8
    if ($Wait) {
        Write-Host ''
        foreach ($key in $summary.Keys) { Write-Host ('  {0,-10} {1}' -f $key, ($summary[$key] -join ', ')) }
    }
    return [pscustomobject]$summary
}

function Stop-Snapshot($Pending) {
    # мониторинг остановили раньше, чем закончились трассировки: недоделанный снапшот не оставляем
    $Pending.Jobs | Stop-Job -ErrorAction SilentlyContinue
    $Pending.Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
    Remove-Item $Pending.Dir -Recurse -Force -ErrorAction SilentlyContinue
}

function Save-Snapshot([switch]$WithPathping) {
    $pending = Start-Snapshot -WithPathping:$WithPathping
    $pending.PublicIp = Get-PublicIp       # пока идут трассировки
    return Complete-Snapshot $pending -Wait
}

function Compare-Snapshots {
    # только завершённые снапшоты (с summary.json)
    $snaps = @(Get-ChildItem (Join-Path $OutDir 'snapshots') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'summary.json') } | Sort-Object Name | Select-Object -Last 2)
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
        if ($file.Name -eq 'tracert_steam_cm.txt') {
            if (-not (Test-Path $oldFile)) {
                # снапшоты старой версии: файл назывался по имени CM-хоста
                $oldFile = (Get-ChildItem $old.FullName -Filter 'tracert_cmp*.txt' | Select-Object -First 1).FullName
            }
            $cmOld = ($sumOld.SteamCm | Select-Object -First 1) -replace ':\d+$', ''
            $cmNew = ($sumNew.SteamCm | Select-Object -First 1) -replace ':\d+$', ''
            if ($cmOld -ne $cmNew) { Write-Host "  Steam CM: цель трассировки сменилась $cmOld -> $cmNew, маршруты сравнимы условно" -ForegroundColor DarkYellow }
        }
        if (-not $oldFile -or -not (Test-Path $oldFile)) { continue }
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
        IfIndex         = $route.IfIndex
        Alias           = $route.Alias
        Gateway         = $route.Gateway
        Dns             = $route.Dns
        GwPingable      = Test-Pingable $route.Gateway
        IspHop          = $ispHop
        IspPingable     = [bool]($ispHop -and (Test-Pingable $ispHop))
        HasIpv6         = Test-Ipv6Available
        SteamCm         = @($Summary.SteamCm)
        PublicIp        = $Summary.PublicIp
        Cycle           = 0
        LastVerdict     = 'START'
        LastLink        = 'Up'
        LastTrace       = @{}
        TraceJobs       = [System.Collections.Generic.List[object]]::new()
        PrevUnexplained = @()
        BadStreak       = 0
        BadSince        = ''
        NotifiedVerdict = ''
        Notifier        = $null
    }
    if (-not $ctx.GwPingable) { Write-Host "Роутер $($ctx.Gateway) не отвечает на ping: проверка роутера отключена (перепроверка раз в $($Cfg.ReprobeEvery) циклов)" -ForegroundColor Yellow }
    if ($ispHop -and -not $ctx.IspPingable) { Write-Host "Первый хоп провайдера $ispHop не отвечает на ping: PROVIDER_EDGE/UPSTREAM различать не будем" -ForegroundColor Yellow }
    Write-NetEvent ("{0} iface='{1}' gw={2} dns={3} isp_hop={4} ipv6={5} public_ip={6} steam_cm={7}" -f
        $Label, $ctx.Alias, $ctx.Gateway, $ctx.Dns, $ispHop, $ctx.HasIpv6, $ctx.PublicIp, ($ctx.SteamCm -join ','))
    return $ctx
}

function Update-Context($Ctx, $Route) {
    # Сменился маршрут по умолчанию (кабель <-> Wi-Fi, VPN, другой роутер): всё, что привязано к старому, пересчитываем
    Write-NetEvent ("ROUTE_CHANGE '{0}' gw {1} -> '{2}' gw {3}" -f $Ctx.Alias, $Ctx.Gateway, $Route.Alias, $Route.Gateway) 'Magenta'
    $summary = [pscustomobject]@{ IspHop = Resolve-IspHop $Route.Gateway; SteamCm = $Ctx.SteamCm; PublicIp = $Ctx.PublicIp }
    $new = Initialize-Context $summary 'ROUTE'
    foreach ($field in 'Cycle', 'LastVerdict', 'LastLink', 'LastTrace', 'TraceJobs', 'PrevUnexplained', 'BadStreak', 'BadSince', 'NotifiedVerdict', 'Notifier') {
        $new.$field = $Ctx.$field
    }
    return $new
}

function Update-Reachability($Ctx) {
    # роутер/хоп провайдера могли не ответить на ping при старте случайно
    if (-not $Ctx.GwPingable -and (Test-Pingable $Ctx.Gateway)) {
        $Ctx.GwPingable = $true
        Write-NetEvent "PROBE роутер $($Ctx.Gateway) отвечает на ping: проверка роутера включена" 'DarkCyan'
    }
    if ($Ctx.IspHop -and -not $Ctx.IspPingable -and (Test-Pingable $Ctx.IspHop)) {
        $Ctx.IspPingable = $true
        Write-NetEvent "PROBE хоп провайдера $($Ctx.IspHop) отвечает на ping: PROVIDER_EDGE/UPSTREAM различаются" 'DarkCyan'
    }
}

function Start-Check([string]$Cat, [string]$Kind, [string]$Target) {
    $chk = [pscustomobject]@{
        Cat = $Cat; Kind = $Kind; Target = $Target; Task = $null; Client = $null; Cts = $null; Progress = $null
        Sw = [Diagnostics.Stopwatch]::StartNew(); DoneMs = $null; Ok = $false; Ms = $null; Err = ''
    }
    try {
        switch ($Kind) {
            'ping' {
                $chk.Client = [System.Net.NetworkInformation.Ping]::new()
                $chk.Task = $chk.Client.SendPingAsync($Target, 1500)
            }
            'tcp' {
                $hostName, $port = $Target -split ':(?=\d+$)'
                $chk.Client = [System.Net.Sockets.TcpClient]::new()
                $chk.Task = $chk.Client.ConnectAsync($hostName, [int]$port)
            }
            'http' { $chk.Task = $Http.GetAsync($Target, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead) }
            'big' {
                $chk.Cts = [Threading.CancellationTokenSource]::new($Cfg.CfBigTimeoutMs)
                $chk.Progress = [long[]]::new(1)
                $chk.Task = [NetmonDownload]::Run($Http, $Target, $chk.Progress, $chk.Cts.Token)
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
    # 256 КБ: сколько успело прийти до обрыва/таймаута. timeout@16384 = классическое "замерзание" ТСПУ
    if (-not $Chk.Ok -and $Chk.Kind -eq 'big' -and $Chk.Progress -and $Chk.Progress[0] -gt 0) { $Chk.Err += "@$($Chk.Progress[0])" }
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

function Get-Verdict {
    # Чистая функция: по результатам проверок одного цикла -> вердикт. Покрыта тестами в tests\
    param(
        $Checks,
        [string]$Link = 'Up',
        [bool]$HasRoute = $true,
        [bool]$IspPingable = $true,
        [string[]]$PrevUnexplained = @(),
        [int]$LossMinFails = $Cfg.LossMinFails
    )
    $byCat = @{}
    foreach ($grp in @($Checks) | Where-Object { $_ } | Group-Object Cat) { $byCat[$grp.Name] = @($grp.Group) }
    $noneOk = { param($cat) $byCat.ContainsKey($cat) -and -not ($byCat[$cat] | Where-Object Ok) }
    $someOk = { param($cat) $byCat.ContainsKey($cat) -and [bool]($byCat[$cat] | Where-Object Ok) }
    $result = { param($verdict, $unexplained) [pscustomobject]@{ Verdict = $verdict; Unexplained = @($unexplained) } }

    if ($Link -ne 'Up' -or -not $HasRoute) { return & $result 'LINK_DOWN' @() }
    if (& $noneOk 'GW') { return & $result 'LAN_ROUTER' @() }
    if ((& $noneOk 'RU_PING') -and (& $noneOk 'INTL_PING') -and (& $noneOk 'RU_HTTP')) {
        $provider = if (-not $IspPingable) { 'PROVIDER' } elseif (& $someOk 'ISP') { 'PROVIDER_UPSTREAM' } else { 'PROVIDER_EDGE' }
        return & $result $provider @()
    }
    if ((& $noneOk 'DNS') -and (& $someOk 'RU_PING')) { return & $result 'DNS' @() }
    if (((& $someOk 'RU_PING') -or (& $someOk 'RU_HTTP')) -and (& $noneOk 'INTL_PING') -and (& $noneOk 'INTL_HTTP')) {
        return & $result 'INTL_DOWN' @()
    }

    $flags = [System.Collections.Generic.List[string]]::new()
    if (& $noneOk 'CF_HTTP') { $flags.Add('CF_DOWN') }
    elseif ((& $noneOk 'CF_BIG') -and ($byCat['CF_BIG'] | Where-Object { $_.Err -like 'timeout*' })) { $flags.Add('CF_THROTTLE') }
    if ((& $noneOk 'STEAM_HTTP') -and (& $noneOk 'STEAM_CM')) { $flags.Add('STEAM_ALL') }
    elseif (& $noneOk 'STEAM_CM') { $flags.Add('STEAM_CM') }
    elseif (& $noneOk 'STEAM_HTTP') { $flags.Add('STEAM_WEB') }
    if (& $noneOk 'IPV6') { $flags.Add('IPV6') }

    $explained = @($flags | ForEach-Object { $FlagCats[$_] })
    $unexplained = @(@($Checks) | Where-Object { $_ -and -not $_.Ok -and $_.Cat -notin $explained } |
        ForEach-Object { '{0}|{1}' -f $_.Cat, $_.Target } | Select-Object -Unique)
    # одиночный сбой одной проверки (8.8.8.8 режет ICMP, api.steampowered.com иногда медлит) - не LOSS
    $repeated = @($unexplained | Where-Object { $_ -in $PrevUnexplained })
    if ($unexplained.Count -ge $LossMinFails -or $repeated.Count) { $flags.Add('LOSS') }

    $verdict = if ($flags.Count) { $flags -join '+' } else { 'OK' }
    return & $result $verdict $unexplained
}

function Invoke-Cycle($Ctx, $Route) {
    $now = Get-Date
    if ($null -eq $Route) { $Route = Get-ActiveRoute }
    # линк смотрим у адаптера текущего маршрута: при переходе кабель -> Wi-Fi старый адаптер Disconnected, а сеть есть
    $ifIndex = if ($Route) { $Route.IfIndex } else { $Ctx.IfIndex }
    $adapter = Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
    $link = if ($adapter) { "$($adapter.Status)" } else { 'Missing' }
    $dnsServer = if ($Route -and $Route.Dns) { $Route.Dns } else { $Ctx.Dns }

    $async = [System.Collections.Generic.List[object]]::new()
    if ($Ctx.GwPingable) { $async.Add((Start-Check 'GW' 'ping' $Ctx.Gateway)) }
    if ($Ctx.IspPingable) { $async.Add((Start-Check 'ISP' 'ping' $Ctx.IspHop)) }
    foreach ($tgt in $Cfg.RuPing) { $async.Add((Start-Check 'RU_PING' 'ping' $tgt)) }
    foreach ($tgt in $Cfg.IntlPing) { $async.Add((Start-Check 'INTL_PING' 'ping' $tgt)) }
    if ($Ctx.HasIpv6) { foreach ($tgt in $Cfg.Ipv6Ping) { $async.Add((Start-Check 'IPV6' 'ping' $tgt)) } }
    foreach ($tgt in $Cfg.RuHttp) { $async.Add((Start-Check 'RU_HTTP' 'http' $tgt)) }
    foreach ($tgt in $Cfg.IntlHttp) { $async.Add((Start-Check 'INTL_HTTP' 'http' $tgt)) }
    foreach ($tgt in $Cfg.CfHttp) { $async.Add((Start-Check 'CF_HTTP' 'http' $tgt)) }
    # Прореживание: первый цикл, каждый N-й и все циклы, пока длится сбой Cloudflare
    $cfBigDue = $Ctx.Cycle -le 1 -or (($Ctx.Cycle - 1) % $CfBigStep) -eq 0 -or $Ctx.LastVerdict -match 'CF_'
    if ($cfBigDue) { $async.Add((Start-Check 'CF_BIG' 'big' $Cfg.CfBig)) }
    foreach ($tgt in $Cfg.SteamHttp) { $async.Add((Start-Check 'STEAM_HTTP' 'http' $tgt)) }
    foreach ($tgt in $Ctx.SteamCm) { $async.Add((Start-Check 'STEAM_CM' 'tcp' $tgt)) }

    # DNS синхронный, поэтому после запуска асинхронных проверок: его таймауты не задерживают остальные
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($chk in Invoke-DnsChecks $dnsServer) { $checks.Add($chk) }

    # ждём завершения всех (максимум ~9 с от старта), фиксируя время ответа каждой проверки
    do {
        $pending = 0
        foreach ($chk in $async) {
            if (-not $chk.Task -or $null -ne $chk.DoneMs) { continue }
            if ($chk.Task.IsCompleted) { $chk.DoneMs = [int]$chk.Sw.ElapsedMilliseconds } else { $pending++ }
        }
        if ($pending -eq 0) { break }
        Start-Sleep -Milliseconds 25
    } while (((Get-Date) - $now).TotalMilliseconds -lt 9000)
    foreach ($chk in $async) { Complete-Check $chk; $checks.Add($chk) }

    $judged = Get-Verdict -Checks $checks -Link $link -HasRoute ([bool]$Route) -IspPingable $Ctx.IspPingable -PrevUnexplained $Ctx.PrevUnexplained
    $Ctx.PrevUnexplained = $judged.Unexplained

    $byCat = @{}
    foreach ($grp in $checks | Group-Object Cat) { $byCat[$grp.Name] = @($grp.Group) }
    $fails = ($checks | Where-Object { -not $_.Ok } | ForEach-Object {
        $short = $_.Target -replace '^https?://', '' -replace '/.*$', ''
        '{0}:{1}={2}' -f $_.Cat, $short, $_.Err
    }) -join '; '

    $row = [ordered]@{
        Time  = '{0:yyyy-MM-dd HH:mm:ss}' -f $now
        Iface = $(if ($Route) { $Route.Alias } else { '' })
        Link  = $link
    }
    foreach ($cat in 'GW', 'ISP', 'DNS', 'RU_PING', 'INTL_PING', 'RU_HTTP', 'INTL_HTTP', 'CF_HTTP', 'CF_BIG', 'STEAM_HTTP', 'STEAM_CM', 'IPV6') {
        $row[$cat] = Format-Cat $byCat[$cat]
    }
    $row.Verdict = $judged.Verdict
    $row.Fails = $fails
    return [pscustomobject]@{ Row = [pscustomobject]$row; Checks = $checks.ToArray() }
}

function Save-CycleRow($Row) {
    # файл по дате цикла (а не текущей), чтобы цикл в 23:59:59 не уехал в завтрашний файл
    $csv = Join-Path $OutDir ('cycles_{0}.csv' -f ($Row.Time.Substring(0, 10) -replace '-', ''))
    if (Test-Path $csv) {
        # сменился набор колонок (новая версия скрипта): старый файл откладываем, иначе Export-Csv -Append упадёт
        $expected = ($Row.PSObject.Properties.Name | ForEach-Object { '"{0}"' -f $_ }) -join ','
        if ((Get-Content $csv -TotalCount 1) -ne $expected) {
            Rename-Item $csv ('{0}_old_{1:HHmmss}.csv' -f [IO.Path]::GetFileNameWithoutExtension($csv), (Get-Date))
        }
    }
    $Row | Export-Csv -Path $csv -Append -NoTypeInformation -Encoding utf8
}

function Get-TraceTargets([string]$Verdict, $Checks, $Ctx) {
    # цель -> причина. Для мягких флагов трассируем то, что реально не прошло, а не фиксированный 8.8.8.8
    $targets = [ordered]@{}
    foreach ($flag in $Verdict -split '\+') {
        switch -Regex ($flag) {
            '^LAN_ROUTER$' { $targets[$Ctx.Gateway] = $flag }
            '^PROVIDER' { $targets['77.88.8.8'] = $flag }
            '^INTL_DOWN$' { $targets['8.8.8.8'] = $flag }
            '^(CF_|STEAM_|IPV6$|LOSS$)' {
                $cats = if ($flag -eq 'LOSS') { $null } else { $FlagCats[$flag] }
                $hosts = @($Checks | Where-Object { -not $_.Ok -and $_.Cat -ne 'DNS' -and (-not $cats -or $_.Cat -in $cats) } |
                    ForEach-Object { Get-CheckHost $_ } | Where-Object { $_ } | Select-Object -Unique -First $Cfg.TracesPerFlag)
                foreach ($hostName in $hosts) { if (-not $targets.Contains($hostName)) { $targets[$hostName] = $flag } }
            }
        }
    }
    return $targets
}

function Update-Notification($Ctx, $Row) {
    # Уведомление, когда сбой держится N циклов подряд, и когда он закончился. Одиночный LOSS не считается
    $isProblem = $Row.Verdict -ne 'OK' -and $Row.Verdict -ne 'LOSS'
    if (-not $isProblem) {
        if ($Ctx.NotifiedVerdict) {
            $since = [datetime]::ParseExact($Ctx.BadSince, 'yyyy-MM-dd HH:mm:ss', $null)
            $duration = [datetime]::ParseExact($Row.Time, 'yyyy-MM-dd HH:mm:ss', $null) - $since
            Send-Notification $Ctx.Notifier 'netmon: восстановилось' ("{0} длился {1:hh\:mm\:ss}" -f $Ctx.NotifiedVerdict, $duration) 'Info'
            Write-NetEvent "NOTIFY восстановилось после $($Ctx.NotifiedVerdict), $('{0:hh\:mm\:ss}' -f $duration)" 'DarkGray' $Row.Time
        }
        $Ctx.BadStreak = 0
        $Ctx.BadSince = ''
        $Ctx.NotifiedVerdict = ''
        return
    }
    if ($Ctx.BadStreak -eq 0) { $Ctx.BadSince = $Row.Time }
    $Ctx.BadStreak++
    $isHard = ($Row.Verdict -split '\+')[0] -in $HardVerdicts
    $threshold = if ($isHard) { $Cfg.NotifyHardAfter } else { $Cfg.NotifySoftAfter }
    if (-not $Ctx.NotifiedVerdict -and $Ctx.BadStreak -ge $threshold) {
        $flag = ($Row.Verdict -split '\+')[0]
        Send-Notification $Ctx.Notifier "netmon: $($Row.Verdict)" ("с {0}: {1}" -f $Ctx.BadSince.Substring(11), $VerdictHelp[$flag]) $(if ($isHard) { 'Error' } else { 'Warning' })
        Write-NetEvent "NOTIFY $($Row.Verdict)" 'DarkGray' $Row.Time
        $Ctx.NotifiedVerdict = $Row.Verdict
    }
}

function Update-State($Ctx, $Result) {
    $row = $Result.Row
    if ($row.Link -ne $Ctx.LastLink) {
        Write-NetEvent "LINK $($Ctx.LastLink) -> $($row.Link) (адаптер '$($Ctx.Alias)')" 'Magenta' $row.Time
        $Ctx.LastLink = $row.Link
    }
    $prevBase = ($Ctx.LastVerdict -split '\+')[0]
    $recovered = $prevBase -in $HardVerdicts -and $row.Verdict -eq 'OK'
    if ($row.Verdict -ne $Ctx.LastVerdict) {
        $color = if ($row.Verdict -eq 'OK') { 'Green' } else { 'Red' }
        Write-NetEvent "VERDICT $($Ctx.LastVerdict) -> $($row.Verdict) | $($row.Fails)" $color $row.Time
        if ($row.Verdict -ne 'OK' -and $row.Verdict -ne 'LINK_DOWN') {
            $targets = Get-TraceTargets $row.Verdict $Result.Checks $Ctx
            foreach ($tgt in $targets.Keys) {
                $last = $Ctx.LastTrace[$tgt]
                if ($last -and ((Get-Date) - $last).TotalSeconds -lt $Cfg.TraceCooldownS) { continue }
                $Ctx.LastTrace[$tgt] = Get-Date
                $trace = Start-Trace $tgt $targets[$tgt]
                $Ctx.TraceJobs.Add($trace.Job)
                Write-NetEvent "TRACE $tgt -> $($trace.File)" 'DarkCyan' $row.Time
            }
        }
        $Ctx.LastVerdict = $row.Verdict
    }
    Update-Notification $Ctx $row
    if ($recovered -or ($Ctx.Cycle % $Cfg.PublicIpEvery -eq 0)) {
        $ip = Get-PublicIp
        if ($ip -and $ip -ne $Ctx.PublicIp) {
            Write-NetEvent "PUBLIC_IP $($Ctx.PublicIp) -> $ip (переподнялась сессия/NAT у провайдера или роутера)" 'Magenta'
            $Ctx.PublicIp = $ip
        }
    }
    # убираем только свои завершившиеся трассировки (включая упавшие)
    foreach ($job in @($Ctx.TraceJobs | Where-Object { $_.State -notin 'NotStarted', 'Running' })) {
        Remove-Job $job -Force
        $null = $Ctx.TraceJobs.Remove($job)
    }
}

function Write-CycleLine($Row) {
    $color = if ($Row.Verdict -eq 'OK') { 'Green' } elseif (($Row.Verdict -split '\+')[0] -in $HardVerdicts) { 'Red' } else { 'Yellow' }
    $line = '{0} {1,-20} gw {2,-9} ru {3,-9} intl {4,-9} dns {5,-5} cf {6,-9} cf256k {7,-9} steam {8,-9} cm {9}' -f
        $Row.Time.Substring(11), $Row.Verdict, $Row.GW, $Row.RU_PING, $Row.INTL_PING, $Row.DNS.Split(' ')[0],
        $Row.CF_HTTP, $Row.CF_BIG, $Row.STEAM_HTTP, $Row.STEAM_CM
    if ($Row.IPV6 -and $Row.IPV6 -ne '-') { $line += " v6 $($Row.IPV6)" }
    Write-Host $line -ForegroundColor $color
    if ($Row.Fails) { Write-Host "         $($Row.Fails)" -ForegroundColor DarkGray }
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
        $color = if ($grp.Name -eq 'OK') { 'Green' } elseif (($grp.Name -split '\+')[0] -in $HardVerdicts) { 'Red' } else { 'Yellow' }
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
    $summary = [pscustomobject]@{
        IspHop   = Resolve-IspHop $route.Gateway
        SteamCm  = Get-SteamCmEndpoints
        PublicIp = Get-PublicIp
    }
    $ctx = Initialize-Context $summary 'CHECK'
    Write-Host 'Прогревочный цикл...'
    $null = Invoke-Cycle $ctx
    $ctx.PrevUnexplained = @()
    $rows = foreach ($num in 1..$Cycles) {
        $result = Invoke-Cycle $ctx
        Save-CycleRow $result.Row
        Write-CycleLine $result.Row
        $result.Row
        if ($num -lt $Cycles) { Start-Sleep -Seconds 5 }
    }
    Show-Status $rows 'Итог быстрой проверки'
}

function Start-Monitor([int]$Minutes = 0) {
    $lock = Enter-MonitorLock
    if (-not $lock) {
        Write-Host "Мониторинг для $OutDir уже запущен в другом окне (автозапуск?). Второй экземпляр не стартует." -ForegroundColor Yellow
        Write-Host 'Посмотреть, что он насобирал: пункт 6 (отчёт).'
        return
    }
    $startTime = Get-Date
    $canReadKeys = -not [Console]::IsInputRedirected
    $snapshot = $null
    $ctx = $null
    try {
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
        # снапшот дописывается в фоне, мониторинг стартует сразу
        $snapshot = Start-Snapshot
        $route = Get-ActiveRoute
        $summary = [pscustomobject]@{ IspHop = Resolve-IspHop $route.Gateway; SteamCm = $snapshot.SteamCm; PublicIp = Get-PublicIp }
        $snapshot.PublicIp = $summary.PublicIp
        $ctx = Initialize-Context $summary
        $ctx.Notifier = New-Notifier
        Write-Host 'Прогревочный цикл (не пишется в лог: первый запуск HttpClient/TLS даёт ложные таймауты)...'
        $null = Invoke-Cycle $ctx
        $ctx.PrevUnexplained = @()
        $limitText = if ($Minutes) { "$Minutes мин" } else { 'до остановки' }
        Write-Host "Мониторинг каждые $IntervalSec с ($limitText), Cloudflare 256 КБ - раз в $CfBigStep цикл(ов). Данные: $OutDir" -ForegroundColor Cyan
        Write-Host 'Остановить: Q, Esc или Ctrl+C - в конце будет итоговый отчёт' -ForegroundColor Cyan

        $sessionRows = [System.Collections.Generic.List[object]]::new()
        $monitorStart = Get-Date
        $dailyDay = (Get-Date).Date
        if ($canReadKeys) { [Console]::TreatControlCAsInput = $true }
        while ($true) {
            $loopSw = [Diagnostics.Stopwatch]::StartNew()
            if ((Get-Date).Date -ne $dailyDay) {
                # раз в сутки: чистка и свежий список CM (Steam перераспределяет нагрузку)
                Invoke-Cleanup $Retention
                $freshCm = @(Get-SteamCmEndpoints)
                if (($freshCm -join ',') -ne ($ctx.SteamCm -join ',')) {
                    Write-NetEvent "STEAM_CM список обновлён: $($freshCm -join ',')" 'DarkGray'
                    $ctx.SteamCm = $freshCm
                }
                $dailyDay = (Get-Date).Date
            }
            $route = Get-ActiveRoute
            if (Test-RouteChanged $ctx $route) { $ctx = Update-Context $ctx $route }
            $ctx.Cycle++
            if ($ctx.Cycle % $Cfg.ReprobeEvery -eq 0) { Update-Reachability $ctx }
            $result = Invoke-Cycle $ctx $route
            Save-CycleRow $result.Row
            $sessionRows.Add($result.Row)
            Write-CycleLine $result.Row
            Update-State $ctx $result
            if ($snapshot -and (Complete-Snapshot $snapshot)) {
                Write-NetEvent "SNAPSHOT готов: $($snapshot.Dir)" 'DarkGray'
                $snapshot = $null
            }
            if ($Minutes -and ((Get-Date) - $monitorStart).TotalMinutes -ge $Minutes) { break }
            if (Wait-OrQuit ($IntervalSec * 1000 - $loopSw.ElapsedMilliseconds) $canReadKeys) { break }
        }
    } finally {
        if ($canReadKeys) { [Console]::TreatControlCAsInput = $false }
        if ($snapshot) { Stop-Snapshot $snapshot }
        if ($ctx -and $ctx.Notifier) { $ctx.Notifier.Visible = $false; $ctx.Notifier.Dispose() }
        if ($ctx) { Write-NetEvent 'STOP' 'Cyan' }
        $lock.ReleaseMutex()
        $lock.Dispose()
    }
    Show-Report $startTime -Brief
    Show-Status $sessionRows 'Итог за сеанс мониторинга'
}

# ----------------------------------------------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------------------------------------------
function Get-Incidents($Rows, [int]$GapSec) {
    # Rows: отсортированные по Ts строки CSV. Подряд идущие одинаковые не-OK вердикты = один инцидент
    $incidents = [System.Collections.Generic.List[object]]::new()
    $current = $null
    $prevTs = $null
    foreach ($row in $Rows) {
        if ($prevTs -and ($row.Ts - $prevTs).TotalSeconds -gt $GapSec) {
            if ($current) { $current.End = $prevTs; $incidents.Add($current); $current = $null }
            $incidents.Add([pscustomobject]@{ Start = $prevTs; End = $row.Ts; Verdict = 'NO_DATA'; Cycles = 0; Sample = '' })
        }
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
    return , $incidents.ToArray()
}

function Show-Report([datetime]$From, [switch]$Brief) {
    $rows = @(Get-ChildItem $OutDir -Filter 'cycles_*.csv' | Sort-Object Name | ForEach-Object { Import-Csv $_.FullName } |
        ForEach-Object { $_ | Add-Member -NotePropertyName Ts -NotePropertyValue ([datetime]::ParseExact($_.Time, 'yyyy-MM-dd HH:mm:ss', $null)) -PassThru } |
        Where-Object { $_.Ts -ge $From } | Sort-Object Ts)
    if (-not $rows.Count) { Write-Host "Нет данных мониторинга с $From в $OutDir"; return }

    $incidents = Get-Incidents $rows ([Math]::Max(60, $IntervalSec * 4))
    $stats = @{}
    foreach ($row in $rows) { $stats[$row.Verdict] = 1 + [int]$stats[$row.Verdict] }

    Write-Host ("`nПериод: {0:yyyy-MM-dd HH:mm} .. {1:yyyy-MM-dd HH:mm}, циклов: {2}" -f $rows[0].Ts, $rows[-1].Ts, $rows.Count) -ForegroundColor Cyan
    Write-Host "`nРаспределение вердиктов:" -ForegroundColor Cyan
    $stats.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        '  {0,-28} {1,6} циклов  {2,6:P1}' -f $_.Key, $_.Value, ($_.Value / $rows.Count)
    } | Write-Host

    $shown = @($incidents | Where-Object { -not ($_.Verdict -eq 'LOSS' -and $_.Cycles -lt $Cfg.ReportMinLoss) })
    $hidden = $incidents.Count - $shown.Count
    $hiddenText = if ($hidden) { ", скрыто коротких LOSS (< $($Cfg.ReportMinLoss) циклов): $hidden" } else { '' }
    Write-Host "`nИнциденты (последние 60$hiddenText):" -ForegroundColor Cyan
    if (-not $shown.Count) { Write-Host '  нет' -ForegroundColor Green }
    $shown | Select-Object -Last 60 | ForEach-Object {
        $dur = $_.End - $_.Start
        $color = if ($_.Verdict -eq 'NO_DATA') { 'DarkGray' } elseif (($_.Verdict -split '\+')[0] -in $HardVerdicts) { 'Red' } else { 'Yellow' }
        Write-Host ('  {0:MM-dd HH:mm:ss} - {1:HH:mm:ss}  {2,10}  {3,-24} {4}' -f $_.Start, $_.End, $dur.ToString('d\.hh\:mm\:ss'), $_.Verdict, $_.Sample) -ForegroundColor $color
    }

    Write-Host "`nСобытия монитора (линк, маршрут, внешний IP, старт/стоп):" -ForegroundColor Cyan
    if (Test-Path $EventsFile) {
        Get-Content $EventsFile | Where-Object {
            $_ -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)' -and [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null) -ge $From -and
            $_ -match '^\S+ \S+ (LINK|ROUTE_CHANGE|ROUTE|PUBLIC_IP|START|CHECK|STOP|WAIT|PROBE)\b'
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

function Save-Report([datetime]$From, [string]$Path = '') {
    # Отчёт и на экран, и в текстовый файл (для провайдера). Write-Host попадает в transcript
    if (-not $Path) { $Path = Join-Path $ReportsDir ('report_{0:yyyyMMdd_HHmmss}.txt' -f (Get-Date)) }
    $Path = [IO.Path]::GetFullPath($Path)
    New-Item -ItemType Directory -Force -Path (Split-Path $Path) | Out-Null
    $tmp = [IO.Path]::GetTempFileName()
    Start-Transcript -Path $tmp -UseMinimalHeader -Force | Out-Null
    try { Show-Report $From } finally { Stop-Transcript | Out-Null }
    $lines = @(Get-Content $tmp)
    Remove-Item $tmp -Force
    # transcript обрамляет вывод блоками из звёздочек: шапка (2 линии) и подвал (2 линии)
    $marks = @(for ($idx = 0; $idx -lt $lines.Count; $idx++) { if ($lines[$idx] -match '^\*{10,}$') { $idx } })
    $body = if ($marks.Count -ge 3 -and $marks[2] - $marks[1] -gt 1) { $lines[($marks[1] + 1)..($marks[2] - 1)] } else { $lines }
    Set-Content -Path $Path -Value $body -Encoding utf8BOM
    Write-Host "`nОтчёт сохранён: $Path" -ForegroundColor Green
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
        Write-Host '  6  Отчёт за последние N часов (+ сохраняется в data\reports)'
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
                '6' { Save-Report (Get-Date).AddHours(-(Read-Number 'За сколько последних часов' 24)) }
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

# Подключение через dot-source (тесты: . .\netmon.ps1 -OutDir ...) - только определения функций, без запуска
if ($MyInvocation.InvocationName -eq '.') { return }

$failed = $false
try {
    switch ($Mode) {
        'Menu' { Show-Menu }
        'Check' { Invoke-QuickCheck 3 }
        'Snapshot' { $null = Save-Snapshot -WithPathping:$Deep }
        'Diff' { Compare-Snapshots }
        'Report' {
            $from = if ($Hours -gt 0) { (Get-Date).AddHours(-$Hours) } else { $Since }
            if ($Out) { Save-Report $from $Out } else { Show-Report $from }
        }
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
