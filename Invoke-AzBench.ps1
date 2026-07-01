#Requires -Version 5.1
<#
.SYNOPSIS
    AzBench -- Azure tenant security audit anchored to CIS Microsoft Azure Foundations Benchmark v2.1.0.

.DESCRIPTION
    AzBench is a single-file PowerShell script that authenticates to an Azure tenant, enumerates
    Entra ID + every readable subscription, and runs ~127 CIS checks plus governance
    extras (PIM standing assignments, stale SP credentials, classic resources, resource
    locks, Defender Secure Score, sub-Owner counts, diagnostic-settings sweep).

    Designed to run from a locked-down Azure Virtual Desktop session where the user
    has no local admin but CAN install PowerShell modules to CurrentUser scope.

    Outputs three artifacts in $OutputPath:
      findings.csv       Flat one-row-per-check report.
      findings.json      Structured findings + collected inventory.
      report.html        Self-contained interactive HTML (no external CDN/JS/CSS).

    Every check resolves to exactly one Status:
      Pass            Compliant.
      Fail            Non-compliant.
      Manual          Requires human judgement; evidence captured.
      NoAccess        Caller lacks required role/scope. Informational, not red.
      NotApplicable   Resource type absent or scope disabled.
      Error           Unexpected exception; investigate.

.PARAMETER OutputPath
    Folder to write findings.csv, findings.json, and report.html into. Created if missing.

.PARAMETER TenantId
    Optional Entra tenant GUID. Required for multi-tenant accounts; otherwise prompts.

.PARAMETER SubscriptionIds
    Optional allow-list of subscription GUIDs. If omitted, every subscription the caller
    can read is audited.

.PARAMETER UseDeviceCode
    Force device-code authentication for both Az and Microsoft.Graph. Use when the AVD
    blocks the interactive browser pop-up.

.PARAMETER SkipModuleInstall
    Skip the CurrentUser-scope module install step. Modules must already be present.

.PARAMETER ChecksFilter
    Optional regex matched against CheckID. Example: '^CIS-3\.' runs only Storage checks.

.PARAMETER MaxParallelism
    Per-subscription parallelism cap. Only effective on PowerShell 7+. Defaults to 8.

.PARAMETER IncludeExtras
    Run the non-CIS governance extras (PIM, stale SP creds, classic resources, locks,
    Secure Score, sub-Owner counts, Log Analytics retention, diagnostic sweep). Default: $true.

.PARAMETER AlreadyAuthenticated
    Skip Connect-AzAccount and Connect-MgGraph. Use when the caller has already
    established Az and (optionally) Microsoft Graph contexts -- e.g. when running in
    Cloud Shell, or when authenticating up-front as a Service Principal via
    Connect-AzAccount -ServicePrincipal + Connect-MgGraph -ClientSecretCredential.
    The script will reuse the existing contexts. If a Graph context is absent, Section 1
    (IAM) checks will report NoAccess gracefully.

.PARAMETER SkipGraph
    Skip every Microsoft Graph operation: skips Connect-MgGraph, the Graph permission
    probe in Build-Inventory, and every CIS Section 1 (IAM) check plus EXT-002 and
    EXT-003. Use when Graph auth is blocked (Conditional Access without a compliant
    device, no admin consent, etc.) and you still want the ~80% of checks that need
    only Az. Produces a "Microsoft Graph operations skipped" coverage row in section 0
    so reviewers know what was deliberately not evaluated.

.PARAMETER CloudShell
    Run in Azure Cloud Shell "one-shot" mode. When set (or auto-detected), the script:
      1. Reuses the existing Az context (or falls back to Connect-AzAccount -Identity),
         so no interactive sign-in is attempted.
      2. Imports / installs the six Microsoft.Graph submodules at the exact version of
         the Microsoft.Graph.Authentication assembly Cloud Shell has already loaded,
         which avoids the "assembly with same name is already loaded" version conflict.
      3. Bridges the current Az access token to Microsoft Graph via Get-AzAccessToken +
         Connect-MgGraph -AccessToken -- no device code, no Conditional Access prompt.
    Cloud Shell is detected automatically (POWERSHELL_DISTRIBUTION_CHANNEL, ACC_CLOUD,
    or AZUREPS_HOST_ENVIRONMENT); pass -CloudShell explicitly to force the behavior.
    Note: if your tenant's Conditional Access requires a compliant device, Cloud Shell
    sign-in itself will fail -- use the Service Principal parameters instead.

.PARAMETER StopOnMissingPermissions
    After authenticating, run a permission preflight that functionally probes every
    Azure role and Microsoft Graph scope the audit relies on. If any required or
    recommended permission is missing, abort BEFORE building inventory or running
    checks, and exit with code 2. Without this switch the preflight still runs and
    prints its report, but the audit proceeds with warnings (missing permissions just
    surface as NoAccess rows). On an interactive host you are also prompted to continue
    or stop when gaps are found.

.PARAMETER PreflightOnly
    Authenticate, run the permission preflight, print the report, then exit without
    building inventory or running any checks. Exit code is 0 when all probed
    permissions are present, 2 when any are missing. Use it as a fast pre-flight in
    CI/CD or before a long run to confirm the principal is correctly entitled.

.PARAMETER SpAppId
    Service Principal application (client) ID. Provide together with -SpTenantId and
    -SpSecret for native SP auth: the script calls Connect-AzAccount -ServicePrincipal
    and Connect-MgGraph -ClientSecretCredential itself, inside its own scope. This is
    the most reliable path in environments where Conditional Access blocks interactive
    and device-code flows.

.PARAMETER SpTenantId
    Entra tenant (directory) ID for the Service Principal auth path.

.PARAMETER SpSecret
    Service Principal client secret as a SecureString, e.g.
    (Read-Host 'Client secret' -AsSecureString). Never pass the secret as plaintext.

.EXAMPLE
    PS> .\Invoke-AzBench.ps1
    Audit every subscription in the default tenant, write outputs to a timestamped folder
    under the current directory.

.EXAMPLE
    PS> .\Invoke-AzBench.ps1 -TenantId 11111111-1111-1111-1111-111111111111 -UseDeviceCode
    Audit a specific tenant using device-code auth (recommended inside AVD).

.EXAMPLE
    PS> .\Invoke-AzBench.ps1 -ChecksFilter '^CIS-(1|8)\.'
    Run only Section 1 (IAM) and Section 8 (Key Vault) checks.

.EXAMPLE
    PS> # Service Principal flow (works around user-CA restrictions).
    PS> $cred = New-Object PSCredential($appId, (ConvertTo-SecureString $secret -AsPlainText -Force))
    PS> Connect-AzAccount -ServicePrincipal -TenantId $tenantId -Credential $cred
    PS> Connect-MgGraph   -TenantId $tenantId -ClientSecretCredential $cred -NoWelcome
    PS> .\Invoke-AzBench.ps1 -SkipModuleInstall -AlreadyAuthenticated

.EXAMPLE
    PS> # Az-only run when no Graph context is available.
    PS> .\Invoke-AzBench.ps1 -AlreadyAuthenticated -SkipGraph

.EXAMPLE
    PS> # Check entitlements only -- no audit. Exit code 0 = all present, 2 = gaps.
    PS> .\Invoke-AzBench.ps1 -PreflightOnly

.EXAMPLE
    PS> # Refuse to run unless every required/recommended permission is present.
    PS> .\Invoke-AzBench.ps1 -StopOnMissingPermissions

.EXAMPLE
    PS> # Azure Cloud Shell: one shot, no separate launcher needed.
    PS> ./Invoke-AzBench.ps1 -CloudShell
    Version-aligns the Graph submodules, bridges the Az token to Microsoft Graph, and
    runs the full audit. -CloudShell is auto-detected, so plain ./Invoke-AzBench.ps1
    inside Cloud Shell does the same thing.

.NOTES
    Anchored to:        CIS Microsoft Azure Foundations Benchmark v2.1.0
    Compatible with:    Windows PowerShell 5.1 and PowerShell 7.x
    Requires modules:   Az.* and Microsoft.Graph.* (auto-installed to CurrentUser scope
                        unless -SkipModuleInstall is set)
    Minimum roles:      Reader at the scope of each subscription. Security Reader and
                        Global Reader strongly recommended for full coverage. Without
                        them many checks correctly report NoAccess rather than a
                        misleading Pass. See the companion README for the proven
                        Service Principal permission set.
#>
[CmdletBinding()]
param(
    [string]   $OutputPath        = (Join-Path -Path $PWD -ChildPath ("AzureCISAudit_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [string]   $TenantId,
    [string[]] $SubscriptionIds,
    [switch]   $UseDeviceCode,
    [switch]   $SkipModuleInstall,
    [string]   $ChecksFilter,
    [int]      $MaxParallelism    = 8,
    [bool]     $IncludeExtras     = $true,
    [switch]   $AlreadyAuthenticated,
    [switch]   $SkipGraph,
    # Azure Cloud Shell one-shot mode: reuse/attach the Az context, version-align the
    # Graph submodules to Cloud Shell's pre-loaded Microsoft.Graph.Authentication, and
    # bridge the Az token to Microsoft Graph. Auto-detected; -CloudShell forces it.
    [switch]   $CloudShell,
    # Permission preflight: verify the caller actually has every role/scope the audit
    # needs before doing any real work.
    [switch]   $StopOnMissingPermissions,
    [switch]   $PreflightOnly,
    # Native Service Principal auth (alternative to -AlreadyAuthenticated).
    # When all three are provided the script calls Connect-AzAccount -ServicePrincipal
    # AND Connect-MgGraph -ClientSecretCredential itself, inside its own scope.
    # This is the most reliable path for SP auth because both contexts are established
    # in the same scope that the check scriptblocks run in, avoiding any context handoff.
    [string]              $SpAppId,
    [string]              $SpTenantId,
    [System.Security.SecureString] $SpSecret
)

# --------------------------------------------------------------------------- #
#  Globals and constants
# --------------------------------------------------------------------------- #
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$script:ProjectName    = 'AzBench'
$script:CISVersion     = '2.1.0'
$script:ScriptVersion  = '1.0.0'
$script:StartedAt      = Get-Date
$script:IsPS7          = $PSVersionTable.PSVersion.Major -ge 7

# Suppress Az noise (Az 12+ prints a breaking-change banner per invocation)
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

# Required modules with minimum versions. Order matters for dependency resolution.
$script:RequiredModules = @(
    @{ Name = 'Az.Accounts';                                MinVersion = '2.15.0' }
    @{ Name = 'Az.ResourceGraph';                           MinVersion = '0.13.0' }
    @{ Name = 'Az.Resources';                               MinVersion = '6.0.0'  }
    @{ Name = 'Az.Storage';                                 MinVersion = '6.0.0'  }
    @{ Name = 'Az.KeyVault';                                MinVersion = '4.0.0'  }
    @{ Name = 'Az.Network';                                 MinVersion = '6.0.0'  }
    @{ Name = 'Az.Compute';                                 MinVersion = '6.0.0'  }
    @{ Name = 'Az.Sql';                                     MinVersion = '4.0.0'  }
    @{ Name = 'Az.PostgreSql';                              MinVersion = '1.0.0'  }
    @{ Name = 'Az.MySql';                                   MinVersion = '1.0.0'  }
    @{ Name = 'Az.CosmosDB';                                MinVersion = '1.0.0'  }
    @{ Name = 'Az.Monitor';                                 MinVersion = '4.0.0'  }
    @{ Name = 'Az.Security';                                MinVersion = '1.5.0'  }
    @{ Name = 'Az.Websites';                                MinVersion = '3.0.0'  }
    @{ Name = 'Az.PolicyInsights';                          MinVersion = '1.6.0'  }
    @{ Name = 'Microsoft.Graph.Authentication';             MinVersion = '2.20.0' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';           MinVersion = '2.20.0' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinVersion = '2.20.0' }
    @{ Name = 'Microsoft.Graph.Users';                      MinVersion = '2.20.0' }
    @{ Name = 'Microsoft.Graph.Groups';                     MinVersion = '2.20.0' }
    @{ Name = 'Microsoft.Graph.Applications';               MinVersion = '2.20.0' }
)

$script:GraphScopes = @(
    'Directory.Read.All'
    'Policy.Read.All'
    'UserAuthenticationMethod.Read.All'
    'RoleManagement.Read.Directory'
    'Application.Read.All'
    'AuditLog.Read.All'
    'Group.Read.All'
)

# Inventory cache populated once and read by every check scriptblock
$script:Inventory = [ordered]@{
    Tenant         = $null
    CallerUpn      = $null
    Subscriptions  = @()
    Resources      = @{}     # keyed by lowercase resource type
    Coverage       = @{}     # keyed by subscriptionId -> @{ Reader; SecurityReader; GraphPolicy }
    Cloud          = $null
}

$script:Results = New-Object 'System.Collections.Generic.List[object]'

# --------------------------------------------------------------------------- #
#  Logging helpers
# --------------------------------------------------------------------------- #
function Write-Step {
    param([string]$Message, [ValidateSet('Info','Ok','Warn','Err','Step')]$Level = 'Info')
    $ts = (Get-Date).ToString('HH:mm:ss')
    $prefix = switch ($Level) {
        'Info' { '[*]' }
        'Ok'   { '[+]' }
        'Warn' { '[!]' }
        'Err'  { '[X]' }
        'Step' { '[=]' }
    }
    $color = switch ($Level) {
        'Info' { 'Gray' }
        'Ok'   { 'Green' }
        'Warn' { 'Yellow' }
        'Err'  { 'Red' }
        'Step' { 'Cyan' }
    }
    Write-Host ("{0} {1} {2}" -f $ts, $prefix, $Message) -ForegroundColor $color
}

# --------------------------------------------------------------------------- #
#  Module bootstrap
# --------------------------------------------------------------------------- #
function Ensure-Modules {
    if ($SkipModuleInstall) {
        Write-Step 'Skipping module install per -SkipModuleInstall' 'Info'
    } else {
        Write-Step 'Verifying required PowerShell modules' 'Step'
        # PSGallery may not be trusted on a hardened image; trust it for this session only.
        try {
            $psg = Get-PSRepository -Name PSGallery -ErrorAction Stop
            if ($psg.InstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }
        } catch {
            Write-Step ("PSGallery not registered or could not be trusted: {0}" -f $_.Exception.Message) 'Warn'
        }

        foreach ($m in $script:RequiredModules) {
            $installed = Get-Module -ListAvailable -Name $m.Name | Sort-Object Version -Descending | Select-Object -First 1
            if ($installed -and [version]$installed.Version -ge [version]$m.MinVersion) {
                continue
            }
            Write-Step ("Installing {0} >= {1} (CurrentUser)" -f $m.Name, $m.MinVersion) 'Info'
            try {
                Install-Module -Name $m.Name -MinimumVersion $m.MinVersion -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
            } catch {
                Write-Step ("Failed to install {0}: {1}" -f $m.Name, $_.Exception.Message) 'Err'
                throw
            }
        }
    }

    Write-Step 'Importing modules' 'Info'
    foreach ($m in $script:RequiredModules) {
        try { Import-Module -Name $m.Name -ErrorAction Stop -WarningAction SilentlyContinue } catch {
            Write-Step ("Failed to import {0}: {1}" -f $m.Name, $_.Exception.Message) 'Warn'
        }
    }

    # Mute Az breaking-change banners now that Az.Accounts is loaded.
    try { Update-AzConfig -DisplayBreakingChangeWarning $false -Scope Process -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Step 'Modules ready' 'Ok'
}

# --------------------------------------------------------------------------- #
#  Azure Cloud Shell bootstrap (folded in from the former start.ps1 launcher)
# --------------------------------------------------------------------------- #
function Test-IsCloudShell {
    # Azure Cloud Shell sets these; any one is a reliable signal.
    if ($env:POWERSHELL_DISTRIBUTION_CHANNEL -like '*CloudShell*') { return $true }
    if ($env:ACC_CLOUD)                                            { return $true }
    if ($env:AZUREPS_HOST_ENVIRONMENT -like '*cloud-shell*')       { return $true }
    return $false
}

function Initialize-CloudShellEnvironment {
    # Mirrors the proven start.ps1 sequence, but inside the audit's own scope so the
    # Az and Graph contexts survive every per-check cmdlet.
    Write-Step 'Cloud Shell mode: bootstrapping Az context and Graph submodules' 'Step'

    # 1. Ensure an Az context (managed identity fallback for automation scenarios).
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-Step 'No Az context found; attempting Connect-AzAccount -Identity' 'Info'
        $azParams = @{ Identity = $true; ErrorAction = 'Stop' }
        if ($TenantId) { $azParams.TenantId = $TenantId }
        $null = Connect-AzAccount @azParams
        $ctx = Get-AzContext
    }
    if (-not $ctx) { throw 'Cloud Shell: could not establish an Az context.' }
    Write-Step ("Az context: {0} on tenant {1}" -f $ctx.Account.Id, $ctx.Tenant.Id) 'Ok'

    if ($SkipGraph) {
        Write-Step '-SkipGraph set: skipping Cloud Shell Graph submodule alignment and token bridge.' 'Info'
        return
    }

    # 2. Determine the Microsoft.Graph.Authentication version to align siblings to.
    #    Cloud Shell pre-loads a specific version; installing siblings at a different
    #    version triggers "assembly with same name is already loaded".
    $auth = Get-Module -Name Microsoft.Graph.Authentication
    if (-not $auth) {
        $auth = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
                Sort-Object Version -Descending | Select-Object -First 1
        if ($auth) { Import-Module $auth -Force -ErrorAction SilentlyContinue }
    }
    if (-not $auth) {
        Write-Step 'Installing Microsoft.Graph.Authentication (first time only)' 'Info'
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module Microsoft.Graph.Authentication -Force
        $auth = Get-Module Microsoft.Graph.Authentication
    }
    $targetVersion = $auth.Version
    Write-Step ("Microsoft.Graph.Authentication loaded: v{0}" -f $targetVersion) 'Ok'

    # 3. Ensure the five sibling submodules are importable AT THE SAME VERSION.
    $siblings = @(
        'Microsoft.Graph.Identity.SignIns'
        'Microsoft.Graph.Identity.DirectoryManagement'
        'Microsoft.Graph.Users'
        'Microsoft.Graph.Groups'
        'Microsoft.Graph.Applications'
    )
    foreach ($name in $siblings) {
        if (Get-Module -Name $name) { continue }   # already loaded -> leave alone
        $matched = Get-Module -ListAvailable -Name $name |
                   Where-Object { $_.Version -eq $targetVersion } | Select-Object -First 1
        if ($matched) {
            Import-Module $matched -Force -ErrorAction SilentlyContinue
            continue
        }
        Write-Step ("Installing {0} v{1}" -f $name, $targetVersion) 'Info'
        try {
            Install-Module -Name $name -RequiredVersion $targetVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Import-Module   -Name $name -RequiredVersion $targetVersion -Force -ErrorAction Stop
        } catch {
            Write-Step ("Could not install {0} at v{1}: {2}. Section 1 checks needing it will report NoAccess." -f $name, $targetVersion, $_.Exception.Message) 'Warn'
        }
    }
    Write-Step 'Graph submodules ready' 'Ok'

    # 4. Bridge the Az access token to Microsoft Graph (no device code, no CA prompt).
    try {
        $tk = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
        if ($tk.Token -is [System.Security.SecureString]) {
            $sec = $tk.Token
        } else {
            $sec = ConvertTo-SecureString $tk.Token -AsPlainText -Force
        }
        Connect-MgGraph -AccessToken $sec -NoWelcome -ErrorAction Stop
        $mg = Get-MgContext
        Write-Step ("Graph context bridged: {0}" -f $mg.Account) 'Ok'
    } catch {
        Write-Step ("Graph token bridge failed: {0}. Section 1 (IAM) checks will report NoAccess; other sections run normally." -f $_.Exception.Message) 'Warn'
    }
}

# --------------------------------------------------------------------------- #
#  Authentication
# --------------------------------------------------------------------------- #
function Initialize-AuditAzContext {
    # SP auth path (takes precedence; native auth inside the audit's own scope)
    if ($SpAppId -and $SpTenantId -and $SpSecret) {
        Write-Step 'Authenticating to Azure as Service Principal' 'Step'
        $script:SpCredential = New-Object System.Management.Automation.PSCredential($SpAppId, $SpSecret)
        $null = Connect-AzAccount -ServicePrincipal -TenantId $SpTenantId -Credential $script:SpCredential -ErrorAction Stop
        $ctx = Get-AzContext
        $script:Inventory.Tenant    = $ctx.Tenant.Id
        $script:Inventory.CallerUpn = $ctx.Account.Id
        $script:Inventory.Cloud     = $ctx.Environment.Name
        Write-Step ("Az SP context: {0} on tenant {1} ({2})" -f $ctx.Account.Id, $ctx.Tenant.Id, $ctx.Environment.Name) 'Ok'
        return
    }

    if ($AlreadyAuthenticated) {
        $ctx = Get-AzContext
        if (-not $ctx) {
            throw "-AlreadyAuthenticated was passed but Get-AzContext returned nothing. Run Connect-AzAccount manually, then re-run with -AlreadyAuthenticated."
        }
        $script:Inventory.Tenant    = $ctx.Tenant.Id
        $script:Inventory.CallerUpn = $ctx.Account.Id
        $script:Inventory.Cloud     = $ctx.Environment.Name
        Write-Step ("Reusing existing Az context: {0} on tenant {1} ({2})" -f $ctx.Account.Id, $ctx.Tenant.Id, $ctx.Environment.Name) 'Ok'
        return
    }

    Write-Step 'Connecting to Azure (Az)' 'Step'
    $azParams = @{}
    if ($TenantId)      { $azParams.TenantId = $TenantId }
    if ($UseDeviceCode) { $azParams.UseDeviceAuthentication = $true }

    try {
        $null = Connect-AzAccount @azParams -ErrorAction Stop
    } catch {
        Write-Step ("Interactive Connect-AzAccount failed ({0}); retrying with device code" -f $_.Exception.Message) 'Warn'
        $azParams.UseDeviceAuthentication = $true
        $null = Connect-AzAccount @azParams -ErrorAction Stop
    }

    $ctx = Get-AzContext
    if (-not $ctx) { throw "No Azure context after Connect-AzAccount." }
    $script:Inventory.Tenant    = $ctx.Tenant.Id
    $script:Inventory.CallerUpn = $ctx.Account.Id
    $script:Inventory.Cloud     = $ctx.Environment.Name
    Write-Step ("Authenticated as {0} on tenant {1} ({2})" -f $ctx.Account.Id, $ctx.Tenant.Id, $ctx.Environment.Name) 'Ok'
}

function Initialize-AuditGraphContext {
    if ($SkipGraph) {
        Write-Step '-SkipGraph passed: every Microsoft Graph operation will be bypassed. Section 1 (IAM) and Graph-dependent extras will be skipped.' 'Warn'
        return
    }

    # SP auth path (takes precedence; native auth inside the audit's own scope so the
    # context survives every per-check Get-Mg* call). Construct credential from the
    # script-level params directly -- don't rely on inter-function variable handoff.
    if ($SpAppId -and $SpTenantId -and $SpSecret) {
        Write-Step 'Authenticating to Microsoft Graph as Service Principal' 'Step'
        try {
            $graphCred = New-Object System.Management.Automation.PSCredential($SpAppId, $SpSecret)
            Connect-MgGraph -TenantId $SpTenantId -ClientSecretCredential $graphCred -NoWelcome -ErrorAction Stop
            $mg = Get-MgContext
            if ($mg) {
                Write-Step ("Graph SP context: AppName={0} AuthType={1}" -f $mg.AppName, $mg.AuthType) 'Ok'
            } else {
                Write-Step 'Connect-MgGraph returned but Get-MgContext is null -- Graph operations will likely fail' 'Warn'
            }
            return
        } catch {
            Write-Step ("Microsoft Graph SP auth failed: {0}. Section 1 (IAM) checks will report NoAccess." -f $_.Exception.Message) 'Warn'
            return
        }
    }

    if ($AlreadyAuthenticated) {
        try {
            $mgCtx = Get-MgContext -ErrorAction Stop
            if ($mgCtx) {
                Write-Step ("Reusing existing Graph context (scopes: {0})" -f ($mgCtx.Scopes -join ',')) 'Ok'
                return
            }
        } catch {}
        Write-Step "-AlreadyAuthenticated was passed but no Microsoft Graph context found. Section 1 (IAM) checks will mostly be NoAccess. In Cloud Shell, use -CloudShell instead (it bridges the Az token to Graph automatically)." 'Warn'
        return
    }

    Write-Step 'Connecting to Microsoft Graph' 'Step'
    $mgParams = @{ Scopes = $script:GraphScopes; NoWelcome = $true }
    if ($TenantId)      { $mgParams.TenantId    = $TenantId }
    if ($UseDeviceCode) { $mgParams.UseDeviceCode = $true }

    # Sovereign clouds need an Environment switch
    if ($script:Inventory.Cloud -and $script:Inventory.Cloud -ne 'AzureCloud') {
        $envMap = @{ AzureUSGovernment = 'USGov'; AzureChinaCloud = 'China'; AzureGermanCloud = 'Germany' }
        if ($envMap.ContainsKey($script:Inventory.Cloud)) { $mgParams.Environment = $envMap[$script:Inventory.Cloud] }
    }

    try {
        Connect-MgGraph @mgParams -ErrorAction Stop | Out-Null
    } catch {
        Write-Step ("Interactive Connect-MgGraph failed ({0}); retrying with device code" -f $_.Exception.Message) 'Warn'
        $mgParams.UseDeviceCode = $true
        try { Connect-MgGraph @mgParams -ErrorAction Stop | Out-Null }
        catch {
            Write-Step ("Microsoft Graph auth failed; Section 1 (IAM) will largely be NoAccess: {0}" -f $_.Exception.Message) 'Warn'
            return
        }
    }
    Write-Step 'Graph connected' 'Ok'
}

# --------------------------------------------------------------------------- #
#  Inventory pass (Resource Graph)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  Permission preflight
# --------------------------------------------------------------------------- #
function Test-CmdletAccess {
    # Runs a cheap probe cmdlet and classifies the outcome:
    #   Granted    - the call succeeded, so the permission is present.
    #   Missing    - failed with an auth/permission error (403/401/RequestDenied).
    #   Unverified - failed for another reason (throttle, transient, licensing). We
    #                cannot prove the permission is missing, so we do not hard-fail.
    param([scriptblock]$Probe)
    try {
        $null = & $Probe
        return 'Granted'
    } catch {
        if (Test-ExceptionIsAuth $_.Exception) { return 'Missing' }
        return 'Unverified'
    }
}

function Invoke-PermissionPreflight {
    # Functionally probes every Azure role and Microsoft Graph scope the audit relies
    # on, up front, so a caller can see (and optionally stop on) missing entitlements
    # before committing to a full run. Returns a summary object consumed by Main.
    Write-Step 'Permission preflight: probing required roles and Graph scopes' 'Step'
    $items = New-Object 'System.Collections.Generic.List[object]'
    $addItem = {
        param($Name, $Category, $Plane, $Status, $Detail)
        $items.Add([pscustomobject]@{ Name = $Name; Category = $Category; Plane = $Plane; Status = $Status; Detail = $Detail })
    }

    # --- Azure resource-manager plane -------------------------------------
    $subs = @()
    try {
        $subs = @(Get-AzSubscription -TenantId $script:Inventory.Tenant -ErrorAction Stop)
        if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
            $subs = @($subs | Where-Object { $SubscriptionIds -contains $_.Id })
        }
        $subs = @($subs | Where-Object { $_.State -eq 'Enabled' })
    } catch {}

    if ($subs.Count -gt 0) {
        & $addItem 'Azure subscriptions visible' 'Required' 'Azure' 'Granted' ("{0} enabled subscription(s) in scope" -f $subs.Count)
        $probeSub = $subs[0]
        try { $null = Set-AzContext -SubscriptionId $probeSub.Id -Tenant $script:Inventory.Tenant -ErrorAction Stop } catch {}

        $reader = Test-CmdletAccess { Get-AzResourceGroup -ErrorAction Stop | Select-Object -First 1 }
        & $addItem 'Azure Reader (resource read)' 'Required' 'Azure' $reader ("Get-AzResourceGroup on '{0}'" -f $probeSub.Name)

        $rg = Test-CmdletAccess { Search-AzGraph -Query 'Resources | project id | limit 1' -Subscription $probeSub.Id -First 1 -ErrorAction Stop }
        & $addItem 'Azure Resource Graph' 'Required' 'Azure' $rg 'Search-AzGraph (inventory backbone)'

        $secRead = Test-CmdletAccess { Get-AzSecurityPricing -ErrorAction Stop | Select-Object -First 1 }
        & $addItem 'Security Reader (Defender)' 'Recommended' 'Azure' $secRead 'Get-AzSecurityPricing; unlocks Section 2'
    } else {
        & $addItem 'Azure subscriptions visible' 'Required' 'Azure' 'Missing' 'Get-AzSubscription returned no enabled subscriptions in scope'
        & $addItem 'Azure Reader (resource read)' 'Required' 'Azure' 'Missing' 'no subscription available to probe'
        & $addItem 'Azure Resource Graph'         'Required' 'Azure' 'Missing' 'no subscription available to probe'
        & $addItem 'Security Reader (Defender)'   'Recommended' 'Azure' 'Missing' 'no subscription available to probe'
    }

    # --- Microsoft Graph plane --------------------------------------------
    if ($SkipGraph) {
        & $addItem 'Microsoft Graph (Section 1)' 'Recommended' 'Graph' 'Skipped' '-SkipGraph set; Section 1 (IAM) will not run'
    } elseif (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        & $addItem 'Microsoft Graph connection' 'Recommended' 'Graph' 'Missing' 'no Graph context; Section 1 (IAM) will report NoAccess'
    } else {
        $granted = @()
        try { $granted = @((Get-MgContext).Scopes) } catch {}

        $graphProbes = @(
            @{ Name = 'Directory.Read.All';            Probe = { Get-MgOrganization -ErrorAction Stop | Select-Object -First 1 } }
            @{ Name = 'Policy.Read.All';               Probe = { Get-MgPolicyAuthorizationPolicy -ErrorAction Stop } }
            @{ Name = 'RoleManagement.Read.Directory'; Probe = { Get-MgRoleManagementDirectoryRoleDefinition -Top 1 -ErrorAction Stop } }
            @{ Name = 'Application.Read.All';          Probe = { Get-MgApplication -Top 1 -ErrorAction Stop } }
            @{ Name = 'Group.Read.All';                Probe = { Get-MgGroup -Top 1 -ErrorAction Stop } }
            @{ Name = 'AuditLog.Read.All';             Probe = { Get-MgAuditLogDirectoryAudit -Top 1 -ErrorAction Stop } }
        )
        foreach ($gp in $graphProbes) {
            $status = Test-CmdletAccess $gp.Probe
            & $addItem $gp.Name 'Recommended' 'Graph' $status 'Graph application/delegated scope'
        }
        # UserAuthenticationMethod.Read.All has no cheap functional probe (it needs a
        # specific user target), so fall back to the token's consented-scope list.
        $uam = if ($granted -contains 'UserAuthenticationMethod.Read.All') { 'Granted' }
               elseif ($granted.Count -eq 0) { 'Unverified' }
               else { 'Missing' }
        & $addItem 'UserAuthenticationMethod.Read.All' 'Recommended' 'Graph' $uam 'from consented scopes (no functional probe)'
    }

    # --- Report ------------------------------------------------------------
    Write-Host ''
    Write-Host ('  {0,-34} {1,-12} {2,-6} {3}' -f 'Permission', 'Category', 'Plane', 'Status') -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 70)) -ForegroundColor DarkGray
    foreach ($it in $items) {
        $c = switch ($it.Status) {
            'Granted' { 'Green' }
            'Missing' { 'Red' }
            'Skipped' { 'DarkGray' }
            default   { 'Yellow' }   # Unverified
        }
        Write-Host ('  {0,-34} {1,-12} {2,-6} {3}' -f $it.Name, $it.Category, $it.Plane, $it.Status) -ForegroundColor $c
    }
    Write-Host ''

    $gaps    = @($items | Where-Object { $_.Status -eq 'Missing' -and ($_.Category -eq 'Required' -or $_.Category -eq 'Recommended') })
    $reqGaps = @($gaps  | Where-Object { $_.Category -eq 'Required' })
    foreach ($g in $gaps) {
        Write-Step ("Missing [{0}] {1} -- {2}" -f $g.Category, $g.Name, $g.Detail) 'Warn'
    }
    if ($gaps.Count -eq 0) {
        Write-Step 'Preflight: all probed permissions present.' 'Ok'
    } else {
        Write-Step ("Preflight: {0} permission gap(s) found ({1} required, {2} recommended)." -f $gaps.Count, $reqGaps.Count, ($gaps.Count - $reqGaps.Count)) 'Warn'
    }

    return [pscustomobject]@{
        Items          = $items
        HasGaps        = ($gaps.Count -gt 0)
        HasRequiredGap = ($reqGaps.Count -gt 0)
        MissingCount   = $gaps.Count
    }
}

function Build-Inventory {
    Write-Step 'Enumerating subscriptions' 'Step'
    $allSubs = Get-AzSubscription -TenantId $script:Inventory.Tenant -ErrorAction SilentlyContinue
    if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
        $allSubs = $allSubs | Where-Object { $SubscriptionIds -contains $_.Id }
    }
    $allSubs = @($allSubs | Where-Object { $_.State -eq 'Enabled' })
    $script:Inventory.Subscriptions = $allSubs
    Write-Step ("Found {0} enabled subscription(s) in scope" -f $allSubs.Count) 'Ok'

    if ($allSubs.Count -eq 0) {
        Write-Step 'No subscriptions in scope - only tenant-level (Entra) checks will produce results' 'Warn'
        return
    }

    # Resource Graph: one pass to enumerate every resource of interest across all subs.
    # Beats 15+ per-sub Get-Az* cmdlets by an order of magnitude on large tenants.
    Write-Step 'Building resource inventory via Resource Graph' 'Step'
    $rgTypes = @(
        'microsoft.storage/storageaccounts'
        'microsoft.keyvault/vaults'
        'microsoft.keyvault/managedhsms'
        'microsoft.network/networksecuritygroups'
        'microsoft.network/networkwatchers'
        'microsoft.network/publicipaddresses'
        'microsoft.network/bastionhosts'
        'microsoft.network/virtualnetworks'
        'microsoft.compute/virtualmachines'
        'microsoft.compute/disks'
        'microsoft.sql/servers'
        'microsoft.dbforpostgresql/servers'
        'microsoft.dbforpostgresql/flexibleservers'
        'microsoft.dbformysql/servers'
        'microsoft.dbformysql/flexibleservers'
        'microsoft.documentdb/databaseaccounts'
        'microsoft.web/sites'
        'microsoft.web/serverfarms'
        'microsoft.insights/components'
        'microsoft.operationalinsights/workspaces'
        'microsoft.classiccompute/virtualmachines'
        'microsoft.classicstorage/storageaccounts'
        'microsoft.classicnetwork/virtualnetworks'
    )
    $subIdList = $allSubs | ForEach-Object { $_.Id }
    foreach ($rt in $rgTypes) {
        try {
            $rows = @()
            $skip = 0
            $batch = 1000
            $query = "Resources | where type =~ '$rt' | project id, name, type, location, subscriptionId, resourceGroup, tags, properties, sku, kind"
            while ($true) {
                # Newer Az.ResourceGraph rejects -Skip 0 (must be >= 1). Omit on the first page.
                $qParams = @{ Query = $query; Subscription = $subIdList; First = $batch; ErrorAction = 'Stop' }
                if ($skip -gt 0) { $qParams.Skip = $skip }
                $page = Search-AzGraph @qParams
                if (-not $page -or $page.Count -eq 0) { break }
                $rows += $page
                if ($page.Count -lt $batch) { break }
                $skip += $batch
            }
            $script:Inventory.Resources[$rt] = $rows
        } catch {
            $script:Inventory.Resources[$rt] = @()
            Write-Step ("Resource Graph query for {0} failed: {1}" -f $rt, $_.Exception.Message) 'Warn'
        }
    }
    $inventoryCount = ($script:Inventory.Resources.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-Step ("Inventory cached: $($script:Inventory.Resources.Keys.Count) resource types, $inventoryCount total resources") 'Ok'

    # Per-subscription permission probe
    Write-Step 'Probing per-subscription effective permissions' 'Step'
    foreach ($sub in $allSubs) {
        $cov = @{ Reader = $false; SecurityReader = $false; GraphPolicy = $false }
        try {
            $null = Set-AzContext -SubscriptionId $sub.Id -Tenant $script:Inventory.Tenant -ErrorAction Stop
            try { $null = Get-AzResourceGroup -ErrorAction Stop; $cov.Reader = $true } catch {}
            try { $null = Get-AzSecurityPricing -ErrorAction Stop; $cov.SecurityReader = $true } catch {}
        } catch {}
        $script:Inventory.Coverage[$sub.Id] = $cov
    }
    if (-not $SkipGraph) {
        try {
            $null = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
            foreach ($k in @($script:Inventory.Coverage.Keys)) { $script:Inventory.Coverage[$k].GraphPolicy = $true }
        } catch {}
    }
    Write-Step 'Permission probe complete' 'Ok'
}

# --------------------------------------------------------------------------- #
#  Check runner / wrapper
# --------------------------------------------------------------------------- #
function Test-ExceptionIsAuth {
    param([Exception]$Ex)
    if (-not $Ex) { return $false }
    $msg = $Ex.Message
    if ($msg -match 'AuthorizationFailed|does not have authorization|Authorization_RequestDenied|Insufficient privileges|Forbidden|\(403\)|\(401\)|Unauthorized') { return $true }
    if ($Ex.PSObject.Properties.Match('Response').Count -gt 0) {
        try {
            $code = $Ex.Response.StatusCode.value__
            if ($code -in 401, 403) { return $true }
        } catch {}
    }
    return $false
}

function Test-ExceptionIsNotFound {
    param([Exception]$Ex)
    if (-not $Ex) { return $false }
    $msg = $Ex.Message
    if ($msg -match 'ResourceNotFound|NotFound|Request_ResourceNotFound|\(404\)|could not be found') { return $true }
    if ($Ex.PSObject.Properties.Match('Response').Count -gt 0) {
        try {
            $code = $Ex.Response.StatusCode.value__
            if ($code -eq 404) { return $true }
        } catch {}
    }
    return $false
}

function Test-ExceptionIsThrottle {
    param([Exception]$Ex)
    if (-not $Ex) { return $false }
    if ($Ex.Message -match '\(429\)|TooManyRequests|throttl') { return $true }
    return $false
}

function Invoke-CISCheck {
    param(
        [Parameter(Mandatory)] [hashtable] $Check,
        [Parameter()]           [object]    $Scope
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $row = [ordered]@{
        CheckID          = $Check.CheckID
        CISControlID     = $Check.CISControlID
        Section          = $Check.Section
        Title            = $Check.Title
        Severity         = $Check.Severity
        Level            = $Check.Level
        Description      = $Check.Description
        BestPractice     = $Check.BestPractice
        Remediation      = $Check.Remediation
        RequiresPerms    = ($Check.RequiresPerms -join '; ')
        ScopeType        = $Check.ScopeType
        ScopeId          = if ($Scope) { $Scope.Id }   else { $null }
        ScopeName        = if ($Scope) { $Scope.Name } else { 'Tenant' }
        Status           = $null
        ActualResult     = $null
        Evidence         = $null
        ExceptionType    = $null
        ExceptionMessage = $null
        DurationMs       = 0
    }

    try {
        # Set context for subscription-scoped checks
        if ($Check.ScopeType -eq 'Subscription' -and $Scope) {
            $null = Set-AzContext -SubscriptionId $Scope.Id -Tenant $script:Inventory.Tenant -ErrorAction Stop
        }

        $attempts = 0
        $maxAttempts = 3
        while ($true) {
            $attempts++
            try {
                $r = & $Check.Run $Scope
                if ($null -eq $r) { $r = @{ Status = 'Error'; Actual = 'Check returned $null'; Evidence = $null } }
                $row.Status       = $r.Status
                $row.ActualResult = $r.Actual
                $row.Evidence     = $r.Evidence
                break
            } catch {
                if ((Test-ExceptionIsThrottle $_.Exception) -and $attempts -lt $maxAttempts) {
                    Start-Sleep -Seconds ([math]::Min(30, [math]::Pow(2, $attempts)))
                    continue
                }
                throw
            }
        }
    } catch {
        $ex = $_.Exception
        $row.ExceptionType    = $ex.GetType().FullName
        $row.ExceptionMessage = $ex.Message
        if (Test-ExceptionIsAuth $ex) {
            $row.Status       = 'NoAccess'
            $row.ActualResult = "Caller lacks required role/scope. Needed: $($Check.RequiresPerms -join ', ')"
        } elseif (Test-ExceptionIsNotFound $ex) {
            $row.Status       = 'NotApplicable'
            $row.ActualResult = 'Target resource or scope not present'
        } else {
            $row.Status       = 'Error'
            $row.ActualResult = $ex.Message
        }
    } finally {
        $sw.Stop()
        $row.DurationMs = $sw.ElapsedMilliseconds
    }

    [pscustomobject]$row
}

function Invoke-AllChecks {
    Write-Step 'Running checks' 'Step'
    $reg = $script:CheckRegistry
    if ($ChecksFilter) {
        $reg = $reg | Where-Object { $_.CheckID -match $ChecksFilter }
        Write-Step ("ChecksFilter applied: {0} of {1} checks selected" -f $reg.Count, $script:CheckRegistry.Count) 'Info'
    }

    # If -SkipGraph: filter out every Section 1 check + Graph-dependent extras,
    # and emit one summary row so the report explains the gap.
    if ($SkipGraph) {
        $graphDependentIds = @('EXT-002','EXT-003')   # Extras that need Graph; others stay
        $before = $reg.Count
        $reg = $reg | Where-Object {
            $_.Section -notlike '1.*' -and $_.CheckID -notin $graphDependentIds
        }
        $skipped = $before - $reg.Count
        Write-Step ("-SkipGraph: dropped {0} Graph-dependent check(s) from the run" -f $skipped) 'Warn'
        $script:Results.Add( [pscustomobject]@{
            CheckID='SKIPGRAPH'; CISControlID='-'; Section='0. Coverage'
            Title='Microsoft Graph operations skipped (-SkipGraph)'; Severity='Info'; Level=0
            Description='The audit was invoked with -SkipGraph. Section 1 (IAM) and Graph-dependent extras were not evaluated.'
            BestPractice='Run without -SkipGraph after a valid Graph context is available.'
            Remediation='Provide Microsoft.Graph application-permission consent and a working Graph context.'
            RequiresPerms='-'; ScopeType='Tenant'; ScopeId=$null; ScopeName='Tenant'
            Status='Manual'; ActualResult=("Skipped {0} Graph-dependent check(s)." -f $skipped)
            Evidence=$null; ExceptionType=$null; ExceptionMessage=$null; DurationMs=0
        }) | Out-Null
    }

    $tenantChecks = $reg | Where-Object { $_.ScopeType -eq 'Tenant' }
    $subChecks    = $reg | Where-Object { $_.ScopeType -eq 'Subscription' }

    # Tenant-scoped checks: run once each
    foreach ($c in $tenantChecks) {
        Write-Step ("[{0}] {1}" -f $c.CheckID, $c.Title) 'Info'
        $script:Results.Add( (Invoke-CISCheck -Check $c -Scope $null) ) | Out-Null
    }

    # Subscription-scoped checks: iterate enabled subs
    foreach ($sub in $script:Inventory.Subscriptions) {
        Write-Step ("--- Subscription: {0} ({1}) ---" -f $sub.Name, $sub.Id) 'Step'
        $cov = $script:Inventory.Coverage[$sub.Id]
        if (-not $cov.Reader) {
            $script:Results.Add( [pscustomobject]@{
                CheckID = 'PROBE-READER'; CISControlID = '-'; Section = '0. Coverage'
                Title = 'Subscription Reader access probe'; Severity = 'High'; Level = 0
                Description = 'Caller could not enumerate resource groups in this subscription. All subscription-scoped checks below will report NoAccess.'
                BestPractice = 'Caller has Reader (or higher) at subscription scope'
                Remediation  = 'Assign Reader at subscription scope'
                RequiresPerms = 'Reader'; ScopeType = 'Subscription'
                ScopeId = $sub.Id; ScopeName = $sub.Name
                Status = 'Fail'; ActualResult = 'No Reader access on this subscription'
                Evidence = $null; ExceptionType = $null; ExceptionMessage = $null; DurationMs = 0
            }) | Out-Null
            continue
        }
        foreach ($c in $subChecks) {
            Write-Step ("  [{0}] {1}" -f $c.CheckID, $c.Title) 'Info'
            $script:Results.Add( (Invoke-CISCheck -Check $c -Scope $sub) ) | Out-Null
        }
    }

    Write-Step ("{0} result rows produced" -f $script:Results.Count) 'Ok'
}

# --------------------------------------------------------------------------- #
#  Inventory-cache lookup helpers used by check scriptblocks
# --------------------------------------------------------------------------- #
function Get-CachedResources {
    param([string]$Type, [string]$SubscriptionId)
    $t = $Type.ToLowerInvariant()
    if (-not $script:Inventory.Resources.ContainsKey($t)) { return @() }
    $rows = $script:Inventory.Resources[$t]
    if ($SubscriptionId) { $rows = $rows | Where-Object { $_.subscriptionId -eq $SubscriptionId } }
    return ,@($rows)
}

# --------------------------------------------------------------------------- #
#  Check registry (built up by the per-section regions below)
# --------------------------------------------------------------------------- #
$script:CheckRegistry = New-Object 'System.Collections.Generic.List[hashtable]'

function Register-Check { param([hashtable]$Check) $script:CheckRegistry.Add($Check) | Out-Null }

# ////////////////////////////////////////////////////////////////////////////
# /////// CHECK DEFINITIONS -- populated by per-section regions below /////////
# ////////////////////////////////////////////////////////////////////////////

#region Section1_IAM
# CIS Section 1 -- Identity and Access Management (Entra ID + AAD-related ARM checks)
# All tenant-scoped unless explicitly per-subscription.

Register-Check @{
    CheckID='CIS-1.1.1'; CISControlID='1.1.1'; Section='1. Identity and Access Management'
    Title="Ensure Security Defaults is enabled on Microsoft Entra ID (if no CA policies)"
    Severity='High'; Level=1
    Description='Security Defaults provide free, Microsoft-curated baseline MFA + legacy auth blocking for tenants without Entra P1.'
    BestPractice='Either Security Defaults enabled, OR equivalent Conditional Access policies in place.'
    Remediation='Entra admin center > Properties > Manage Security defaults > Enabled, OR build equivalent CA policies.'
    RequiresPerms=@('Policy.Read.All (Graph)'); ScopeType='Tenant'
    Run = {
        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $caCount = (Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($sd.IsEnabled) {
            @{ Status='Pass'; Actual='Security Defaults enabled'; Evidence=@{ SecurityDefaultsEnabled=$true; ConditionalAccessPolicies=$caCount } }
        } elseif ($caCount -gt 0) {
            @{ Status='Manual'; Actual="Security Defaults disabled but $caCount CA policies present; verify they enforce equivalent baseline"; Evidence=@{ SecurityDefaultsEnabled=$false; ConditionalAccessPolicies=$caCount } }
        } else {
            @{ Status='Fail'; Actual='Security Defaults disabled AND no Conditional Access policies'; Evidence=@{ SecurityDefaultsEnabled=$false; ConditionalAccessPolicies=0 } }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.1.2'; CISControlID='1.1.2'; Section='1. Identity and Access Management'
    Title='Ensure MFA is enabled for all privileged users'
    Severity='High'; Level=1
    Description='Every account in a privileged Entra role should require MFA via CA policy or Security Defaults.'
    BestPractice='CA policy requiring MFA targets all privileged role members, or Security Defaults enabled.'
    Remediation='Create CA policy: Assignments > Users > Directory roles (privileged) > Grant > Require MFA.'
    RequiresPerms=@('Policy.Read.All','RoleManagement.Read.Directory'); ScopeType='Tenant'
    Run = {
        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        if ($sd.IsEnabled) { return @{ Status='Pass'; Actual='Security Defaults covers MFA for privileged roles'; Evidence=@{ SecurityDefaultsEnabled=$true } } }
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $privPolicies = $policies | Where-Object {
            ($_.Conditions.Users.IncludeRoles -and $_.Conditions.Users.IncludeRoles.Count -gt 0) -and
            ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        if ($privPolicies.Count -gt 0) {
            @{ Status='Pass'; Actual="$($privPolicies.Count) CA policy(s) enforce MFA on privileged role members"; Evidence=($privPolicies | Select-Object DisplayName,Id) }
        } else {
            @{ Status='Fail'; Actual='No enabled CA policy enforces MFA for privileged role members'; Evidence=$null }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.1.3'; CISControlID='1.1.3'; Section='1. Identity and Access Management'
    Title='Ensure MFA is enabled for all non-privileged users'
    Severity='High'; Level=1
    Description='All users (not just admins) should require MFA.'
    BestPractice='CA policy "All users / All cloud apps / Require MFA" or Security Defaults.'
    Remediation='Create CA policy targeting All Users excluding break-glass accounts, requiring MFA.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        if ($sd.IsEnabled) { return @{ Status='Pass'; Actual='Security Defaults enforces MFA for all users'; Evidence=@{ SecurityDefaultsEnabled=$true } } }
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $allUsers = $policies | Where-Object {
            ($_.Conditions.Users.IncludeUsers -contains 'All') -and
            ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        if ($allUsers.Count -gt 0) {
            @{ Status='Pass'; Actual="$($allUsers.Count) CA policy(s) require MFA for All Users"; Evidence=($allUsers | Select-Object DisplayName,Id) }
        } else {
            @{ Status='Fail'; Actual='No enabled CA policy requires MFA for All Users'; Evidence=$null }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.1.4'; CISControlID='1.1.4'; Section='1. Identity and Access Management'
    Title='Ensure "Allow users to remember multi-factor authentication on devices they trust" is disabled'
    Severity='Medium'; Level=1
    Description='Legacy per-user MFA setting in the classic Entra portal that allows users to skip MFA on remembered devices.'
    BestPractice='Disabled.'
    Remediation='Entra > Users > Per-user MFA > service settings > uncheck "Allow users to remember MFA".'
    RequiresPerms=@('Portal access (no Graph API)'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Setting only visible in legacy Entra MFA portal; verify manually'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.2.1'; CISControlID='1.2.1'; Section='1. Identity and Access Management'
    Title='Ensure Trusted Locations are defined'
    Severity='Medium'; Level=1
    Description='Trusted (named) locations let CA policies treat known corporate IP space as low-risk.'
    BestPractice='At least one Named Location marked as trusted.'
    Remediation='Entra > Security > Conditional Access > Named locations > New location.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $loc = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
        $trusted = $loc | Where-Object { $_.AdditionalProperties.isTrusted -eq $true -or $_.IsTrusted -eq $true }
        if ($trusted.Count -gt 0) {
            @{ Status='Pass'; Actual="$($trusted.Count) trusted named location(s) defined"; Evidence=($trusted | Select-Object DisplayName,Id) }
        } else {
            @{ Status='Fail'; Actual="No trusted named locations defined (total locations: $($loc.Count))"; Evidence=$null }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.2.2'; CISControlID='1.2.2'; Section='1. Identity and Access Management'
    Title='Ensure an exclusionary Geographic Access Policy is considered'
    Severity='Medium'; Level=2
    Description='CA policy that blocks sign-ins from unexpected countries / regions.'
    BestPractice='At least one enabled CA policy blocks sign-ins from disallowed countries.'
    Remediation='Create CA policy: Locations > Selected (countries to block) > Grant > Block.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $geo = $policies | Where-Object {
            $_.Conditions.Locations -and
            ($_.GrantControls.BuiltInControls -contains 'block')
        }
        if ($geo.Count -gt 0) {
            @{ Status='Pass'; Actual="$($geo.Count) geographic blocking CA policy(s) present"; Evidence=($geo | Select-Object DisplayName,Id) }
        } else {
            @{ Status='Fail'; Actual='No CA policy blocks sign-ins from unexpected geographies'; Evidence=$null }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.2.3'; CISControlID='1.2.3'; Section='1. Identity and Access Management'
    Title='Ensure a CA policy requires MFA for administrative roles'
    Severity='High'; Level=1
    Description='Privileged roles must always be MFA-protected, not just at session level.'
    BestPractice='CA policy targets privileged role members and grants only with MFA.'
    Remediation='Create CA policy: Users > Directory roles (Global Admin, Privileged Role Admin, etc.) > Grant > Require MFA.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $hits = $policies | Where-Object {
            ($_.Conditions.Users.IncludeRoles.Count -gt 0) -and
            ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        if ($hits.Count -gt 0) { @{ Status='Pass'; Actual="$($hits.Count) policy(s)"; Evidence=($hits | Select-Object DisplayName,Id) } }
        else { @{ Status='Fail'; Actual='No enabled CA policy enforces MFA on directory roles'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-1.2.4'; CISControlID='1.2.4'; Section='1. Identity and Access Management'
    Title='Ensure a CA policy requires MFA for Azure Management'
    Severity='High'; Level=1
    Description='Access to ARM (Azure portal, CLI, PowerShell, REST) should require MFA.'
    BestPractice='CA policy targets cloud app "Microsoft Azure Management" with grant Require MFA.'
    Remediation='Create CA policy: Cloud apps > Microsoft Azure Management > Grant > Require MFA.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $azureMgmtAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $hits = $policies | Where-Object {
            ($_.Conditions.Applications.IncludeApplications -contains $azureMgmtAppId -or $_.Conditions.Applications.IncludeApplications -contains 'All') -and
            ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        if ($hits.Count -gt 0) { @{ Status='Pass'; Actual="$($hits.Count) policy(s) require MFA for Azure Management"; Evidence=($hits | Select-Object DisplayName,Id) } }
        else { @{ Status='Fail'; Actual='No CA policy requires MFA for Microsoft Azure Management'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-1.2.5'; CISControlID='1.2.5'; Section='1. Identity and Access Management'
    Title='Ensure a CA policy blocks legacy authentication'
    Severity='High'; Level=1
    Description='Legacy auth protocols (POP, IMAP, SMTP basic, older Office clients) cannot enforce MFA and must be blocked.'
    BestPractice='CA policy with client app types "Exchange ActiveSync clients" + "Other clients" > Block.'
    Remediation='Create CA policy: Conditions > Client apps > select Exchange ActiveSync + Other clients > Grant > Block.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $hits = $policies | Where-Object {
            ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other') -and
            ($_.GrantControls.BuiltInControls -contains 'block')
        }
        if ($hits.Count -gt 0) { @{ Status='Pass'; Actual="$($hits.Count) policy(s) block legacy auth"; Evidence=($hits | Select-Object DisplayName,Id) } }
        else { @{ Status='Fail'; Actual='No CA policy blocks legacy authentication'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-1.2.6'; CISControlID='1.2.6'; Section='1. Identity and Access Management'
    Title='Ensure a CA policy requires MFA on sign-in risk (Entra P2)'
    Severity='Medium'; Level=2
    Description='Identity Protection raises risk for impossible-travel / anonymous IP / leaked credential events. CA policy should force MFA when sign-in risk is medium+.'
    BestPractice='CA policy with Conditions > Sign-in risk = medium/high > Grant > Require MFA.'
    Remediation='Entra > Security > Conditional Access > New policy > Sign-in risk: medium/high > Grant: Require MFA.'
    RequiresPerms=@('Policy.Read.All','Entra P2 license'); ScopeType='Tenant'
    Run = {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $hits = $policies | Where-Object {
            $_.Conditions.SignInRiskLevels.Count -gt 0 -and ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        if ($hits.Count -gt 0) { @{ Status='Pass'; Actual="$($hits.Count) sign-in-risk MFA policy(s)"; Evidence=($hits | Select-Object DisplayName,Id) } }
        else { @{ Status='Fail'; Actual='No sign-in-risk-based MFA CA policy (requires Entra P2)'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-1.2.7'; CISControlID='1.2.7'; Section='1. Identity and Access Management'
    Title='Ensure a CA policy requires password change for high user risk (Entra P2)'
    Severity='Medium'; Level=2
    Description='When Identity Protection raises user risk to High, account should be required to change password.'
    BestPractice='CA policy with Conditions > User risk = high > Grant > Require password change.'
    Remediation='Entra > Security > Conditional Access > User risk = high > Grant: Require password change.'
    RequiresPerms=@('Policy.Read.All','Entra P2 license'); ScopeType='Tenant'
    Run = {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $hits = $policies | Where-Object {
            $_.Conditions.UserRiskLevels.Count -gt 0 -and ($_.GrantControls.BuiltInControls -contains 'passwordChange')
        }
        if ($hits.Count -gt 0) { @{ Status='Pass'; Actual="$($hits.Count) user-risk password-change policy(s)"; Evidence=($hits | Select-Object DisplayName,Id) } }
        else { @{ Status='Fail'; Actual='No user-risk password-change CA policy (requires Entra P2)'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-1.3'; CISControlID='1.3'; Section='1. Identity and Access Management'
    Title='Ensure "Restrict non-admin users from creating tenants" is set to Yes'
    Severity='Medium'; Level=1
    Description='Default user role should not be allowed to create new Entra tenants.'
    BestPractice='AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateTenants = $false'
    Remediation='Entra > Users > User settings > Restrict non-admin users from creating tenants: Yes.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $p = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $val = $p.DefaultUserRolePermissions.AllowedToCreateTenants
        if (-not $val) { @{ Status='Pass'; Actual='Non-admins cannot create tenants'; Evidence=@{ AllowedToCreateTenants=$val } } }
        else           { @{ Status='Fail'; Actual='Non-admin users CAN create tenants'; Evidence=@{ AllowedToCreateTenants=$val } } }
    }
}

Register-Check @{
    CheckID='CIS-1.4'; CISControlID='1.4'; Section='1. Identity and Access Management'
    Title='Ensure no guest users (or that guest users are reviewed)'
    Severity='Medium'; Level=1
    Description='Guests in the directory should be inventoried and reviewed.'
    BestPractice='All guests are intentional and reviewed regularly.'
    Remediation='Entra > Users > Filter userType=Guest; remove stale guests.'
    RequiresPerms=@('User.Read.All'); ScopeType='Tenant'
    Run = {
        $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property Id,DisplayName,UserPrincipalName,CreatedDateTime,SignInActivity -ErrorAction Stop
        @{ Status='Manual'
           Actual="$($guests.Count) guest user(s) present; review for relevance"
           Evidence=($guests | Select-Object DisplayName,UserPrincipalName,CreatedDateTime -First 50) }
    }
}

Register-Check @{
    CheckID='CIS-1.5'; CISControlID='1.5'; Section='1. Identity and Access Management'
    Title='Ensure guest invite restrictions are set to "Only users assigned to specific admin roles"'
    Severity='Medium'; Level=1
    Description='Default users should not be able to invite guests.'
    BestPractice='AllowInvitesFrom = adminsAndGuestInviters (or stricter: none / adminsOnly).'
    Remediation='Entra > External Identities > External collaboration settings > Guest invite settings.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $p = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $val = $p.AllowInvitesFrom
        if ($val -in @('adminsAndGuestInviters','none')) {
            @{ Status='Pass'; Actual="AllowInvitesFrom = $val"; Evidence=@{ AllowInvitesFrom=$val } }
        } else {
            @{ Status='Fail'; Actual="AllowInvitesFrom = $val (too permissive)"; Evidence=@{ AllowInvitesFrom=$val } }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.6'; CISControlID='1.6'; Section='1. Identity and Access Management'
    Title='Ensure "Restrict access to Microsoft Entra admin center" is set to Yes'
    Severity='Low'; Level=1
    Description='Non-admins should not be able to browse the admin center read-only.'
    BestPractice='Restricted to admins.'
    Remediation='Entra > Users > User settings > Restrict access to Entra admin center: Yes.'
    RequiresPerms=@('Portal'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Not exposed via Graph API; verify in portal'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.7'; CISControlID='1.7'; Section='1. Identity and Access Management'
    Title='Ensure "Restrict user ability to access groups features in My Groups" is set to Yes'
    Severity='Low'; Level=2
    Description='Reduces default user permissions to manage groups via My Groups portal.'
    BestPractice='AllowedToCreateSecurityGroups = $false AND AllowedToCreateGroups (M365) controls in place.'
    Remediation='Entra > Groups > General settings.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $p = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $secGrp = $p.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
        if (-not $secGrp) { @{ Status='Pass'; Actual='Default users cannot create security groups'; Evidence=@{ AllowedToCreateSecurityGroups=$secGrp } } }
        else              { @{ Status='Fail'; Actual='Default users CAN create security groups'; Evidence=@{ AllowedToCreateSecurityGroups=$secGrp } } }
    }
}

Register-Check @{
    CheckID='CIS-1.8'; CISControlID='1.8'; Section='1. Identity and Access Management'
    Title='Ensure "Users can create security groups in Azure portals, API or PowerShell" is set to No'
    Severity='Medium'; Level=1
    Description='Default users creating security groups bypasses governance.'
    BestPractice='AllowedToCreateSecurityGroups = $false'
    Remediation='Entra > Groups > General > Users can create security groups: No.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $p = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $val = $p.DefaultUserRolePermissions.AllowedToCreateSecurityGroups
        if (-not $val) { @{ Status='Pass'; Actual='Disabled'; Evidence=@{ AllowedToCreateSecurityGroups=$val } } }
        else           { @{ Status='Fail'; Actual='Enabled -- any user can create security groups'; Evidence=@{ AllowedToCreateSecurityGroups=$val } } }
    }
}

Register-Check @{
    CheckID='CIS-1.9'; CISControlID='1.9'; Section='1. Identity and Access Management'
    Title='Ensure "Owners can manage group membership requests in My Groups" is set to No'
    Severity='Low'; Level=2
    Description='Self-service group membership approval should not be left to owners.'
    BestPractice='Disabled (managed centrally).'
    Remediation='Entra > Groups > General > Self-service group management.'
    RequiresPerms=@('Portal'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Group settings template not consistently exposed via Graph; verify in portal'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.10'; CISControlID='1.10'; Section='1. Identity and Access Management'
    Title='Ensure "Users can create Microsoft 365 groups in Azure portals, API or PowerShell" is set to No'
    Severity='Medium'; Level=2
    Description='Restrict default user ability to spin up M365 groups (which create SharePoint sites, Teams etc).'
    BestPractice='Group.Unified setting EnableGroupCreation = $false (M365 group setting).'
    Remediation='Set via Graph: directorySettings > Group.Unified template > EnableGroupCreation = false.'
    RequiresPerms=@('Directory.Read.All'); ScopeType='Tenant'
    Run = {
        try {
            $settings = Get-MgBetaDirectorySetting -ErrorAction Stop -ErrorVariable e
        } catch {
            # Fallback to v1.0 cmdlet name if beta module not loaded
            $settings = Get-MgGroupSetting -All -ErrorAction Stop
        }
        $gu = $settings | Where-Object { $_.DisplayName -eq 'Group.Unified' } | Select-Object -First 1
        if (-not $gu) { return @{ Status='Manual'; Actual='Group.Unified directory setting not configured (defaults apply: creation allowed)'; Evidence=$null } }
        $kv = $gu.Values | Where-Object { $_.Name -eq 'EnableGroupCreation' } | Select-Object -First 1
        if ($kv -and $kv.Value -eq 'false') { @{ Status='Pass'; Actual='M365 group creation disabled for non-admins'; Evidence=@{ EnableGroupCreation=$kv.Value } } }
        else { @{ Status='Fail'; Actual="EnableGroupCreation = $($kv.Value)"; Evidence=@{ EnableGroupCreation=$kv.Value } } }
    }
}

Register-Check @{
    CheckID='CIS-1.11'; CISControlID='1.11'; Section='1. Identity and Access Management'
    Title='Ensure "Require Multi-Factor Authentication to register or join devices" is Yes'
    Severity='Medium'; Level=1
    Description='Adding/joining a device to the directory should require MFA.'
    BestPractice='Device registration policy.MultiFactorAuthConfiguration = required.'
    Remediation='Entra > Devices > Device settings > Require MFA to register or join devices: Yes.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        try {
            $uri = 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy'
            $r = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            if ($r.multiFactorAuthConfiguration -eq 'required' -or $r.multiFactorAuthConfiguration -eq 1) {
                @{ Status='Pass'; Actual='MFA required for device registration'; Evidence=@{ multiFactorAuthConfiguration=$r.multiFactorAuthConfiguration } }
            } else {
                @{ Status='Fail'; Actual="MFA NOT required (value=$($r.multiFactorAuthConfiguration))"; Evidence=@{ multiFactorAuthConfiguration=$r.multiFactorAuthConfiguration } }
            }
        } catch { throw }
    }
}

Register-Check @{
    CheckID='CIS-1.12'; CISControlID='1.12'; Section='1. Identity and Access Management'
    Title='Ensure no custom subscription owner roles are created'
    Severity='High'; Level=1
    Description='Custom roles with subscription-level write actions (*) effectively grant Owner.'
    BestPractice='Use built-in Owner role only; review and remove any custom roles with broad actions.'
    Remediation='List custom roles and remove unnecessary ones; replace with least-privilege built-ins.'
    RequiresPerms=@('Reader'); ScopeType='Tenant'
    Run = {
        $custom = Get-AzRoleDefinition -Custom -ErrorAction Stop
        $bad = @()
        foreach ($r in $custom) {
            $hasWildcard = ($r.Actions -contains '*') -or ($r.NotActions.Count -eq 0 -and ($r.Actions | Where-Object { $_ -like '*write' -or $_ -eq '*' }))
            $subScope    = $r.AssignableScopes | Where-Object { $_ -match '^/subscriptions/[0-9a-fA-F-]+/?$' -or $_ -eq '/' }
            if ($hasWildcard -and $subScope) { $bad += $r }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="$($custom.Count) custom role(s); none have subscription-level wildcard actions"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) custom owner-equivalent role(s) at subscription scope"; Evidence=($bad | Select-Object Name,Id,Actions,AssignableScopes) } }
    }
}

Register-Check @{
    CheckID='CIS-1.13'; CISControlID='1.13'; Section='1. Identity and Access Management'
    Title='Ensure subscription leaving/entering directory is "Permit no one"'
    Severity='Medium'; Level=1
    Description='Prevent unauthorized subscription transfers in/out of the tenant.'
    BestPractice='Tenant transfer permissions set to "no one" except specific role.'
    Remediation='Entra admin center > Cost Management + Billing > Subscriptions > Manage Policies.'
    RequiresPerms=@('Portal/Billing role'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='No Graph/ARM API; verify in Cost Management policies'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.14'; CISControlID='1.14'; Section='1. Identity and Access Management'
    Title='Ensure custom banned password list is set to "Enforce"'
    Severity='Medium'; Level=1
    Description='Entra Password Protection should enforce a custom banned list in addition to the global list.'
    BestPractice='Password Protection: EnableBannedPasswordCheck=Yes, ModeOfOperation=Enforce, BannedPasswordList populated.'
    Remediation='Entra > Security > Authentication methods > Password protection > Enforce custom list: Yes.'
    RequiresPerms=@('Directory.Read.All','Entra P1+'); ScopeType='Tenant'
    Run = {
        $settings = Get-MgGroupSetting -All -ErrorAction Stop
        $pp = $settings | Where-Object { $_.DisplayName -eq 'Password Rule Settings' } | Select-Object -First 1
        if (-not $pp) { return @{ Status='Fail'; Actual='Password Rule Settings not configured (defaults apply)'; Evidence=$null } }
        $mode = ($pp.Values | Where-Object Name -eq 'BannedPasswordCheckOnPremisesMode').Value
        $enable = ($pp.Values | Where-Object Name -eq 'EnableBannedPasswordCheck').Value
        $list = ($pp.Values | Where-Object Name -eq 'BannedPasswordList').Value
        if ($enable -eq 'true' -and $mode -eq 'Enforced' -and $list) {
            @{ Status='Pass'; Actual='Custom banned password list enforced'; Evidence=@{ EnableBannedPasswordCheck=$enable; Mode=$mode } }
        } else {
            @{ Status='Fail'; Actual="EnableBannedPasswordCheck=$enable Mode=$mode ListLen=$($list.Length)"; Evidence=@{ EnableBannedPasswordCheck=$enable; Mode=$mode } }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.15'; CISControlID='1.15'; Section='1. Identity and Access Management'
    Title='Ensure Self-Service Password Reset is Enabled for All users'
    Severity='Medium'; Level=1
    Description='SSPR reduces helpdesk load and exposure of admin credentials for routine resets.'
    BestPractice='SSPR enabled for All users (or at minimum All except service accounts).'
    Remediation='Entra > Password reset > Properties > Self-service password reset enabled: All.'
    RequiresPerms=@('Portal/Graph beta'); ScopeType='Tenant'
    Run = {
        try {
            $r = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy' -ErrorAction Stop
            $sspr = $r.allowedToUseSSPR
            if ($sspr) { @{ Status='Pass'; Actual='SSPR enabled (tenant authorizationPolicy.allowedToUseSSPR=true)'; Evidence=@{ allowedToUseSSPR=$sspr } } }
            else { @{ Status='Manual'; Actual='Tenant-level allowedToUseSSPR is false; verify scoped enablement in portal'; Evidence=@{ allowedToUseSSPR=$sspr } } }
        } catch { throw }
    }
}

Register-Check @{
    CheckID='CIS-1.16'; CISControlID='1.16'; Section='1. Identity and Access Management'
    Title='Ensure Microsoft Authenticator is configured to use recommended settings'
    Severity='Medium'; Level=1
    Description='Number-matching, geographic location, and app name context strengthen Authenticator MFA.'
    BestPractice='Authenticator method state=Enabled; numberMatchingRequiredState=enabled; show app context.'
    Remediation='Entra > Security > Authentication methods > Microsoft Authenticator > Configure.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $r = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator' -ErrorAction Stop
        if ($r.state -ne 'enabled') { return @{ Status='Fail'; Actual='Microsoft Authenticator method not enabled'; Evidence=@{ state=$r.state } } }
        $fs = $r.featureSettings
        $nm = $fs.numberMatchingRequiredState.state
        $ctx = $fs.displayAppInformationRequiredState.state
        $loc = $fs.displayLocationInformationRequiredState.state
        if ($nm -eq 'enabled' -and $ctx -eq 'enabled' -and $loc -eq 'enabled') {
            @{ Status='Pass'; Actual='Number matching + app context + location enabled'; Evidence=@{ numberMatching=$nm; appContext=$ctx; location=$loc } }
        } else {
            @{ Status='Fail'; Actual="numberMatching=$nm appContext=$ctx location=$loc"; Evidence=@{ numberMatching=$nm; appContext=$ctx; location=$loc } }
        }
    }
}

Register-Check @{
    CheckID='CIS-1.17'; CISControlID='1.17'; Section='1. Identity and Access Management'
    Title='Ensure a phishing-resistant MFA strength is required for administrators'
    Severity='High'; Level=2
    Description='Admins should require FIDO2 / Windows Hello for Business / certificate-based auth, not just OTP/push.'
    BestPractice='CA policy targeting privileged roles requires Authentication Strength = Phishing-resistant.'
    Remediation='Create CA policy: Users > Directory roles > Grant > Require authentication strength: Phishing-resistant MFA.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop | Where-Object { $_.State -eq 'enabled' }
        $hits = $policies | Where-Object {
            $_.Conditions.Users.IncludeRoles.Count -gt 0 -and $_.GrantControls.AuthenticationStrength
        }
        if ($hits.Count -gt 0) { @{ Status='Pass'; Actual="$($hits.Count) policy(s) require authentication strength for admins"; Evidence=($hits | Select-Object DisplayName,Id) } }
        else { @{ Status='Fail'; Actual='No CA policy specifies authentication strength for privileged roles'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-1.18'; CISControlID='1.18'; Section='1. Identity and Access Management'
    Title='Ensure account lockout threshold is <= 10'
    Severity='Medium'; Level=1
    Description='Smart Lockout threshold caps brute-force attempts.'
    BestPractice='lockoutThreshold <= 10.'
    Remediation='Entra > Security > Authentication methods > Password protection > Lockout threshold.'
    RequiresPerms=@('Directory.Read.All'); ScopeType='Tenant'
    Run = {
        $settings = Get-MgGroupSetting -All -ErrorAction Stop
        $pp = $settings | Where-Object { $_.DisplayName -eq 'Password Rule Settings' } | Select-Object -First 1
        if (-not $pp) { return @{ Status='Fail'; Actual='Password Rule Settings not configured (defaults apply: 10)'; Evidence=$null } }
        $th = [int](($pp.Values | Where-Object Name -eq 'LockoutThreshold').Value)
        if ($th -le 10 -and $th -gt 0) { @{ Status='Pass'; Actual="LockoutThreshold=$th"; Evidence=@{ LockoutThreshold=$th } } }
        else { @{ Status='Fail'; Actual="LockoutThreshold=$th (recommended <=10)"; Evidence=@{ LockoutThreshold=$th } } }
    }
}

Register-Check @{
    CheckID='CIS-1.19'; CISControlID='1.19'; Section='1. Identity and Access Management'
    Title='Ensure account lockout duration is >= 60 seconds'
    Severity='Low'; Level=1
    Description='Smart Lockout duration delays subsequent password attempts after lockout.'
    BestPractice='LockoutDurationInSeconds >= 60.'
    Remediation='Entra > Security > Password protection > Lockout duration in seconds.'
    RequiresPerms=@('Directory.Read.All'); ScopeType='Tenant'
    Run = {
        $settings = Get-MgGroupSetting -All -ErrorAction Stop
        $pp = $settings | Where-Object { $_.DisplayName -eq 'Password Rule Settings' } | Select-Object -First 1
        if (-not $pp) { return @{ Status='Fail'; Actual='Password Rule Settings not configured'; Evidence=$null } }
        $d = [int](($pp.Values | Where-Object Name -eq 'LockoutDurationInSeconds').Value)
        if ($d -ge 60) { @{ Status='Pass'; Actual="LockoutDurationInSeconds=$d"; Evidence=@{ LockoutDurationInSeconds=$d } } }
        else { @{ Status='Fail'; Actual="LockoutDurationInSeconds=$d (recommended >=60)"; Evidence=@{ LockoutDurationInSeconds=$d } } }
    }
}

Register-Check @{
    CheckID='CIS-1.20'; CISControlID='1.20'; Section='1. Identity and Access Management'
    Title='Ensure smart lockout is enabled with on-prem hybrid AD (Password Protection for Windows Server AD)'
    Severity='Medium'; Level=2
    Description='Smart Lockout extended to on-prem AD via DC agent.'
    BestPractice='Password Protection for Windows Server AD installed and Enforced.'
    Remediation='Install Password Protection DC agent + proxy; set Mode = Enforced.'
    RequiresPerms=@('On-prem AD'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Hybrid configuration; verify on-prem agent deployment'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.21'; CISControlID='1.21'; Section='1. Identity and Access Management'
    Title='Ensure all members of the AAD admin role review their privileged role assignments'
    Severity='Medium'; Level=2
    Description='Periodic access reviews of privileged role assignments.'
    BestPractice='Quarterly access reviews configured for each privileged role.'
    Remediation='Entra > Identity Governance > Access reviews > New access review.'
    RequiresPerms=@('Process check'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Organizational process; verify access reviews configured'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.22'; CISControlID='1.22'; Section='1. Identity and Access Management'
    Title='Ensure Microsoft Entra Password Protection is deployed to AD DS'
    Severity='Medium'; Level=2
    Description='Hybrid DCs run the Password Protection agent.'
    BestPractice='Agent installed and reporting Healthy.'
    Remediation='Deploy DC agent + proxy.'
    RequiresPerms=@('On-prem AD'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Hybrid configuration; verify DC agent deployment'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.23'; CISControlID='1.23'; Section='1. Identity and Access Management'
    Title='Ensure no custom subscription administrator roles exist'
    Severity='Medium'; Level=1
    Description='Duplicate of 1.12 in spirit but worded for classic admin roles.'
    BestPractice='No custom roles assignable at subscription scope with broad write.'
    Remediation='Audit custom roles, consolidate to built-ins.'
    RequiresPerms=@('Reader'); ScopeType='Tenant'
    Run = {
        $custom = Get-AzRoleDefinition -Custom -ErrorAction Stop
        $names = $custom | Select-Object Name,Id,@{n='Scopes';e={ $_.AssignableScopes -join ', '}}
        @{ Status='Manual'; Actual="$($custom.Count) custom role(s) exist; review for least privilege"; Evidence=$names }
    }
}

Register-Check @{
    CheckID='CIS-1.24'; CISControlID='1.24'; Section='1. Identity and Access Management'
    Title='Ensure custom roles are approved by management'
    Severity='Low'; Level=2
    Description='Governance check: custom role creation should follow change management.'
    BestPractice='Each custom role has a documented business justification + approver.'
    Remediation='Document approval workflow.'
    RequiresPerms=@('Process check'); ScopeType='Tenant'
    Run = { @{ Status='Manual'; Actual='Organizational process; verify approval workflow exists'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-1.25'; CISControlID='1.25'; Section='1. Identity and Access Management'
    Title='Ensure "Users can register applications" is No'
    Severity='Medium'; Level=1
    Description='Default users should not be allowed to register Entra applications.'
    BestPractice='AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps = $false'
    Remediation='Entra > Users > User settings > App registrations: No.'
    RequiresPerms=@('Policy.Read.All'); ScopeType='Tenant'
    Run = {
        $p = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $val = $p.DefaultUserRolePermissions.AllowedToCreateApps
        if (-not $val) { @{ Status='Pass'; Actual='Users cannot register applications'; Evidence=@{ AllowedToCreateApps=$val } } }
        else { @{ Status='Fail'; Actual='Users CAN register applications'; Evidence=@{ AllowedToCreateApps=$val } } }
    }
}

#endregion Section1_IAM

#region Section2_Defender
# CIS Section 2 -- Microsoft Defender for Cloud
# All subscription-scoped. High NoAccess risk: most cmdlets need Security Reader.

# Helper: fetch security contacts via REST (cmdlet response shape varies between Az.Security
# versions and breaks ConvertFrom-Json in older builds; raw REST is reliable).
function _Get-SecurityContactsRest {
    param([string]$SubId)
    try {
        $r = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$SubId/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview" -ErrorAction Stop
        if ($r.StatusCode -ne 200) { return @() }
        $body = $r.Content | ConvertFrom-Json
        if ($body.value) { return @($body.value) }
        return @()
    } catch { return @() }
}

# Helper used by 2.1.* plan checks
function _Test-DefenderPlan {
    param([string]$PricingName, [string]$Label)
    $p = Get-AzSecurityPricing -Name $PricingName -ErrorAction Stop
    if ($p.PricingTier -eq 'Standard') {
        @{ Status='Pass'; Actual="$Label plan = Standard"; Evidence=@{ Name=$p.Name; Tier=$p.PricingTier; SubPlan=$p.SubPlan } }
    } else {
        @{ Status='Fail'; Actual="$Label plan = $($p.PricingTier)"; Evidence=@{ Name=$p.Name; Tier=$p.PricingTier; SubPlan=$p.SubPlan } }
    }
}

$_DefenderPlans = @(
    @{ N='CIS-2.1.1';  P='VirtualMachines';                 L='Defender for Servers' }
    @{ N='CIS-2.1.2';  P='AppServices';                     L='Defender for App Service' }
    @{ N='CIS-2.1.3';  P='SqlServers';                      L='Defender for Azure SQL Databases' }
    @{ N='CIS-2.1.4';  P='SqlServerVirtualMachines';        L='Defender for SQL Servers on machines' }
    @{ N='CIS-2.1.5';  P='OpenSourceRelationalDatabases';   L='Defender for Open-source RDBMS' }
    @{ N='CIS-2.1.6';  P='StorageAccounts';                 L='Defender for Storage' }
    @{ N='CIS-2.1.7';  P='Containers';                      L='Defender for Containers' }
    @{ N='CIS-2.1.8';  P='CosmosDbs';                       L='Defender for Cosmos DB' }
    @{ N='CIS-2.1.9';  P='KeyVaults';                       L='Defender for Key Vault' }
    @{ N='CIS-2.1.10'; P='Arm';                             L='Defender for Resource Manager' }
    @{ N='CIS-2.1.11'; P='CloudPosture';                    L='Defender CSPM' }
    @{ N='CIS-2.1.12'; P='Api';                             L='Defender for APIs' }
)
foreach ($plan in $_DefenderPlans) {
    Register-Check @{
        CheckID=$plan.N; CISControlID=($plan.N -replace 'CIS-',''); Section='2. Microsoft Defender for Cloud'
        Title=("Ensure {0} is set to On" -f $plan.L)
        Severity='High'; Level=2
        Description=("MDC plan '{0}' provides detection and posture management for the targeted workload type." -f $plan.L)
        BestPractice='PricingTier = Standard'
        Remediation=("Set-AzSecurityPricing -Name '{0}' -PricingTier 'Standard'" -f $plan.P)
        RequiresPerms=@('Security Reader (read); Security Admin (set)'); ScopeType='Subscription'
        Run = [ScriptBlock]::Create("_Test-DefenderPlan -PricingName '$($plan.P)' -Label '$($plan.L)'")
    }
}

Register-Check @{
    CheckID='CIS-2.1.13'; CISControlID='2.1.13'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure Microsoft Defender for Endpoint (MDE) integration is enabled'
    Severity='Medium'; Level=2
    Description='MDC server protection should integrate MDE for unified endpoint telemetry.'
    BestPractice='WDATP integration setting Enabled = true.'
    Remediation='Defender for Cloud > Environment Settings > Integrations > Microsoft Defender for Endpoint: On.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        $s = Get-AzSecuritySetting -ErrorAction Stop
        $mde = $s | Where-Object { $_.Name -eq 'WDATP' -or $_.Name -eq 'WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW' } | Select-Object -First 1
        if ($mde -and $mde.Enabled) { @{ Status='Pass'; Actual='MDE integration enabled'; Evidence=$mde } }
        else { @{ Status='Fail'; Actual='MDE integration not enabled'; Evidence=$mde } }
    }
}

Register-Check @{
    CheckID='CIS-2.1.14'; CISControlID='2.1.14'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure Microsoft Defender for Cloud Apps (MDA / MCAS) integration is enabled'
    Severity='Low'; Level=2
    Description='MDC <-> MDA telemetry for cloud app discovery.'
    BestPractice='MCAS setting Enabled = true.'
    Remediation='Defender for Cloud > Integrations > Microsoft Defender for Cloud Apps.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        $s = Get-AzSecuritySetting -ErrorAction Stop
        $mcas = $s | Where-Object { $_.Name -eq 'MCAS' } | Select-Object -First 1
        if ($mcas -and $mcas.Enabled) { @{ Status='Pass'; Actual='MDA integration enabled'; Evidence=$mcas } }
        else { @{ Status='Fail'; Actual='MDA integration not enabled'; Evidence=$mcas } }
    }
}

Register-Check @{
    CheckID='CIS-2.1.15'; CISControlID='2.1.15'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure auto-provisioning of Log Analytics agent / Defender extensions is On'
    Severity='Medium'; Level=1
    Description='New VMs should auto-install monitoring agents required by MDC.'
    BestPractice='AutoProvision = On.'
    Remediation='Defender for Cloud > Environment Settings > Auto provisioning: On.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        $ap = Get-AzSecurityAutoProvisioningSetting -ErrorAction Stop
        $def = $ap | Where-Object { $_.Name -eq 'default' } | Select-Object -First 1
        if ($def -and $def.AutoProvision -eq 'On') { @{ Status='Pass'; Actual='Auto-provisioning On'; Evidence=$def } }
        else { @{ Status='Fail'; Actual="Auto-provisioning = $($def.AutoProvision)"; Evidence=$def } }
    }
}

Register-Check @{
    CheckID='CIS-2.1.16'; CISControlID='2.1.16'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure additional email address(es) is configured for security alerts'
    Severity='Medium'; Level=1
    Description='At least one notification email for MDC alerts beyond the subscription Owner.'
    BestPractice='Security contact email populated.'
    Remediation='Defender for Cloud > Environment Settings > Email notifications.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $contacts = _Get-SecurityContactsRest -SubId $Scope.Id
        if (-not $contacts -or $contacts.Count -eq 0) { return @{ Status='Fail'; Actual='No security contacts configured'; Evidence=$null } }
        $hasEmail = $contacts | Where-Object { $_.properties.emails -and $_.properties.emails.Trim() -ne '' } | Select-Object -First 1
        if ($hasEmail) { @{ Status='Pass'; Actual="Email configured: $($hasEmail.properties.emails)"; Evidence=$hasEmail.properties } }
        else { @{ Status='Fail'; Actual='No security contact email configured'; Evidence=$contacts } }
    }
}

Register-Check @{
    CheckID='CIS-2.1.17'; CISControlID='2.1.17'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure "Notify about alerts with the following severity" is High'
    Severity='Medium'; Level=1
    Description='Notification minimum severity should be High (or lower if desired).'
    BestPractice='AlertNotifications.MinimalSeverity = High (or Medium/Low).'
    Remediation='Defender for Cloud > Email notifications > Notify about alerts: High.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $contacts = _Get-SecurityContactsRest -SubId $Scope.Id
        if (-not $contacts -or $contacts.Count -eq 0) { return @{ Status='Fail'; Actual='No security contact present'; Evidence=$null } }
        $best = $contacts | Where-Object { $_.properties.alertNotifications.state -eq 'On' } | Select-Object -First 1
        if (-not $best) { $best = $contacts | Select-Object -First 1 }
        $minSev = $best.properties.alertNotifications.minimalSeverity
        if ($minSev) { @{ Status='Pass'; Actual="Min severity = $minSev"; Evidence=$best.properties.alertNotifications } }
        else { @{ Status='Fail'; Actual='Alert notifications not enabled (no minimalSeverity set)'; Evidence=$best } }
    }
}

Register-Check @{
    CheckID='CIS-2.1.18'; CISControlID='2.1.18'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure "Notify subscription owners with Owner role assignment" is On'
    Severity='Medium'; Level=1
    Description='Owners should receive MDC alerts in addition to listed email contacts.'
    BestPractice='NotificationsByRole.State = On AND Roles includes "Owner".'
    Remediation='Defender for Cloud > Email notifications > All users with the following roles: Owner.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $contacts = _Get-SecurityContactsRest -SubId $Scope.Id
        if (-not $contacts -or $contacts.Count -eq 0) { return @{ Status='Fail'; Actual='No security contact present'; Evidence=$null } }
        $owner = $contacts | Where-Object { $_.properties.notificationsByRole.state -eq 'On' -and ($_.properties.notificationsByRole.roles -contains 'Owner') } | Select-Object -First 1
        if ($owner) { @{ Status='Pass'; Actual='Owner role notifications On'; Evidence=$owner.properties.notificationsByRole } }
        else { @{ Status='Fail'; Actual='Owner role notifications not enabled'; Evidence=$contacts } }
    }
}

Register-Check @{
    CheckID='CIS-2.1.19'; CISControlID='2.1.19'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure a workspace is configured for MDC to collect agent telemetry'
    Severity='Low'; Level=2
    Description='Subscription is wired to a Log Analytics workspace for MDC data.'
    BestPractice='WorkspaceSettings populated with a workspaceId.'
    Remediation='Defender for Cloud > Environment Settings > Workspace.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        $ws = Get-AzSecurityWorkspaceSetting -ErrorAction Stop
        if ($ws -and $ws.WorkspaceId) { @{ Status='Pass'; Actual="Workspace: $($ws.WorkspaceId)"; Evidence=$ws } }
        else { @{ Status='Fail'; Actual='No custom workspace configured (default workspace in use)'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-2.2.1'; CISControlID='2.2.1'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure that "Microsoft Defender External Attack Surface Management" is reviewed'
    Severity='Low'; Level=2
    Description='EASM is a separate service for external-facing asset discovery.'
    BestPractice='EASM workspace exists and is reviewed regularly.'
    Remediation='Deploy Microsoft.Easm/workspaces; review attack surface.'
    RequiresPerms=@('Process check'); ScopeType='Subscription'
    Run = {
        $easm = @()
        try { $easm = Get-AzResource -ResourceType 'Microsoft.Easm/workspaces' -ErrorAction Stop } catch {}
        if ($easm.Count -gt 0) { @{ Status='Pass'; Actual="$($easm.Count) EASM workspace(s)"; Evidence=($easm | Select-Object Name,ResourceGroupName) } }
        else { @{ Status='Manual'; Actual='No EASM workspaces present; review whether the org should deploy one'; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-2.2.2'; CISControlID='2.2.2'; Section='2. Microsoft Defender for Cloud'
    Title='Ensure "All users with the following roles" includes Owner'
    Severity='Low'; Level=1
    Description='Duplicate intent of 2.1.18 but commonly listed separately. Kept for explicit coverage.'
    BestPractice='Owner role notified for high-severity alerts.'
    Remediation='See 2.1.18.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $contacts = _Get-SecurityContactsRest -SubId $Scope.Id
        if (-not $contacts -or $contacts.Count -eq 0) { return @{ Status='Fail'; Actual='No security contact'; Evidence=$null } }
        $hasOwner = $contacts | Where-Object { $_.properties.notificationsByRole.roles -contains 'Owner' } | Select-Object -First 1
        if ($hasOwner) { @{ Status='Pass'; Actual='Owner notified'; Evidence=$hasOwner.properties } }
        else { @{ Status='Fail'; Actual='Owner not in notification roles'; Evidence=$contacts } }
    }
}

#endregion Section2_Defender

#region Section3_Storage
# CIS Section 3 -- Storage Accounts. Subscription-scoped, reads cached inventory + per-account blob props.

# Helper: get list of storage accounts in scope (from inventory cache)
function _Get-StorageAccountsForScope {
    param($SubId)
    Get-CachedResources -Type 'microsoft.storage/storageaccounts' -SubscriptionId $SubId
}

Register-Check @{
    CheckID='CIS-3.1'; CISControlID='3.1'; Section='3. Storage Accounts'
    Title='Ensure "Secure transfer required" is set to Enabled'
    Severity='High'; Level=1
    Description='Reject HTTP requests; require HTTPS for blob/queue/table/file endpoints.'
    BestPractice='supportsHttpsTrafficOnly = true on every storage account.'
    Remediation='Set-AzStorageAccount -EnableHttpsTrafficOnly $true ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.supportsHttpsTrafficOnly -ne $true }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="$($accts.Count) storage account(s), all enforce HTTPS"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) storage account(s) allow HTTP"; Evidence=($bad | Select-Object name,resourceGroup,id) } }
    }
}

Register-Check @{
    CheckID='CIS-3.2'; CISControlID='3.2'; Section='3. Storage Accounts'
    Title='Ensure infrastructure encryption is enabled'
    Severity='Medium'; Level=2
    Description='Double encryption at infrastructure layer (in addition to service encryption).'
    BestPractice='encryption.requireInfrastructureEncryption = true.'
    Remediation='Must be set at creation time. New-AzStorageAccount -RequireInfrastructureEncryption $true.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.encryption.requireInfrastructureEncryption -ne $true }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All accounts have infra encryption'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) lack infra encryption"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.3'; CISControlID='3.3'; Section='3. Storage Accounts'
    Title='Ensure storage account access keys are periodically regenerated'
    Severity='Medium'; Level=1
    Description='Account keys should be rotated; alternatively use shared-key-disabled with AAD only.'
    BestPractice='Keys rotated within last 90 days OR shared key auth disabled.'
    Remediation='Storage account > Access keys > Rotate; OR set allowSharedKeyAccess=$false (see 3.4).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        # No "last rotated" timestamp surfaced via PS; report as Manual with evidence
        $sharedOnly = $accts | Where-Object { $_.properties.allowSharedKeyAccess -ne $false }
        @{ Status='Manual'
           Actual="$($sharedOnly.Count)/$($accts.Count) accounts still allow shared-key auth -- verify rotation cadence (no API)."
           Evidence=($sharedOnly | Select-Object name,resourceGroup) }
    }
}

Register-Check @{
    CheckID='CIS-3.4'; CISControlID='3.4'; Section='3. Storage Accounts'
    Title='Ensure that "Allow storage account key access" is disabled'
    Severity='High'; Level=2
    Description='Disabling shared key access forces AAD-based auth.'
    BestPractice='allowSharedKeyAccess = false.'
    Remediation='Set-AzStorageAccount -AllowSharedKeyAccess $false ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.allowSharedKeyAccess -ne $false }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Shared key access disabled on all accounts'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) still allow shared-key auth"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.5'; CISControlID='3.5'; Section='3. Storage Accounts'
    Title='Ensure soft delete for blobs is enabled'
    Severity='Medium'; Level=2
    Description='Recover accidentally deleted blobs within retention window.'
    BestPractice='Blob service deleteRetentionPolicy.enabled = true, retention >= 7 days.'
    Remediation='Enable-AzStorageBlobDeleteRetentionPolicy -RetentionDays 7 ...'
    RequiresPerms=@('Reader','Storage Blob Data Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = @(); $err = @()
        foreach ($a in $accts) {
            try {
                $ctx = (Get-AzStorageAccount -ResourceGroupName $a.resourceGroup -Name $a.name -ErrorAction Stop).Context
                $svc = Get-AzStorageBlobServiceProperty -ResourceGroupName $a.resourceGroup -StorageAccountName $a.name -ErrorAction Stop
                if (-not $svc.DeleteRetentionPolicy.Enabled -or $svc.DeleteRetentionPolicy.Days -lt 7) { $bad += $a.name }
            } catch { $err += "$($a.name): $($_.Exception.Message)" }
        }
        if ($bad.Count -eq 0 -and $err.Count -eq 0) { @{ Status='Pass'; Actual='All accounts have blob soft-delete >= 7d'; Evidence=$null } }
        elseif ($bad.Count -eq 0 -and $err.Count -gt 0) { @{ Status='Manual'; Actual="Errors querying blob props: $($err.Count)"; Evidence=$err } }
        else { @{ Status='Fail'; Actual="$($bad.Count) account(s) without sufficient soft delete"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-3.6'; CISControlID='3.6'; Section='3. Storage Accounts'
    Title='Ensure storage logging is enabled for Queue / Table / Blob service'
    Severity='Medium'; Level=2
    Description='Service-level diagnostic logging captures read/write/delete operations.'
    BestPractice='Diagnostic settings with categories StorageRead/StorageWrite/StorageDelete sent to a workspace or storage.'
    Remediation='New-AzDiagnosticSetting for each storage subresource (blobServices/default etc).'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = @()
        foreach ($a in $accts) {
            foreach ($svc in 'blobServices','queueServices','tableServices') {
                try {
                    $rid = "$($a.id)/$svc/default"
                    $ds = Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction SilentlyContinue
                    if (-not $ds) { $bad += "$($a.name)/$svc"; continue }
                    $enabled = $ds | Where-Object { ($_.Log | Where-Object { $_.Enabled }) }
                    if (-not $enabled) { $bad += "$($a.name)/$svc" }
                } catch { $bad += "$($a.name)/$svc(err)" }
            }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Diagnostic logging present on all blob/queue/table services'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) subresource(s) lack diagnostic logging"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-3.7'; CISControlID='3.7'; Section='3. Storage Accounts'
    Title='Ensure blob public access level is disabled'
    Severity='High'; Level=1
    Description='Prevent anonymous blob access at the storage account level.'
    BestPractice='allowBlobPublicAccess = false.'
    Remediation='Set-AzStorageAccount -AllowBlobPublicAccess $false ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.allowBlobPublicAccess -ne $false }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All accounts disallow public blob access'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) allow public blob access"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.8'; CISControlID='3.8'; Section='3. Storage Accounts'
    Title='Ensure default network access rule is set to Deny'
    Severity='High'; Level=1
    Description='Default deny + explicit allow via firewall/private endpoint.'
    BestPractice='networkAcls.defaultAction = Deny.'
    Remediation='Set-AzStorageAccount -NetworkRuleSet (... -DefaultAction Deny ...).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.networkAcls.defaultAction -ne 'Deny' }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All accounts default-deny'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) default to Allow"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.9'; CISControlID='3.9'; Section='3. Storage Accounts'
    Title='Ensure "Allow Azure services on the trusted services list to access" is enabled'
    Severity='Low'; Level=2
    Description='When firewall enabled, trusted Azure services bypass must still work (e.g. Defender, Backup).'
    BestPractice='networkAcls.bypass contains AzureServices.'
    Remediation='Set-AzStorageAccount -NetworkRuleSet (... -Bypass AzureServices,Logging,Metrics ...).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { -not ($_.properties.networkAcls.bypass -match 'AzureServices') }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All accounts allow AzureServices bypass'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) do not allow AzureServices bypass"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.10'; CISControlID='3.10'; Section='3. Storage Accounts'
    Title='Ensure Private Endpoints are used to access Storage Accounts'
    Severity='Medium'; Level=2
    Description='Reduce data exfiltration surface by avoiding public endpoints.'
    BestPractice='At least one Approved privateEndpointConnection per account, public network access disabled.'
    Remediation='Create Private Endpoint to blob/table/queue/file subresource.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $noPe = $accts | Where-Object { -not $_.properties.privateEndpointConnections -or $_.properties.privateEndpointConnections.Count -eq 0 }
        if ($noPe.Count -eq 0) { @{ Status='Pass'; Actual='All accounts have at least one Private Endpoint'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($noPe.Count)/$($accts.Count) account(s) have no Private Endpoint"; Evidence=($noPe | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.11'; CISControlID='3.11'; Section='3. Storage Accounts'
    Title='Ensure soft delete for containers is enabled'
    Severity='Medium'; Level=2
    Description='Recover accidentally deleted blob containers.'
    BestPractice='Blob service containerDeleteRetentionPolicy.enabled = true, days >= 7.'
    Remediation='Enable-AzStorageContainerDeleteRetentionPolicy -RetentionDays 7 ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = @()
        foreach ($a in $accts) {
            try {
                $svc = Get-AzStorageBlobServiceProperty -ResourceGroupName $a.resourceGroup -StorageAccountName $a.name -ErrorAction Stop
                if (-not $svc.ContainerDeleteRetentionPolicy.Enabled -or $svc.ContainerDeleteRetentionPolicy.Days -lt 7) { $bad += $a.name }
            } catch { $bad += "$($a.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Container soft delete >=7d on all accounts'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) account(s) lack container soft delete"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-3.12'; CISControlID='3.12'; Section='3. Storage Accounts'
    Title='Ensure storage for critical data is encrypted with Customer Managed Keys (CMK)'
    Severity='Medium'; Level=2
    Description='CMK gives the customer key revocation control.'
    BestPractice='encryption.keySource = Microsoft.Keyvault for accounts holding sensitive data.'
    Remediation='Set-AzStorageAccount -KeyvaultEncryption ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $pmk = $accts | Where-Object { $_.properties.encryption.keySource -ne 'Microsoft.Keyvault' }
        if ($pmk.Count -eq 0) { @{ Status='Pass'; Actual='All accounts use CMK'; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($pmk.Count)/$($accts.Count) use platform-managed keys; review whether these hold critical data"; Evidence=($pmk | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.13'; CISControlID='3.13'; Section='3. Storage Accounts'
    Title='Ensure storage logging is enabled for Blob service (read/write/delete)'
    Severity='Medium'; Level=2
    Description='Audit data-plane operations on blob endpoints.'
    BestPractice='Blob diagnostic setting with StorageRead/StorageWrite/StorageDelete enabled.'
    Remediation='New-AzDiagnosticSetting on blobServices/default with all three log categories.'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = @()
        foreach ($a in $accts) {
            try {
                $ds = Get-AzDiagnosticSetting -ResourceId "$($a.id)/blobServices/default" -ErrorAction SilentlyContinue
                $hasAll = $false
                foreach ($d in $ds) {
                    $cats = $d.Log | Where-Object { $_.Enabled } | ForEach-Object { $_.Category }
                    if (($cats -contains 'StorageRead') -and ($cats -contains 'StorageWrite') -and ($cats -contains 'StorageDelete')) { $hasAll = $true; break }
                }
                if (-not $hasAll) { $bad += $a.name }
            } catch { $bad += "$($a.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All accounts log Read/Write/Delete on blob'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) account(s) missing blob audit logging"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-3.14'; CISControlID='3.14'; Section='3. Storage Accounts'
    Title='Ensure cross-tenant replication is disabled'
    Severity='High'; Level=1
    Description='Prevent object replication to storage accounts in other Entra tenants.'
    BestPractice='allowCrossTenantReplication = false.'
    Remediation='Set-AzStorageAccount -AllowCrossTenantReplication $false ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.allowCrossTenantReplication -ne $false }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Cross-tenant replication disabled on all accounts'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) allow cross-tenant replication"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-3.15'; CISControlID='3.15'; Section='3. Storage Accounts'
    Title='Ensure minimum TLS version is 1.2 or higher'
    Severity='High'; Level=1
    Description='Block TLS 1.0/1.1 on storage account endpoints.'
    BestPractice='minimumTlsVersion = TLS1_2 (or TLS1_3 once GA).'
    Remediation='Set-AzStorageAccount -MinimumTlsVersion TLS1_2 ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = _Get-StorageAccountsForScope -SubId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No storage accounts'; Evidence=$null } }
        $bad = $accts | Where-Object {
            $v = $_.properties.minimumTlsVersion
            $v -ne 'TLS1_2' -and $v -ne 'TLS1_3'
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All accounts at TLS1.2+'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) allow TLS<1.2"; Evidence=($bad | Select-Object name,resourceGroup,@{n='MinTls';e={$_.properties.minimumTlsVersion}}) } }
    }
}

#endregion Section3_Storage

#region Section4_Databases
# CIS Section 4 -- Database Services. Subscription-scoped.

# --- 4.1 SQL Server ---
Register-Check @{
    CheckID='CIS-4.1.1'; CISControlID='4.1.1'; Section='4. Database Services'
    Title='Ensure SQL Server auditing is enabled'
    Severity='High'; Level=1
    Description='Server-level auditing captures all database actions.'
    BestPractice='Get-AzSqlServerAudit.BlobStorageTargetState OR LogAnalyticsTargetState = Enabled.'
    Remediation='Set-AzSqlServerAudit -State Enabled -StorageAccountResourceId ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $audit = Get-AzSqlServerAudit -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if ($audit.BlobStorageTargetState -ne 'Enabled' -and $audit.LogAnalyticsTargetState -ne 'Enabled' -and $audit.EventHubTargetState -ne 'Enabled') {
                    $bad += $s.name
                }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="$($servers.Count) SQL server(s), auditing enabled on all"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) without auditing"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.1.2'; CISControlID='4.1.2'; Section='4. Database Services'
    Title='Ensure no Azure SQL Database allows ingress from 0.0.0.0/0'
    Severity='High'; Level=1
    Description='Server firewall must not allow any IP to all IPs.'
    BestPractice='No firewall rule with StartIpAddress 0.0.0.0 and EndIpAddress 255.255.255.255.'
    Remediation='Remove-AzSqlServerFirewallRule for offending rule(s).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $rules = Get-AzSqlServerFirewallRule -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                $open = $rules | Where-Object { $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '255.255.255.255' }
                if ($open) { $bad += "$($s.name):$($open.FirewallRuleName -join ',')" }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='No server has 0.0.0.0/0 firewall rule'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) server(s) with open firewall rules"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.1.3'; CISControlID='4.1.3'; Section='4. Database Services'
    Title='Ensure an Entra (AAD) administrator is provisioned for SQL Servers'
    Severity='High'; Level=1
    Description='AAD admin allows central identity management and removes need for SQL logins.'
    BestPractice='Each SQL server has an AAD administrator set.'
    Remediation='Set-AzSqlServerActiveDirectoryAdministrator -DisplayName ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $admin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if (-not $admin) { $bad += $s.name }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All SQL servers have AAD admin'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) lack AAD admin"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.1.4'; CISControlID='4.1.4'; Section='4. Database Services'
    Title='Ensure Data encryption is set to On for every SQL Database (TDE)'
    Severity='High'; Level=1
    Description='Transparent Data Encryption on every database.'
    BestPractice='TDE State = Enabled on all DBs except master.'
    Remediation='Set-AzSqlDatabaseTransparentDataEncryption -State Enabled ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $dbs = Get-AzSqlDatabase -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop | Where-Object DatabaseName -ne 'master'
                foreach ($db in $dbs) {
                    $tde = Get-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $s.resourceGroup -ServerName $s.name -DatabaseName $db.DatabaseName -ErrorAction Stop
                    if ($tde.State -ne 'Enabled') { $bad += "$($s.name)/$($db.DatabaseName)" }
                }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='TDE enabled on all user databases'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) database(s) without TDE"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.1.5'; CISControlID='4.1.5'; Section='4. Database Services'
    Title='Ensure SQL Server TDE protector is encrypted with Customer Managed Key'
    Severity='Medium'; Level=2
    Description='TDE protector should reference a KV key (BYOK) for revocation control.'
    BestPractice='TransparentDataEncryptionProtector.Type = AzureKeyVault.'
    Remediation='Set-AzSqlServerTransparentDataEncryptionProtector -Type AzureKeyVault -KeyId ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $p = Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if ($p.Type -ne 'AzureKeyVault') { $bad += $s.name }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All TDE protectors are CMK'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) using service-managed TDE key"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.1.6'; CISControlID='4.1.6'; Section='4. Database Services'
    Title='Ensure SQL Server auditing retention is >= 90 days'
    Severity='Medium'; Level=2
    Description='Audit log retention must support investigations.'
    BestPractice='RetentionInDays >= 90.'
    Remediation='Set-AzSqlServerAudit -RetentionInDays 90 (storage target only).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $a = Get-AzSqlServerAudit -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if ($a.BlobStorageTargetState -eq 'Enabled' -and ($a.RetentionInDays -lt 90 -and $a.RetentionInDays -ne 0)) { $bad += "$($s.name)(retention=$($a.RetentionInDays))" }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All blob-audited servers retain >=90 days'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) server(s) with retention < 90 days"; Evidence=$bad } }
    }
}

# --- 4.2 SQL ATP / VA ---
Register-Check @{
    CheckID='CIS-4.2.1'; CISControlID='4.2.1'; Section='4. Database Services'
    Title='Ensure Microsoft Defender for SQL is enabled for critical SQL Servers'
    Severity='Medium'; Level=1
    Description='ATP at server level provides anomaly + VA + threat detection.'
    BestPractice='Defender for SQL Server policy ThreatDetectionState = Enabled.'
    Remediation='Update-AzSqlServerAdvancedThreatProtectionSetting -State Enabled.'
    RequiresPerms=@('Reader','Security Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $atp = Get-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if ($atp.ThreatDetectionState -ne 'Enabled') { $bad += $s.name }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='ATP enabled on all SQL servers'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) lack Defender for SQL"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.2.2'; CISControlID='4.2.2'; Section='4. Database Services'
    Title='Ensure Vulnerability Assessment (VA) is enabled on SQL Servers with periodic recurring scans'
    Severity='Medium'; Level=2
    Description='VA scans surface drift from secure baselines.'
    BestPractice='Server VA RecurringScans.IsEnabled = true.'
    Remediation='Update-AzSqlServerVulnerabilityAssessmentSetting -RecurringScansInterval Weekly ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $va = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if (-not $va.RecurringScansInterval -or $va.RecurringScansInterval -eq 'None') { $bad += $s.name }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='VA recurring scans enabled on all servers'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) lack VA recurring scans"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.2.3'; CISControlID='4.2.3'; Section='4. Database Services'
    Title='Ensure VA "Also send email notifications to admins and subscription owners" is set'
    Severity='Low'; Level=2
    Description='Admins notified of new VA findings.'
    BestPractice='EmailAdmins = true on VA settings.'
    Remediation='Update-AzSqlServerVulnerabilityAssessmentSetting -EmailAdmins $true.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $va = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if (-not $va.EmailAdmins) { $bad += $s.name }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='EmailAdmins set on all servers'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) lack EmailAdmins"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.2.4'; CISControlID='4.2.4'; Section='4. Database Services'
    Title='Ensure VA "Send scan reports to" is configured for SQL Servers'
    Severity='Low'; Level=2
    Description='At least one email recipient configured.'
    BestPractice='NotificationEmail list non-empty.'
    Remediation='Update-AzSqlServerVulnerabilityAssessmentSetting -NotificationEmail ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = Get-CachedResources -Type 'microsoft.sql/servers' -SubscriptionId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No SQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $va = Get-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if (-not $va.NotificationEmail -or $va.NotificationEmail.Count -eq 0) { $bad += $s.name }
            } catch { $bad += "$($s.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Notification recipients set'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) without recipients"; Evidence=$bad } }
    }
}

# --- 4.3 PostgreSQL ---
function _Get-PgServers { param($SubId)
    $a = @(Get-CachedResources -Type 'microsoft.dbforpostgresql/servers' -SubscriptionId $SubId)
    $b = @(Get-CachedResources -Type 'microsoft.dbforpostgresql/flexibleservers' -SubscriptionId $SubId)
    return $a + $b
}

Register-Check @{
    CheckID='CIS-4.3.1'; CISControlID='4.3.1'; Section='4. Database Services'
    Title='Ensure SSL connection for PostgreSQL is enabled'
    Severity='High'; Level=1
    Description='Force TLS on the Postgres wire.'
    BestPractice='Single server: sslEnforcement=Enabled. Flexible server: require_secure_transport=ON.'
    Remediation='Update-AzPostgreSqlServer -SslEnforcement Enabled / Update-AzPostgreSqlFlexibleServerConfiguration ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = _Get-PgServers -SubId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No PostgreSQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            $isFlex = $s.type -like '*flexibleservers*'
            if ($isFlex) {
                try {
                    $cfg = Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName $s.resourceGroup -ServerName $s.name -Name 'require_secure_transport' -ErrorAction Stop
                    if ($cfg.Value -ne 'on' -and $cfg.Value -ne 'ON') { $bad += "$($s.name)(flex)" }
                } catch { $bad += "$($s.name)(flex,err)" }
            } else {
                if ($s.properties.sslEnforcement -ne 'Enabled') { $bad += "$($s.name)" }
            }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='SSL/TLS enforced on all PostgreSQL servers'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) without SSL enforcement"; Evidence=$bad } }
    }
}

function _Pg-CheckBoolConfig {
    param($Scope, [string]$Name, [string]$Expected = 'on')
    $servers = _Get-PgServers -SubId $Scope.Id
    if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No PostgreSQL servers'; Evidence=$null } }
    $bad = @()
    foreach ($s in $servers) {
        $isFlex = $s.type -like '*flexibleservers*'
        try {
            if ($isFlex) {
                $cfg = Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName $s.resourceGroup -ServerName $s.name -Name $Name -ErrorAction Stop
            } else {
                $cfg = Get-AzPostgreSqlConfiguration -ResourceGroupName $s.resourceGroup -ServerName $s.name -Name $Name -ErrorAction Stop
            }
            if (($cfg.Value).ToString().ToLower() -ne $Expected.ToLower()) { $bad += "$($s.name)($($cfg.Value))" }
        } catch { $bad += "$($s.name)(err)" }
    }
    if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="$Name = $Expected on all"; Evidence=$null } }
    else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) misconfigured"; Evidence=$bad } }
}

Register-Check @{ CheckID='CIS-4.3.2'; CISControlID='4.3.2'; Section='4. Database Services'
    Title='Ensure PostgreSQL parameter log_checkpoints = on'
    Severity='Low'; Level=2; Description='Log every checkpoint event for forensic value.'
    BestPractice='log_checkpoints = on'
    Remediation='Update-AzPostgreSqlConfiguration -Name log_checkpoints -Value on'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Pg-CheckBoolConfig -Scope $Scope -Name 'log_checkpoints' -Expected 'on' }
}
Register-Check @{ CheckID='CIS-4.3.3'; CISControlID='4.3.3'; Section='4. Database Services'
    Title='Ensure PostgreSQL parameter log_connections = on'
    Severity='Low'; Level=2; Description='Log all session start events.'
    BestPractice='log_connections = on'; Remediation='Update-AzPostgreSqlConfiguration -Name log_connections -Value on'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Pg-CheckBoolConfig -Scope $Scope -Name 'log_connections' -Expected 'on' }
}
Register-Check @{ CheckID='CIS-4.3.4'; CISControlID='4.3.4'; Section='4. Database Services'
    Title='Ensure PostgreSQL parameter log_disconnections = on'
    Severity='Low'; Level=2; Description='Log every session end.'
    BestPractice='log_disconnections = on'; Remediation='Update-AzPostgreSqlConfiguration -Name log_disconnections -Value on'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Pg-CheckBoolConfig -Scope $Scope -Name 'log_disconnections' -Expected 'on' }
}
Register-Check @{ CheckID='CIS-4.3.5'; CISControlID='4.3.5'; Section='4. Database Services'
    Title='Ensure PostgreSQL parameter connection_throttling = on'
    Severity='Low'; Level=2; Description='Throttles repeated failed connections to slow brute force.'
    BestPractice='connection_throttling = on'; Remediation='Update-AzPostgreSqlConfiguration -Name connection_throttling -Value on'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Pg-CheckBoolConfig -Scope $Scope -Name 'connection_throttling' -Expected 'on' }
}

Register-Check @{
    CheckID='CIS-4.3.6'; CISControlID='4.3.6'; Section='4. Database Services'
    Title='Ensure PostgreSQL parameter log_retention_days >= 3'
    Severity='Low'; Level=2
    Description='Logs retained on server side at least 3 days.'
    BestPractice='log_retention_days >= 3'
    Remediation='Update-AzPostgreSqlConfiguration -Name log_retention_days -Value 7'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = _Get-PgServers -SubId $Scope.Id
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No PostgreSQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $cfg = Get-AzPostgreSqlConfiguration -ResourceGroupName $s.resourceGroup -ServerName $s.name -Name 'log_retention_days' -ErrorAction Stop
                if ([int]$cfg.Value -lt 3) { $bad += "$($s.name)($($cfg.Value))" }
            } catch {} # flexible server uses Azure Monitor diag settings
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Retention >=3 on applicable servers'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) under-retained"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.3.7'; CISControlID='4.3.7'; Section='4. Database Services'
    Title='Ensure "Allow access to Azure services" is disabled for PostgreSQL'
    Severity='Medium'; Level=1
    Description='Equivalent to a 0.0.0.0/0 rule named AllowAllWindowsAzureIps.'
    BestPractice='No AllowAllAzureIps firewall rule present.'
    Remediation='Remove-AzPostgreSqlFirewallRule -Name AllowAllAzureIps.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = _Get-PgServers -SubId $Scope.Id | Where-Object { $_.type -notlike '*flexibleservers*' }
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Single-server PostgreSQL'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            try {
                $rules = Get-AzPostgreSqlFirewallRule -ResourceGroupName $s.resourceGroup -ServerName $s.name -ErrorAction Stop
                if ($rules | Where-Object { $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '0.0.0.0' }) { $bad += $s.name }
            } catch {}
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='No AllowAllAzureIps rule'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) server(s) have AllowAllAzureIps"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.3.8'; CISControlID='4.3.8'; Section='4. Database Services'
    Title='Ensure PostgreSQL infrastructure double encryption is enabled'
    Severity='Low'; Level=2
    Description='Adds infrastructure-layer encryption on top of service encryption.'
    BestPractice='infrastructureEncryption = Enabled.'
    Remediation='Must be set at server creation.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers = _Get-PgServers -SubId $Scope.Id | Where-Object { $_.type -notlike '*flexibleservers*' }
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No applicable PostgreSQL servers'; Evidence=$null } }
        $bad = $servers | Where-Object { $_.properties.infrastructureEncryption -ne 'Enabled' }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Infra double encryption on all'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) lack infra encryption"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

# --- 4.4 MySQL ---
Register-Check @{
    CheckID='CIS-4.4.1'; CISControlID='4.4.1'; Section='4. Database Services'
    Title='Ensure MySQL TLS version >= 1.2'
    Severity='High'; Level=1
    Description='Block legacy TLS on MySQL.'
    BestPractice='minimalTlsVersion = TLS1_2 (single server) or tls_version = TLSV1.2 (flexible).'
    Remediation='Update-AzMySqlServer -MinimalTlsVersion TLS1_2'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $servers  = @(Get-CachedResources -Type 'microsoft.dbformysql/servers' -SubscriptionId $Scope.Id)
        $servers += @(Get-CachedResources -Type 'microsoft.dbformysql/flexibleservers' -SubscriptionId $Scope.Id)
        if ($servers.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No MySQL servers'; Evidence=$null } }
        $bad = @()
        foreach ($s in $servers) {
            $v = $s.properties.minimalTlsVersion
            if ($v -and $v -ne 'TLS1_2' -and $v -ne 'TLSv1.2' -and $v -ne 'TLS1_3') { $bad += "$($s.name)($v)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All MySQL servers at TLS 1.2+'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($servers.Count) at TLS<1.2"; Evidence=$bad } }
    }
}

# --- 4.5 Cosmos DB ---
Register-Check @{
    CheckID='CIS-4.5.1'; CISControlID='4.5.1'; Section='4. Database Services'
    Title='Ensure Cosmos DB account has firewall rules or selected networks set (not all networks)'
    Severity='High'; Level=1
    Description='Cosmos accounts should not allow access from all networks.'
    BestPractice='ipRules populated or VNet rules set; publicNetworkAccess Disabled where possible.'
    Remediation='Update-AzCosmosDBAccount -IpRule ... -VirtualNetworkRuleObject ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = Get-CachedResources -Type 'microsoft.documentdb/databaseaccounts' -SubscriptionId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Cosmos DB accounts'; Evidence=$null } }
        $bad = @()
        foreach ($a in $accts) {
            $hasFilter = (
                ($a.properties.ipRules -and $a.properties.ipRules.Count -gt 0) -or
                ($a.properties.virtualNetworkRules -and $a.properties.virtualNetworkRules.Count -gt 0) -or
                ($a.properties.publicNetworkAccess -eq 'Disabled')
            )
            if (-not $hasFilter) { $bad += $a.name }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All Cosmos accounts have network filters / private'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) open to all networks"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-4.5.2'; CISControlID='4.5.2'; Section='4. Database Services'
    Title='Ensure Cosmos DB Private Endpoints are used'
    Severity='Medium'; Level=2
    Description='Prefer private endpoint over public network access for sensitive data.'
    BestPractice='privateEndpointConnections count >= 1 OR publicNetworkAccess Disabled.'
    Remediation='New-AzPrivateEndpoint to the Cosmos account.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = Get-CachedResources -Type 'microsoft.documentdb/databaseaccounts' -SubscriptionId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Cosmos DB accounts'; Evidence=$null } }
        $bad = $accts | Where-Object {
            (-not $_.properties.privateEndpointConnections -or $_.properties.privateEndpointConnections.Count -eq 0) -and
            ($_.properties.publicNetworkAccess -ne 'Disabled')
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All Cosmos accounts have PE or public disabled'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) lack Private Endpoint"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-4.5.3'; CISControlID='4.5.3'; Section='4. Database Services'
    Title='Ensure Cosmos DB account local authentication is disabled (AAD-only)'
    Severity='High'; Level=2
    Description='disableLocalAuth=true forces RBAC for data plane operations.'
    BestPractice='properties.disableLocalAuth = true.'
    Remediation='Update-AzCosmosDBAccount -DisableLocalAuth $true'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $accts = Get-CachedResources -Type 'microsoft.documentdb/databaseaccounts' -SubscriptionId $Scope.Id
        if ($accts.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Cosmos DB accounts'; Evidence=$null } }
        $bad = $accts | Where-Object { $_.properties.disableLocalAuth -ne $true }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Local auth disabled on all Cosmos accounts'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($accts.Count) allow key/local auth"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

#endregion Section4_Databases

#region Section5_Logging
# CIS Section 5 -- Logging and Monitoring. Subscription-scoped.

Register-Check @{
    CheckID='CIS-5.1.1'; CISControlID='5.1.1'; Section='5. Logging and Monitoring'
    Title='Ensure a Diagnostic Setting exists for the subscription Activity Log'
    Severity='High'; Level=1
    Description='Activity log must be exported to long-term storage / Log Analytics.'
    BestPractice='At least one subscription-scoped Diagnostic Setting present.'
    Remediation='New-AzDiagnosticSetting -ResourceId /subscriptions/<id> -Name al -Log @(...).'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        try {
            $ds = Get-AzDiagnosticSetting -ResourceId ("/subscriptions/" + $Scope.Id) -ErrorAction Stop
            if ($ds -and $ds.Count -gt 0) { @{ Status='Pass'; Actual="$($ds.Count) diagnostic setting(s)"; Evidence=($ds | Select-Object Name,Id) } }
            else { @{ Status='Fail'; Actual='No diagnostic setting on subscription activity log'; Evidence=$null } }
        } catch { throw }
    }
}

Register-Check @{
    CheckID='CIS-5.1.2'; CISControlID='5.1.2'; Section='5. Logging and Monitoring'
    Title='Ensure Activity Log captures all categories (Administrative, Security, Alert, Policy, ServiceHealth, etc.)'
    Severity='Medium'; Level=1
    Description='All activity log categories enabled in at least one diagnostic setting.'
    BestPractice='Required categories Administrative, Security, Alert, Policy, Autoscale, ResourceHealth, ServiceHealth, Recommendation present and enabled.'
    Remediation='Update diagnostic setting to include all log categories.'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $required = @('Administrative','Security','Alert','Policy','Autoscale','ResourceHealth','ServiceHealth','Recommendation')
        $ds = Get-AzDiagnosticSetting -ResourceId ("/subscriptions/" + $Scope.Id) -ErrorAction Stop
        if (-not $ds -or $ds.Count -eq 0) { return @{ Status='Fail'; Actual='No diagnostic setting'; Evidence=$null } }
        foreach ($d in $ds) {
            $enabled = $d.Log | Where-Object { $_.Enabled } | ForEach-Object { $_.Category }
            $missing = $required | Where-Object { $_ -notin $enabled }
            if (-not $missing) { return @{ Status='Pass'; Actual="Setting '$($d.Name)' captures all required categories"; Evidence=$null } }
        }
        @{ Status='Fail'; Actual="No setting enables all required categories. Required: $($required -join ', ')"; Evidence=$null }
    }
}

Register-Check @{
    CheckID='CIS-5.1.3'; CISControlID='5.1.3'; Section='5. Logging and Monitoring'
    Title='Ensure Storage container storing Activity Logs is not publicly accessible'
    Severity='High'; Level=1
    Description='Activity log target container must not allow anonymous access.'
    BestPractice='Container PublicAccess = Off.'
    Remediation='Set-AzStorageContainerAcl -Permission Off.'
    RequiresPerms=@('Reader','Storage Blob Data Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $ds = Get-AzDiagnosticSetting -ResourceId ("/subscriptions/" + $Scope.Id) -ErrorAction Stop |
              Where-Object { $_.StorageAccountId }
        if (-not $ds) { return @{ Status='NotApplicable'; Actual='No storage targets'; Evidence=$null } }
        $bad = @()
        foreach ($d in $ds) {
            try {
                $rgName = ($d.StorageAccountId -split '/')[4]
                $saName = ($d.StorageAccountId -split '/')[-1]
                $ctx = (Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction Stop).Context
                $cs = Get-AzStorageContainer -Context $ctx -Name 'insights-activity-logs' -ErrorAction SilentlyContinue
                if ($cs -and $cs.PublicAccess -ne 'Off') { $bad += "$saName/insights-activity-logs" }
            } catch { $bad += "$saName(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Activity log container(s) not public'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) container(s) public"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-5.1.4'; CISControlID='5.1.4'; Section='5. Logging and Monitoring'
    Title='Ensure Storage account containing Activity Logs is encrypted with CMK'
    Severity='Medium'; Level=2
    Description='Target storage uses customer-managed keys.'
    BestPractice='encryption.keySource = Microsoft.Keyvault.'
    Remediation='Set-AzStorageAccount -KeyvaultEncryption ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $ds = Get-AzDiagnosticSetting -ResourceId ("/subscriptions/" + $Scope.Id) -ErrorAction Stop |
              Where-Object { $_.StorageAccountId }
        if (-not $ds) { return @{ Status='NotApplicable'; Actual='No storage targets'; Evidence=$null } }
        $bad = @()
        foreach ($d in $ds) {
            $rgName = ($d.StorageAccountId -split '/')[4]
            $saName = ($d.StorageAccountId -split '/')[-1]
            $sa = Get-AzStorageAccount -ResourceGroupName $rgName -Name $saName -ErrorAction SilentlyContinue
            if ($sa -and $sa.Encryption.KeySource -ne 'Microsoft.Keyvault') { $bad += $saName }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All activity log storage accounts use CMK'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) use platform-managed keys"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-5.1.5'; CISControlID='5.1.5'; Section='5. Logging and Monitoring'
    Title='Ensure logging for Azure Key Vault is enabled'
    Severity='High'; Level=1
    Description='AuditEvent logs on each Key Vault sent to Log Analytics / storage.'
    BestPractice='Diagnostic setting on every KV with AuditEvent category enabled.'
    Remediation='New-AzDiagnosticSetting on each KV with AuditEvent.'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = Get-CachedResources -Type 'microsoft.keyvault/vaults' -SubscriptionId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = @()
        foreach ($v in $vaults) {
            try {
                $ds = Get-AzDiagnosticSetting -ResourceId $v.id -ErrorAction SilentlyContinue
                $hasAudit = $false
                foreach ($d in $ds) {
                    if ($d.Log | Where-Object { $_.Category -eq 'AuditEvent' -and $_.Enabled }) { $hasAudit = $true; break }
                }
                if (-not $hasAudit) { $bad += $v.name }
            } catch { $bad += "$($v.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='AuditEvent logging on all KVs'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vaults.Count) without AuditEvent logging"; Evidence=$bad } }
    }
}

# --- 5.2 Activity Log Alerts ---
# Generic helper: look for an enabled ActivityLogAlert matching a given operation regex
function _ActivityAlertExists {
    param([string]$OperationPattern)
    $alerts = Get-AzActivityLogAlert -ErrorAction SilentlyContinue
    if (-not $alerts) { return @{ Match=$false; Total=0 } }
    $enabled = $alerts | Where-Object { $_.Enabled -eq $true }
    foreach ($a in $enabled) {
        foreach ($cond in $a.ConditionAllOf) {
            if ($cond.Field -in 'operationName','OperationName') {
                if ($cond.Equal -match $OperationPattern -or $cond.EqualsValue -match $OperationPattern) {
                    return @{ Match=$true; Total=$alerts.Count; Alert=$a.Name }
                }
            }
        }
    }
    @{ Match=$false; Total=$alerts.Count }
}

$_AlertSpecs = @(
    @{ N='CIS-5.2.1'; OP='Microsoft.Authorization/policyAssignments/write';    T='Create Policy Assignment'  }
    @{ N='CIS-5.2.2'; OP='Microsoft.Authorization/policyAssignments/delete';   T='Delete Policy Assignment'  }
    @{ N='CIS-5.2.3'; OP='Microsoft.Network/networkSecurityGroups/write';      T='Create/Update NSG'         }
    @{ N='CIS-5.2.4'; OP='Microsoft.Network/networkSecurityGroups/delete';     T='Delete NSG'                }
    @{ N='CIS-5.2.5'; OP='Microsoft.Network/networkSecurityGroups/securityRules/write';  T='Create/Update NSG Rule' }
    @{ N='CIS-5.2.6'; OP='Microsoft.Network/networkSecurityGroups/securityRules/delete'; T='Delete NSG Rule' }
    @{ N='CIS-5.2.7'; OP='Microsoft.Security/securitySolutions/write';         T='Create/Update Security Solution' }
    @{ N='CIS-5.2.8'; OP='Microsoft.Security/securitySolutions/delete';        T='Delete Security Solution' }
    @{ N='CIS-5.2.9'; OP='Microsoft.Sql/servers/firewallRules/write';          T='Create/Update SQL Server Firewall Rule' }
    @{ N='CIS-5.2.10'; OP='Microsoft.Sql/servers/firewallRules/delete';        T='Delete SQL Server Firewall Rule' }
)
foreach ($a in $_AlertSpecs) {
    Register-Check @{
        CheckID=$a.N; CISControlID=($a.N -replace 'CIS-',''); Section='5. Logging and Monitoring'
        Title=("Ensure activity log alert exists for: {0}" -f $a.T)
        Severity='Medium'; Level=1
        Description='Detective control: notify when a sensitive control-plane operation occurs.'
        BestPractice=("Enabled ActivityLogAlert matching operation '{0}'" -f $a.OP)
        Remediation=("New-AzActivityLogAlert with condition operationName equals '{0}'" -f $a.OP)
        RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
        Run = [ScriptBlock]::Create("param(`$Scope) `$r = _ActivityAlertExists -OperationPattern '$($a.OP)'; if (`$r.Match) { @{ Status='Pass'; Actual=`"Alert '`$(`$r.Alert)' matches`"; Evidence=`$r } } else { @{ Status='Fail'; Actual=`"No enabled alert for $($a.OP)`"; Evidence=`$r } }")
    }
}

Register-Check @{
    CheckID='CIS-5.3.1'; CISControlID='5.3.1'; Section='5. Logging and Monitoring'
    Title='Ensure Application Insights is configured for production applications'
    Severity='Low'; Level=2
    Description='Application telemetry presence (criticality is org-defined).'
    BestPractice='At least one App Insights resource per subscription with deployed apps.'
    Remediation='New-AzApplicationInsights ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $ai = Get-CachedResources -Type 'microsoft.insights/components' -SubscriptionId $Scope.Id
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No App Service / Function apps'; Evidence=$null } }
        if ($ai.Count -gt 0) { @{ Status='Manual'; Actual="$($ai.Count) App Insights resource(s); verify they cover production apps"; Evidence=($ai | Select-Object name,resourceGroup) } }
        else { @{ Status='Fail'; Actual="$($apps.Count) app(s) but no Application Insights resources"; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-5.4'; CISControlID='5.4'; Section='5. Logging and Monitoring'
    Title='Ensure Diagnostic Settings exist for all supported resource types (sample sweep)'
    Severity='Medium'; Level=2
    Description='Sweep every Key Vault, SQL Server, NSG, Storage Account, AppService for at least one diagnostic setting.'
    BestPractice='Every monitored resource has >=1 diagnostic setting.'
    Remediation='Apply Azure Policy: deployIfNotExists diagnostic settings.'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $types = @(
            'microsoft.keyvault/vaults','microsoft.sql/servers',
            'microsoft.network/networksecuritygroups','microsoft.storage/storageaccounts',
            'microsoft.web/sites'
        )
        $missing = @(); $total = 0
        foreach ($t in $types) {
            $rs = Get-CachedResources -Type $t -SubscriptionId $Scope.Id
            foreach ($r in $rs) {
                $total++
                try {
                    $ds = Get-AzDiagnosticSetting -ResourceId $r.id -ErrorAction SilentlyContinue
                    if (-not $ds -or $ds.Count -eq 0) { $missing += "$($r.type)/$($r.name)" }
                } catch { $missing += "$($r.name)(err)" }
            }
        }
        if ($total -eq 0) { return @{ Status='NotApplicable'; Actual='No relevant resources'; Evidence=$null } }
        if ($missing.Count -eq 0) { @{ Status='Pass'; Actual="All $total resource(s) have diagnostic settings"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($missing.Count)/$total resource(s) lack diagnostic settings"; Evidence=$missing } }
    }
}

Register-Check @{
    CheckID='CIS-5.5'; CISControlID='5.5'; Section='5. Logging and Monitoring'
    Title='Ensure Log Analytics workspaces have retention >= 30 days (90+ recommended)'
    Severity='Low'; Level=2
    Description='Adequate log retention for investigation.'
    BestPractice='retentionInDays >= 90 (allow 30 for non-critical).'
    Remediation='Set-AzOperationalInsightsWorkspace -RetentionInDays 90'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $ws = Get-CachedResources -Type 'microsoft.operationalinsights/workspaces' -SubscriptionId $Scope.Id
        if ($ws.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No workspaces'; Evidence=$null } }
        $short = $ws | Where-Object { ($_.properties.retentionInDays -as [int]) -lt 30 }
        if ($short.Count -eq 0) { @{ Status='Pass'; Actual="All $($ws.Count) workspaces >= 30 days"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($short.Count)/$($ws.Count) workspaces have retention < 30d"; Evidence=($short | Select-Object name,@{n='Days';e={$_.properties.retentionInDays}}) } }
    }
}

#endregion Section5_Logging

#region Section6_Networking
# CIS Section 6 -- Networking. Subscription-scoped.

# Helper: return NSG rules that expose the given port from 'Internet' / '*' / '0.0.0.0/0'
function _Find-NsgInternetIngressForPort {
    param($SubId, [int]$Port)
    $nsgs = Get-CachedResources -Type 'microsoft.network/networksecuritygroups' -SubscriptionId $SubId
    $hits = @()
    foreach ($nsg in $nsgs) {
        $rules = @($nsg.properties.securityRules) + @($nsg.properties.defaultSecurityRules)
        foreach ($r in $rules) {
            if ($r.properties.access -ne 'Allow') { continue }
            if ($r.properties.direction -ne 'Inbound') { continue }
            $src = @($r.properties.sourceAddressPrefix) + @($r.properties.sourceAddressPrefixes)
            $openSrc = $src | Where-Object { $_ -in '*','Internet','0.0.0.0/0','any' }
            if (-not $openSrc) { continue }
            $portRanges = @($r.properties.destinationPortRange) + @($r.properties.destinationPortRanges)
            foreach ($pr in $portRanges) {
                if (-not $pr) { continue }
                if ($pr -eq '*') { $hits += "$($nsg.name)/$($r.name)"; break }
                if ($pr -eq "$Port") { $hits += "$($nsg.name)/$($r.name)"; break }
                if ($pr -match '^(\d+)-(\d+)$') {
                    $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                    if ($Port -ge $lo -and $Port -le $hi) { $hits += "$($nsg.name)/$($r.name)"; break }
                }
            }
        }
    }
    return ,$hits
}

Register-Check @{
    CheckID='CIS-6.1'; CISControlID='6.1'; Section='6. Networking'
    Title='Ensure no NSG allows RDP (3389) from the Internet'
    Severity='High'; Level=1
    Description='Remote desktop must not be exposed to the public internet without a jump host / Bastion.'
    BestPractice='No inbound Allow rule with source Internet/* and port 3389.'
    Remediation='Remove rule or scope source to VPN/Bastion subnet.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $hits = _Find-NsgInternetIngressForPort -SubId $Scope.Id -Port 3389
        if ($hits.Count -eq 0) { @{ Status='Pass'; Actual='No NSG exposes 3389 to Internet'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($hits.Count) rule(s) expose 3389"; Evidence=$hits } }
    }
}

Register-Check @{
    CheckID='CIS-6.2'; CISControlID='6.2'; Section='6. Networking'
    Title='Ensure no NSG allows SSH (22) from the Internet'
    Severity='High'; Level=1
    Description='SSH must not be exposed to the public internet.'
    BestPractice='No inbound Allow rule with source Internet/* and port 22.'
    Remediation='Remove rule or scope source to VPN/Bastion subnet.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $hits = _Find-NsgInternetIngressForPort -SubId $Scope.Id -Port 22
        if ($hits.Count -eq 0) { @{ Status='Pass'; Actual='No NSG exposes 22 to Internet'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($hits.Count) rule(s) expose 22"; Evidence=$hits } }
    }
}

Register-Check @{
    CheckID='CIS-6.3'; CISControlID='6.3'; Section='6. Networking'
    Title='Ensure no NSG allows ingress to SQL ports (1433/3306/5432/1521) from the Internet'
    Severity='High'; Level=2
    Description='Database engines should not be reachable from the public internet.'
    BestPractice='No inbound Allow rule with source Internet/* and destination ports 1433, 3306, 5432, or 1521.'
    Remediation='Remove rule or restrict source.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $allHits = @()
        foreach ($p in 1433,3306,5432,1521) {
            $hits = _Find-NsgInternetIngressForPort -SubId $Scope.Id -Port $p
            if ($hits.Count -gt 0) { $allHits += $hits | ForEach-Object { "$_(port=$p)" } }
        }
        if ($allHits.Count -eq 0) { @{ Status='Pass'; Actual='No NSG exposes DB ports to Internet'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($allHits.Count) rule(s) expose DB ports"; Evidence=$allHits } }
    }
}

Register-Check @{
    CheckID='CIS-6.4'; CISControlID='6.4'; Section='6. Networking'
    Title='Ensure NSG flow log retention period is greater than 90 days'
    Severity='Low'; Level=2
    Description='Flow logs retained for forensic / incident investigation.'
    BestPractice='Flow log enabled with retentionDays > 90.'
    Remediation='Set-AzNetworkWatcherFlowLog -RetentionPolicyDays 90.'
    RequiresPerms=@('Reader','Network Contributor'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $watchers = Get-CachedResources -Type 'microsoft.network/networkwatchers' -SubscriptionId $Scope.Id
        if ($watchers.Count -eq 0) { return @{ Status='Fail'; Actual='No Network Watcher resource(s)'; Evidence=$null } }
        $bad = @(); $totalFlows = 0
        foreach ($w in $watchers) {
            try {
                $nwObj = Get-AzNetworkWatcher -Name $w.name -ResourceGroupName $w.resourceGroup -ErrorAction Stop
                $flows = Get-AzNetworkWatcherFlowLog -NetworkWatcher $nwObj -ErrorAction SilentlyContinue
                foreach ($f in $flows) {
                    $totalFlows++
                    if (-not $f.Enabled -or $f.RetentionPolicy.Days -le 90) { $bad += "$($w.name)/$($f.Name)(retention=$($f.RetentionPolicy.Days),enabled=$($f.Enabled))" }
                }
            } catch { $bad += "$($w.name)(err)" }
        }
        if ($totalFlows -eq 0) { @{ Status='Fail'; Actual='No flow logs configured'; Evidence=$null } }
        elseif ($bad.Count -eq 0) { @{ Status='Pass'; Actual="$totalFlows flow log(s), all retain >90 days"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$totalFlows flow log(s) misconfigured"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-6.5'; CISControlID='6.5'; Section='6. Networking'
    Title='Ensure Network Watcher is enabled in each region with workloads'
    Severity='Medium'; Level=1
    Description='Network Watcher must exist in any region with VNets / VMs to enable flow logs and diagnostics.'
    BestPractice='One NetworkWatcher per region with resources.'
    Remediation='New-AzNetworkWatcher -Name NetworkWatcher_<region> -Location <region>.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vnets = Get-CachedResources -Type 'microsoft.network/virtualnetworks' -SubscriptionId $Scope.Id
        if ($vnets.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VNets in this subscription'; Evidence=$null } }
        $regions = $vnets | ForEach-Object { $_.location } | Sort-Object -Unique
        $watchers = Get-CachedResources -Type 'microsoft.network/networkwatchers' -SubscriptionId $Scope.Id
        $watchedRegions = $watchers | ForEach-Object { $_.location } | Sort-Object -Unique
        $missing = $regions | Where-Object { $_ -notin $watchedRegions }
        if (-not $missing) { @{ Status='Pass'; Actual="Watcher in all $($regions.Count) region(s) with VNets"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($missing.Count) region(s) without Network Watcher"; Evidence=$missing } }
    }
}

Register-Check @{
    CheckID='CIS-6.6'; CISControlID='6.6'; Section='6. Networking'
    Title='Ensure NSG flow logs are enabled for every NSG'
    Severity='Medium'; Level=2
    Description='Flow logs provide traffic visibility for each NSG.'
    BestPractice='Every NSG has an enabled flow log resource attached.'
    Remediation='Set-AzNetworkWatcherFlowLog ... -TargetResourceId <nsg>.'
    RequiresPerms=@('Reader','Network Contributor'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $nsgs = Get-CachedResources -Type 'microsoft.network/networksecuritygroups' -SubscriptionId $Scope.Id
        if ($nsgs.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No NSGs'; Evidence=$null } }
        $watchers = Get-CachedResources -Type 'microsoft.network/networkwatchers' -SubscriptionId $Scope.Id
        $flowMap = @{}
        foreach ($w in $watchers) {
            try {
                $nwObj = Get-AzNetworkWatcher -Name $w.name -ResourceGroupName $w.resourceGroup -ErrorAction Stop
                Get-AzNetworkWatcherFlowLog -NetworkWatcher $nwObj -ErrorAction SilentlyContinue |
                    Where-Object Enabled | ForEach-Object { $flowMap[$_.TargetResourceId.ToLower()] = $true }
            } catch {}
        }
        $bad = $nsgs | Where-Object { -not $flowMap.ContainsKey($_.id.ToLower()) }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All NSGs have flow logs enabled'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($nsgs.Count) NSGs without flow logs"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-6.7'; CISControlID='6.7'; Section='6. Networking'
    Title='Ensure that public IP addresses are evaluated on a periodic basis'
    Severity='Low'; Level=2
    Description='Public IPs grow over time; inventory periodically for unneeded exposures.'
    BestPractice='Public IP inventory is reviewed; only justified PIPs remain.'
    Remediation='Periodic review; delete unused PIPs.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $pips = Get-CachedResources -Type 'microsoft.network/publicipaddresses' -SubscriptionId $Scope.Id
        if ($pips.Count -eq 0) { @{ Status='Pass'; Actual='No public IPs'; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($pips.Count) public IP(s) -- review for necessity"; Evidence=($pips | Select-Object name,resourceGroup,@{n='Assoc';e={$_.properties.ipConfiguration.id}} -First 50) } }
    }
}

#endregion Section6_Networking

#region Section7_VMs
# CIS Section 7 -- Virtual Machines. Subscription-scoped.

Register-Check @{
    CheckID='CIS-7.1'; CISControlID='7.1'; Section='7. Virtual Machines'
    Title='Ensure Azure Bastion is deployed where remote VM access is needed'
    Severity='Medium'; Level=2
    Description='Bastion removes the need for public IPs on VMs for RDP/SSH.'
    BestPractice='At least one Azure Bastion host where the subscription has VMs.'
    Remediation='New-AzBastion ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vms = Get-CachedResources -Type 'microsoft.compute/virtualmachines' -SubscriptionId $Scope.Id
        $bas = Get-CachedResources -Type 'microsoft.network/bastionhosts' -SubscriptionId $Scope.Id
        if ($vms.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VMs in subscription'; Evidence=$null } }
        if ($bas.Count -gt 0) { @{ Status='Pass'; Actual="$($bas.Count) Bastion host(s)"; Evidence=($bas | Select-Object name,resourceGroup) } }
        else { @{ Status='Fail'; Actual="$($vms.Count) VM(s) but no Bastion host"; Evidence=$null } }
    }
}

Register-Check @{
    CheckID='CIS-7.2'; CISControlID='7.2'; Section='7. Virtual Machines'
    Title='Ensure VMs use Managed Disks'
    Severity='Medium'; Level=1
    Description='Unmanaged disks (VHDs in storage accounts) lack encryption guarantees and lifecycle features.'
    BestPractice='Every VM uses a managed OS disk (storageProfile.osDisk.managedDisk).'
    Remediation='ConvertTo-AzVMManagedDisk ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vms = Get-CachedResources -Type 'microsoft.compute/virtualmachines' -SubscriptionId $Scope.Id
        if ($vms.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VMs'; Evidence=$null } }
        $bad = $vms | Where-Object { -not $_.properties.storageProfile.osDisk.managedDisk }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All VMs use managed disks'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vms.Count) VM(s) use unmanaged disks"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-7.3'; CISControlID='7.3'; Section='7. Virtual Machines'
    Title='Ensure managed disks (OS + data) are encrypted with Customer Managed Keys'
    Severity='Medium'; Level=2
    Description='Disk encryption set with CMK gives revocation control.'
    BestPractice='Disk encryption.type = EncryptionAtRestWithCustomerKey OR DiskWithVMGuestState (CMK).'
    Remediation='New-AzDiskEncryptionSetConfig ... ; New/Update disk with -DiskEncryptionSetId.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $disks = Get-CachedResources -Type 'microsoft.compute/disks' -SubscriptionId $Scope.Id
        if ($disks.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No managed disks'; Evidence=$null } }
        $bad = $disks | Where-Object {
            $t = $_.properties.encryption.type
            $t -ne 'EncryptionAtRestWithCustomerKey' -and $t -ne 'EncryptionAtRestWithPlatformAndCustomerKeys'
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $($disks.Count) disks use CMK"; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($bad.Count)/$($disks.Count) disks use PMK; review whether they hold sensitive data"; Evidence=($bad | Select-Object name,resourceGroup -First 25) } }
    }
}

Register-Check @{
    CheckID='CIS-7.4'; CISControlID='7.4'; Section='7. Virtual Machines'
    Title='Ensure unattached managed disks are encrypted with CMK'
    Severity='Medium'; Level=2
    Description='Unattached disks may contain sensitive snapshots / data and should be CMK-encrypted (or deleted).'
    BestPractice='Disks with managedBy=null use CMK.'
    Remediation='Same as 7.3, or delete stale disks.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $disks = Get-CachedResources -Type 'microsoft.compute/disks' -SubscriptionId $Scope.Id |
                 Where-Object { -not $_.properties.managedBy }
        if ($disks.Count -eq 0) { return @{ Status='Pass'; Actual='No unattached disks'; Evidence=$null } }
        $bad = $disks | Where-Object {
            $t = $_.properties.encryption.type
            $t -ne 'EncryptionAtRestWithCustomerKey' -and $t -ne 'EncryptionAtRestWithPlatformAndCustomerKeys'
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $($disks.Count) unattached disks use CMK"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($disks.Count) unattached disks use PMK"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-7.5'; CISControlID='7.5'; Section='7. Virtual Machines'
    Title='Ensure that only approved extensions are installed on VMs'
    Severity='Low'; Level=2
    Description='VM extensions execute code; inventory and verify each.'
    BestPractice='All extensions on the approved-publisher list.'
    Remediation='Remove-AzVMExtension for unapproved ones; lock down via Azure Policy.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vms = Get-CachedResources -Type 'microsoft.compute/virtualmachines' -SubscriptionId $Scope.Id
        if ($vms.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VMs'; Evidence=$null } }
        $extByPublisher = @{}
        foreach ($vm in $vms) {
            try {
                $exts = Get-AzVMExtension -ResourceGroupName $vm.resourceGroup -VMName $vm.name -ErrorAction Stop
                foreach ($e in $exts) {
                    $k = "$($e.Publisher)/$($e.ExtensionType)"
                    if (-not $extByPublisher.ContainsKey($k)) { $extByPublisher[$k] = 0 }
                    $extByPublisher[$k]++
                }
            } catch {}
        }
        @{ Status='Manual'; Actual="$($extByPublisher.Count) distinct extension types in use across $($vms.Count) VM(s); review approved list"
           Evidence=($extByPublisher.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { @{ Extension=$_.Key; Count=$_.Value } }) }
    }
}

Register-Check @{
    CheckID='CIS-7.6'; CISControlID='7.6'; Section='7. Virtual Machines'
    Title='Ensure endpoint protection is installed on every VM'
    Severity='High'; Level=1
    Description='EDR/AV present on every VM via extension.'
    BestPractice='MDE.Windows / MDE.Linux extension (or equivalent AV) installed on each VM.'
    Remediation='Set-AzVMExtension -Publisher Microsoft.Azure.AzureDefenderForServers -ExtensionType MDE.Windows ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vms = Get-CachedResources -Type 'microsoft.compute/virtualmachines' -SubscriptionId $Scope.Id
        if ($vms.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VMs'; Evidence=$null } }
        $approved = @('MDE.Windows','MDE.Linux','IaaSAntimalware','EndpointProtection','Trend.Micro','Symantec','Microsoft.Azure.Security.IaaSAntimalware')
        $bad = @()
        foreach ($vm in $vms) {
            try {
                $exts = Get-AzVMExtension -ResourceGroupName $vm.resourceGroup -VMName $vm.name -ErrorAction Stop
                $has = $exts | Where-Object { $_.ExtensionType -in $approved -or $_.Name -in $approved }
                if (-not $has) { $bad += $vm.name }
            } catch { $bad += "$($vm.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Endpoint protection present on every VM'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vms.Count) VM(s) without recognized endpoint protection"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-7.7'; CISControlID='7.7'; Section='7. Virtual Machines'
    Title='Ensure VM OS Disk is set to Delete on VM deletion'
    Severity='Low'; Level=2
    Description='Avoid stale orphaned OS disks containing sensitive data.'
    BestPractice='osDisk.deleteOption = Delete.'
    Remediation='Update-AzVM ... -OsDiskDeleteOption Delete'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vms = Get-CachedResources -Type 'microsoft.compute/virtualmachines' -SubscriptionId $Scope.Id
        if ($vms.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VMs'; Evidence=$null } }
        $bad = $vms | Where-Object { $_.properties.storageProfile.osDisk.deleteOption -ne 'Delete' }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All VMs delete OS disk on removal'; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($bad.Count)/$($vms.Count) retain OS disk on delete"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-7.8'; CISControlID='7.8'; Section='7. Virtual Machines'
    Title='Ensure VMs have latest OS patches installed'
    Severity='High'; Level=1
    Description='Patch compliance via Update Manager or Defender for Cloud.'
    BestPractice='Defender / Update Manager reports compliant.'
    Remediation='Use Update Manager assessment + auto patching schedules.'
    RequiresPerms=@('Update Manager / Defender Reader'); ScopeType='Subscription'
    Run = { @{ Status='Manual'; Actual='Verify in Defender / Update Manager dashboards'; Evidence=$null } }
}

Register-Check @{
    CheckID='CIS-7.9'; CISControlID='7.9'; Section='7. Virtual Machines'
    Title='Ensure Trusted Launch (Secure Boot + vTPM) is enabled on Gen2 VMs'
    Severity='Medium'; Level=2
    Description='Trusted Launch protects boot integrity.'
    BestPractice='securityProfile.uefiSettings.secureBootEnabled = true AND vTpmEnabled = true.'
    Remediation='Update-AzVM -SecurityType TrustedLaunch ... (or recreate).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vms = Get-CachedResources -Type 'microsoft.compute/virtualmachines' -SubscriptionId $Scope.Id
        if ($vms.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No VMs'; Evidence=$null } }
        $bad = $vms | Where-Object {
            $sp = $_.properties.securityProfile
            -not $sp -or -not $sp.uefiSettings.secureBootEnabled -or -not $sp.uefiSettings.vTpmEnabled
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='Secure Boot + vTPM on all VMs'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vms.Count) VM(s) lack Trusted Launch"; Evidence=($bad | Select-Object name,resourceGroup -First 25) } }
    }
}

#endregion Section7_VMs

#region Section8_KeyVault
# CIS Section 8 -- Key Vault. Mixed control plane (Reader) and data plane (KV-specific RBAC).
# Data-plane checks (8.1-8.4, 8.8) are the highest NoAccess risk.

function _Get-KeyVaultsForScope { param($SubId) Get-CachedResources -Type 'microsoft.keyvault/vaults' -SubscriptionId $SubId }

Register-Check @{
    CheckID='CIS-8.1'; CISControlID='8.1'; Section='8. Key Vault'
    Title='Ensure that expiration date is set on all KEYS in RBAC Key Vaults'
    Severity='Medium'; Level=1
    Description='Keys without expiration cannot be rotated by lifecycle automation.'
    BestPractice='Every key has Expires set.'
    Remediation='Update-AzKeyVaultKey -Expires (Get-Date).AddYears(2)'
    RequiresPerms=@('Reader','Key Vault Reader','Key Vault Crypto Officer (data plane)'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id | Where-Object { $_.properties.enableRbacAuthorization -eq $true }
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No RBAC Key Vaults'; Evidence=$null } }
        $bad = @(); $checked = 0
        foreach ($v in $vaults) {
            try {
                $keys = Get-AzKeyVaultKey -VaultName $v.name -ErrorAction Stop
                foreach ($k in $keys) {
                    $checked++
                    if (-not $k.Expires) { $bad += "$($v.name)/$($k.Name)" }
                }
            } catch { $bad += "$($v.name)(err:$($_.Exception.Message.Substring(0,[Math]::Min(60,$_.Exception.Message.Length))))" }
        }
        if ($checked -eq 0 -and $bad.Count -gt 0) { return @{ Status='NoAccess'; Actual='Data-plane read denied on RBAC vaults; assign Key Vault Reader role'; Evidence=$bad } }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $checked key(s) have expiration"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) key(s) without expiration"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-8.2'; CISControlID='8.2'; Section='8. Key Vault'
    Title='Ensure that expiration date is set on all KEYS in non-RBAC (access policy) Key Vaults'
    Severity='Medium'; Level=1
    Description='Same as 8.1 for legacy access-policy vaults.'
    BestPractice='Every key has Expires set.'
    Remediation='Update-AzKeyVaultKey -Expires ...'
    RequiresPerms=@('Reader','access policy Get/List for keys'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id | Where-Object { $_.properties.enableRbacAuthorization -ne $true }
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No access-policy Key Vaults'; Evidence=$null } }
        $bad = @(); $checked = 0
        foreach ($v in $vaults) {
            try {
                $keys = Get-AzKeyVaultKey -VaultName $v.name -ErrorAction Stop
                foreach ($k in $keys) {
                    $checked++
                    if (-not $k.Expires) { $bad += "$($v.name)/$($k.Name)" }
                }
            } catch { $bad += "$($v.name)(err)" }
        }
        if ($checked -eq 0 -and $bad.Count -gt 0) { return @{ Status='NoAccess'; Actual='Data-plane access policies missing for caller'; Evidence=$bad } }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $checked key(s) have expiration"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) key(s) without expiration"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-8.3'; CISControlID='8.3'; Section='8. Key Vault'
    Title='Ensure that expiration date is set on all SECRETS in RBAC Key Vaults'
    Severity='Medium'; Level=1
    Description='Secrets should rotate via lifecycle, requiring an expiration date.'
    BestPractice='Every secret has Expires set.'
    Remediation='Update-AzKeyVaultSecret -Expires ...'
    RequiresPerms=@('Reader','Key Vault Secrets User'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id | Where-Object { $_.properties.enableRbacAuthorization -eq $true }
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No RBAC Key Vaults'; Evidence=$null } }
        $bad = @(); $checked = 0
        foreach ($v in $vaults) {
            try {
                $secrets = Get-AzKeyVaultSecret -VaultName $v.name -ErrorAction Stop
                foreach ($s in $secrets) {
                    $checked++
                    if (-not $s.Expires) { $bad += "$($v.name)/$($s.Name)" }
                }
            } catch { $bad += "$($v.name)(err)" }
        }
        if ($checked -eq 0 -and $bad.Count -gt 0) { return @{ Status='NoAccess'; Actual='Data-plane read denied'; Evidence=$bad } }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $checked secret(s) have expiration"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) secret(s) without expiration"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-8.4'; CISControlID='8.4'; Section='8. Key Vault'
    Title='Ensure that expiration date is set on all SECRETS in non-RBAC Key Vaults'
    Severity='Medium'; Level=1
    Description='Same as 8.3 for access-policy vaults.'
    BestPractice='Every secret has Expires set.'
    Remediation='Update-AzKeyVaultSecret -Expires ...'
    RequiresPerms=@('Reader','access policy Get/List for secrets'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id | Where-Object { $_.properties.enableRbacAuthorization -ne $true }
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No access-policy Key Vaults'; Evidence=$null } }
        $bad = @(); $checked = 0
        foreach ($v in $vaults) {
            try {
                $secrets = Get-AzKeyVaultSecret -VaultName $v.name -ErrorAction Stop
                foreach ($s in $secrets) {
                    $checked++
                    if (-not $s.Expires) { $bad += "$($v.name)/$($s.Name)" }
                }
            } catch { $bad += "$($v.name)(err)" }
        }
        if ($checked -eq 0 -and $bad.Count -gt 0) { return @{ Status='NoAccess'; Actual='Data-plane access denied'; Evidence=$bad } }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $checked secret(s) have expiration"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) secret(s) without expiration"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-8.5'; CISControlID='8.5'; Section='8. Key Vault'
    Title='Ensure Key Vaults are recoverable (soft-delete + purge protection)'
    Severity='High'; Level=1
    Description='Prevent accidental or malicious permanent deletion.'
    BestPractice='enableSoftDelete=true AND enablePurgeProtection=true.'
    Remediation='Update-AzKeyVault -EnablePurgeProtection $true (soft delete is on by default on new vaults).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = $vaults | Where-Object { $_.properties.enableSoftDelete -ne $true -or $_.properties.enablePurgeProtection -ne $true }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All KVs recoverable'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vaults.Count) lack soft-delete or purge protection"; Evidence=($bad | Select-Object name,resourceGroup,@{n='Soft';e={$_.properties.enableSoftDelete}},@{n='Purge';e={$_.properties.enablePurgeProtection}}) } }
    }
}

Register-Check @{
    CheckID='CIS-8.6'; CISControlID='8.6'; Section='8. Key Vault'
    Title='Ensure Role-Based Access Control is enabled on Key Vault (vs legacy access policies)'
    Severity='Medium'; Level=2
    Description='RBAC is preferred over access policies for unified governance.'
    BestPractice='enableRbacAuthorization = true.'
    Remediation='Update-AzKeyVault -EnableRbacAuthorization $true (one-way; migrate access policies first).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = $vaults | Where-Object { $_.properties.enableRbacAuthorization -ne $true }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All KVs use RBAC'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vaults.Count) still use access policies"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-8.7'; CISControlID='8.7'; Section='8. Key Vault'
    Title='Ensure Key Vaults use Private Endpoints'
    Severity='Medium'; Level=2
    Description='Private Endpoints eliminate public access risk on KVs holding secrets.'
    BestPractice='At least one privateEndpointConnection per vault.'
    Remediation='New-AzPrivateEndpoint targeting KV.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = $vaults | Where-Object { -not $_.properties.privateEndpointConnections -or $_.properties.privateEndpointConnections.Count -eq 0 }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All KVs have Private Endpoints'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vaults.Count) KVs lack Private Endpoint"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-8.8'; CISControlID='8.8'; Section='8. Key Vault'
    Title='Ensure automatic key rotation is enabled for all keys in Key Vault'
    Severity='Medium'; Level=2
    Description='Rotation policy automates the security-hygiene rotation of crypto material.'
    BestPractice='Every key has a rotation policy with action=Rotate.'
    Remediation='Set-AzKeyVaultKeyRotationPolicy ...'
    RequiresPerms=@('Reader','Key Vault Crypto Officer'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = @(); $checked = 0; $denied = 0
        foreach ($v in $vaults) {
            try {
                $keys = Get-AzKeyVaultKey -VaultName $v.name -ErrorAction Stop
                foreach ($k in $keys) {
                    $checked++
                    try {
                        $rp = Get-AzKeyVaultKeyRotationPolicy -VaultName $v.name -Name $k.Name -ErrorAction Stop
                        $rotate = $rp.LifetimeActions | Where-Object { $_.Action -eq 'Rotate' }
                        if (-not $rotate) { $bad += "$($v.name)/$($k.Name)" }
                    } catch { $bad += "$($v.name)/$($k.Name)(err)" }
                }
            } catch { $denied++ }
        }
        if ($denied -gt 0 -and $checked -eq 0) { return @{ Status='NoAccess'; Actual="$denied vault(s) denied data-plane access"; Evidence=$null } }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $checked key(s) have rotation policy"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) key(s) lack rotation policy"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-8.9'; CISControlID='8.9'; Section='8. Key Vault'
    Title='Ensure Managed HSM keys use Entra ID for access (if HSM in use)'
    Severity='Medium'; Level=2
    Description='Managed HSM should use AAD-only data plane.'
    BestPractice='Managed HSM exists with AAD RBAC active.'
    Remediation='Configure Managed HSM RBAC role assignments.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $hsms = Get-CachedResources -Type 'microsoft.keyvault/managedhsms' -SubscriptionId $Scope.Id
        if ($hsms.Count -eq 0) { @{ Status='NotApplicable'; Actual='No Managed HSMs'; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($hsms.Count) Managed HSM(s) -- verify RBAC assignments"; Evidence=($hsms | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-8.10'; CISControlID='8.10'; Section='8. Key Vault'
    Title='Ensure Key Vault Public Network Access is Disabled'
    Severity='High'; Level=2
    Description='Disable the public endpoint when private endpoints handle traffic.'
    BestPractice='properties.publicNetworkAccess = Disabled.'
    Remediation='Update-AzKeyVault -PublicNetworkAccess Disabled.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = $vaults | Where-Object { $_.properties.publicNetworkAccess -ne 'Disabled' }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All KVs have public network access disabled'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vaults.Count) KVs allow public access"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-8.11'; CISControlID='8.11'; Section='8. Key Vault'
    Title='Ensure diagnostic logging is enabled on every Key Vault (AuditEvent)'
    Severity='High'; Level=1
    Description='Mirror of 5.1.5 specifically scoped to Key Vault to surface KV-by-KV results.'
    BestPractice='Every KV has AuditEvent diagnostic setting.'
    Remediation='New-AzDiagnosticSetting on each KV with AuditEvent.'
    RequiresPerms=@('Reader','Monitoring Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $vaults = _Get-KeyVaultsForScope -SubId $Scope.Id
        if ($vaults.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No Key Vaults'; Evidence=$null } }
        $bad = @()
        foreach ($v in $vaults) {
            try {
                $ds = Get-AzDiagnosticSetting -ResourceId $v.id -ErrorAction SilentlyContinue
                $ok = $false
                foreach ($d in $ds) { if ($d.Log | Where-Object { $_.Category -eq 'AuditEvent' -and $_.Enabled }) { $ok = $true; break } }
                if (-not $ok) { $bad += $v.name }
            } catch { $bad += "$($v.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='AuditEvent logging on all KVs'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($vaults.Count) KVs without AuditEvent logging"; Evidence=$bad } }
    }
}

#endregion Section8_KeyVault

#region Section9_AppService
# CIS Section 9 -- App Service. Subscription-scoped.
# Site config is fetched per-app via Get-AzWebApp because Resource Graph cache does not expand siteConfig.

function _Get-AppSiteConfigs {
    param($SubId)
    $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $SubId
    $out = @()
    foreach ($a in $apps) {
        try {
            $full = Get-AzWebApp -ResourceGroupName $a.resourceGroup -Name $a.name -ErrorAction Stop
            $out += [pscustomobject]@{ Name=$a.name; RG=$a.resourceGroup; Kind=$a.kind; App=$full }
        } catch {
            $out += [pscustomobject]@{ Name=$a.name; RG=$a.resourceGroup; Kind=$a.kind; App=$null; Error=$_.Exception.Message }
        }
    }
    return ,$out
}

Register-Check @{
    CheckID='CIS-9.1'; CISControlID='9.1'; Section='9. App Service'
    Title='Ensure App Service Authentication is enabled (for apps requiring authentication)'
    Severity='Medium'; Level=2
    Description='When apps host non-public content, EasyAuth / federated auth should be enabled.'
    BestPractice='SiteAuthSettingsV2.platform.enabled = true OR SiteAuthSettings.enabled = true.'
    Remediation='Enable EasyAuth in App Service > Authentication.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No App Service / Function apps'; Evidence=$null } }
        $details = @(); $noAuth = 0
        foreach ($a in $apps) {
            try {
                $auth = Invoke-AzRestMethod -Method GET -Path "$($a.id)/config/authsettingsV2?api-version=2022-03-01" -ErrorAction Stop
                $j = $auth.Content | ConvertFrom-Json
                $enabled = $j.properties.globalValidation.requireAuthentication -eq $true -or $j.properties.platform.enabled -eq $true
                if (-not $enabled) { $noAuth++; $details += $a.name }
            } catch { $details += "$($a.name)(err)" }
        }
        @{ Status='Manual'
           Actual="$noAuth of $($apps.Count) app(s) appear to have auth disabled -- verify which should be public vs protected"
           Evidence=$details }
    }
}

Register-Check @{
    CheckID='CIS-9.2'; CISControlID='9.2'; Section='9. App Service'
    Title='Ensure web app redirects all HTTP traffic to HTTPS'
    Severity='High'; Level=1
    Description='httpsOnly forces TLS redirect.'
    BestPractice='properties.httpsOnly = true.'
    Remediation='Set-AzWebApp -HttpsOnly $true ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $bad = $apps | Where-Object { $_.properties.httpsOnly -ne $true }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All apps enforce HTTPS only'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($apps.Count) apps allow HTTP"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

Register-Check @{
    CheckID='CIS-9.3'; CISControlID='9.3'; Section='9. App Service'
    Title='Ensure web apps use minimum TLS version 1.2 or higher'
    Severity='High'; Level=1
    Description='Block TLS 1.0/1.1 on the app endpoint.'
    BestPractice='siteConfig.minTlsVersion = 1.2 or higher.'
    Remediation='Set-AzWebApp -MinTlsVersion 1.2 ...'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $bad = @(); $checked = 0
        foreach ($a in $apps) {
            try {
                $w = Get-AzWebApp -ResourceGroupName $a.resourceGroup -Name $a.name -ErrorAction Stop
                $v = $w.SiteConfig.MinTlsVersion
                $checked++
                if ($v -and ([version]$v -lt [version]'1.2')) { $bad += "$($a.name)($v)" }
            } catch { $bad += "$($a.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual="$checked app(s), all min TLS >=1.2"; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) app(s) allow TLS<1.2"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-9.4'; CISControlID='9.4'; Section='9. App Service'
    Title='Ensure web app "Incoming client certificates" is enabled (for apps requiring mTLS)'
    Severity='Low'; Level=2
    Description='clientCertEnabled = true (for apps that should require client cert).'
    BestPractice='Either app explicitly requires it OR mode is Optional/OptionalInteractiveUser per app.'
    Remediation='Set-AzWebApp -ClientCertEnabled $true.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $none = $apps | Where-Object { $_.properties.clientCertEnabled -ne $true }
        @{ Status='Manual'
           Actual="$($none.Count)/$($apps.Count) app(s) have client cert disabled -- verify which apps require mTLS"
           Evidence=($none | Select-Object name,resourceGroup -First 50) }
    }
}

Register-Check @{
    CheckID='CIS-9.5'; CISControlID='9.5'; Section='9. App Service'
    Title='Ensure App Services have a Managed Identity registered with Entra ID'
    Severity='Medium'; Level=2
    Description='Managed identity avoids secrets in app settings.'
    BestPractice='identity.type contains SystemAssigned or UserAssigned.'
    Remediation='Update-AzWebApp -AssignIdentity $true.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $bad = $apps | Where-Object { -not $_.identity -or $_.identity.type -eq 'None' }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All apps have managed identity'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($apps.Count) apps without managed identity"; Evidence=($bad | Select-Object name,resourceGroup) } }
    }
}

# Helper for runtime version checks 9.6 / 9.7 / 9.8
function _Check-AppRuntime {
    param($Scope, [string]$StackKey, [string]$MinValue)
    $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
    if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
    $bad = @(); $relevant = 0
    foreach ($a in $apps) {
        try {
            $w = Get-AzWebApp -ResourceGroupName $a.resourceGroup -Name $a.name -ErrorAction Stop
            $v = $null
            switch ($StackKey) {
                'php'   { $v = $w.SiteConfig.PhpVersion }
                'python'{ $v = $w.SiteConfig.PythonVersion }
                'java'  { $v = $w.SiteConfig.JavaVersion }
            }
            if ($v) {
                $relevant++
                if (-not $v -or ($v -ne 'OFF' -and $v -lt $MinValue)) { $bad += "$($a.name)($v)" }
            }
        } catch {}
    }
    if ($relevant -eq 0) { @{ Status='NotApplicable'; Actual="No app with $StackKey runtime configured"; Evidence=$null } }
    elseif ($bad.Count -eq 0) { @{ Status='Pass'; Actual="All $relevant $StackKey app(s) at >= $MinValue"; Evidence=$null } }
    else { @{ Status='Manual'; Actual="$($bad.Count)/$relevant $StackKey app(s) below $MinValue -- verify against current supported versions"; Evidence=$bad }
    }
}

Register-Check @{
    CheckID='CIS-9.6'; CISControlID='9.6'; Section='9. App Service'
    Title='Ensure PHP runtime is at a supported version'
    Severity='Medium'; Level=1
    Description='Apps running EOL PHP miss security patches.'
    BestPractice='PHP 8.x.'
    Remediation='Update site config to a supported PHP version.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Check-AppRuntime -Scope $Scope -StackKey 'php' -MinValue '8.0' }
}
Register-Check @{
    CheckID='CIS-9.7'; CISControlID='9.7'; Section='9. App Service'
    Title='Ensure Python runtime is at a supported version'
    Severity='Medium'; Level=1
    Description='Apps running EOL Python miss security patches.'
    BestPractice='Python 3.10+.'
    Remediation='Update site config to a supported Python version.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Check-AppRuntime -Scope $Scope -StackKey 'python' -MinValue '3.10' }
}
Register-Check @{
    CheckID='CIS-9.8'; CISControlID='9.8'; Section='9. App Service'
    Title='Ensure Java runtime is at a supported version'
    Severity='Medium'; Level=1
    Description='Apps running EOL Java miss security patches.'
    BestPractice='Java 11 / 17 LTS.'
    Remediation='Update site config to a supported Java version.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = { param($Scope) _Check-AppRuntime -Scope $Scope -StackKey 'java' -MinValue '11' }
}

Register-Check @{
    CheckID='CIS-9.9'; CISControlID='9.9'; Section='9. App Service'
    Title='Ensure HTTP version is set to 2.0'
    Severity='Low'; Level=2
    Description='Modern HTTP/2 connection multiplexing.'
    BestPractice='siteConfig.http20Enabled = true.'
    Remediation='Set-AzWebApp -Http20Enabled $true.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $bad = @()
        foreach ($a in $apps) {
            try {
                $w = Get-AzWebApp -ResourceGroupName $a.resourceGroup -Name $a.name -ErrorAction Stop
                if (-not $w.SiteConfig.Http20Enabled) { $bad += $a.name }
            } catch { $bad += "$($a.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='HTTP/2 enabled on all apps'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($apps.Count) apps not on HTTP/2"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-9.10'; CISControlID='9.10'; Section='9. App Service'
    Title='Ensure FTP deployments are disabled (FTPS-only or off)'
    Severity='Medium'; Level=1
    Description='Plaintext FTP exposes deployment credentials.'
    BestPractice='siteConfig.ftpsState = Disabled OR FtpsOnly.'
    Remediation='Set-AzWebApp -FtpsState Disabled.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $bad = @()
        foreach ($a in $apps) {
            try {
                $w = Get-AzWebApp -ResourceGroupName $a.resourceGroup -Name $a.name -ErrorAction Stop
                if ($w.SiteConfig.FtpsState -notin 'Disabled','FtpsOnly') { $bad += "$($a.name)($($w.SiteConfig.FtpsState))" }
            } catch { $bad += "$($a.name)(err)" }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='All apps disable plain FTP'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count)/$($apps.Count) apps allow plain FTP"; Evidence=$bad } }
    }
}

Register-Check @{
    CheckID='CIS-9.11'; CISControlID='9.11'; Section='9. App Service'
    Title='Ensure Key Vault is used to store app secrets (no inline secrets in app settings)'
    Severity='Medium'; Level=2
    Description='Inline secrets in App Settings are visible to anyone with Contributor; KV references reduce risk.'
    BestPractice='Each "sensitive" app setting references a KV secret (@Microsoft.KeyVault(...)).'
    Remediation='Replace inline secret values with @Microsoft.KeyVault(SecretUri=...) references.'
    RequiresPerms=@('Reader','Website Contributor or higher to read app settings'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $apps = Get-CachedResources -Type 'microsoft.web/sites' -SubscriptionId $Scope.Id
        if ($apps.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No apps'; Evidence=$null } }
        $apps_with_inline = @(); $denied = 0
        foreach ($a in $apps) {
            try {
                $cfg = Invoke-AzRestMethod -Method POST -Path "$($a.id)/config/appsettings/list?api-version=2022-03-01" -ErrorAction Stop
                $j = $cfg.Content | ConvertFrom-Json
                $secretLike = $j.properties.PSObject.Properties | Where-Object {
                    $_.Name -match '(SECRET|PASSWORD|KEY|TOKEN|CONNECTIONSTRING)' -and ($_.Value -notmatch '^@Microsoft\.KeyVault')
                }
                if ($secretLike) { $apps_with_inline += "$($a.name) ($($secretLike.Count) inline secret-like setting(s))" }
            } catch { $denied++ }
        }
        if ($denied -eq $apps.Count) { @{ Status='NoAccess'; Actual='Could not list app settings (needs higher RBAC)'; Evidence=$null } }
        elseif ($apps_with_inline.Count -eq 0) { @{ Status='Pass'; Actual='No inline secret-named settings detected'; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($apps_with_inline.Count) app(s) have settings named like secrets -- confirm they are KV references"; Evidence=$apps_with_inline } }
    }
}

#endregion Section9_AppService

#region Section10_Misc
# CIS Section 10 -- Misc / Governance.

Register-Check @{
    CheckID='CIS-10.1'; CISControlID='10.1'; Section='10. Miscellaneous'
    Title='Ensure resource locks are configured for resource groups containing production resources'
    Severity='Medium'; Level=2
    Description='Resource locks (CanNotDelete / ReadOnly) protect against accidental deletion of critical infrastructure.'
    BestPractice='At least one ReadOnly or CanNotDelete lock per critical RG.'
    Remediation='New-AzResourceLock -LockName production-lock -LockLevel CanNotDelete -ResourceGroupName <rg>.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $locks = Get-AzResourceLock -ErrorAction Stop
        $rgs   = Get-AzResourceGroup -ErrorAction Stop
        if ($rgs.Count -eq 0) { return @{ Status='NotApplicable'; Actual='No resource groups'; Evidence=$null } }
        $lockedRGs = $locks | Where-Object { $_.ResourceId -match '/resourceGroups/[^/]+$' } | ForEach-Object { ($_.ResourceId -split '/')[4].ToLower() }
        $noLock = $rgs | Where-Object { $_.ResourceGroupName.ToLower() -notin $lockedRGs }
        @{ Status='Manual'
           Actual="$($lockedRGs.Count)/$($rgs.Count) RGs have at least one lock; review remaining $($noLock.Count) for production-criticality"
           Evidence=($noLock | Select-Object -ExpandProperty ResourceGroupName -First 50) }
    }
}

#endregion Section10_Misc

#region Extras
# Non-CIS governance checks that consistently appear in cloud security reviews.

Register-Check @{
    CheckID='EXT-001'; CISControlID='-'; Section='11. Extras (Governance)'
    Title='Surface Defender for Cloud Secure Score for the subscription'
    Severity='Info'; Level=0
    Description='Microsoft Secure Score gives a single benchmark % for each subscription.'
    BestPractice='Score >= 70% (Microsoft target); investigate top recommendations.'
    Remediation='Address top weighted recommendations in MDC > Recommendations.'
    RequiresPerms=@('Security Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $s = Get-AzSecuritySecureScore -ErrorAction Stop | Select-Object -First 1
        if (-not $s) { return @{ Status='NotApplicable'; Actual='No Secure Score available'; Evidence=$null } }
        $pct = [math]::Round(($s.Score.Current / [math]::Max($s.Score.Max,1)) * 100, 1)
        @{ Status='Manual'; Actual="Secure Score: $pct% ($($s.Score.Current)/$($s.Score.Max))"
           Evidence=@{ Current=$s.Score.Current; Max=$s.Score.Max; Percentage=$pct; Weight=$s.Weight } }
    }
}

Register-Check @{
    CheckID='EXT-002'; CISControlID='-'; Section='11. Extras (Governance)'
    Title='Flag standing (always-active) assignments to highest-privilege Entra roles'
    Severity='High'; Level=1
    Description='Standing privileged assignments (vs PIM-eligible) bypass just-in-time controls.'
    BestPractice='No standing Global Admin / Privileged Role Admin / User Access Admin assignments (other than break-glass).'
    Remediation='Convert active assignments to PIM-eligible.'
    RequiresPerms=@('RoleManagement.Read.Directory'); ScopeType='Tenant'
    Run = {
        $watchRoles = @{
            '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
            'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
            'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Access Administrator'
            '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        }
        $hits = @()
        foreach ($roleId in $watchRoles.Keys) {
            try {
                $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$roleId'"
                $r = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                foreach ($asn in $r.value) {
                    $hits += [pscustomobject]@{ Role=$watchRoles[$roleId]; PrincipalId=$asn.principalId; Scope=$asn.directoryScopeId }
                }
            } catch { }
        }
        if ($hits.Count -eq 0) { @{ Status='Pass'; Actual='No standing assignments found on watched roles'; Evidence=$null } }
        else { @{ Status='Manual'; Actual="$($hits.Count) standing assignment(s) on high-privilege roles -- verify each is PIM-eligible or break-glass"; Evidence=$hits } }
    }
}

Register-Check @{
    CheckID='EXT-003'; CISControlID='-'; Section='11. Extras (Governance)'
    Title='Flag service principals with stale credentials (>365 days old or no expiry)'
    Severity='High'; Level=1
    Description='Long-lived SP secrets and certificates broaden the credential-theft attack window.'
    BestPractice='Credentials rotated within 365 days, with explicit expiration.'
    Remediation='Rotate via app registration > Certificates & secrets; prefer federated credentials.'
    RequiresPerms=@('Application.Read.All'); ScopeType='Tenant'
    Run = {
        $apps = Get-MgApplication -All -Property Id,DisplayName,AppId,PasswordCredentials,KeyCredentials -ErrorAction Stop
        $cutoff = (Get-Date).AddDays(-365)
        $bad = @()
        foreach ($a in $apps) {
            foreach ($pc in @($a.PasswordCredentials)) {
                if (-not $pc) { continue }
                $start = if ($pc.StartDateTime) { $pc.StartDateTime } else { $null }
                $end = if ($pc.EndDateTime) { $pc.EndDateTime } else { $null }
                if (-not $end -or $start -lt $cutoff) {
                    $bad += [pscustomobject]@{ App=$a.DisplayName; AppId=$a.AppId; Type='Secret'; Start=$start; End=$end }
                }
            }
            foreach ($kc in @($a.KeyCredentials)) {
                if (-not $kc) { continue }
                $start = if ($kc.StartDateTime) { $kc.StartDateTime } else { $null }
                $end = if ($kc.EndDateTime) { $kc.EndDateTime } else { $null }
                if (-not $end -or $start -lt $cutoff) {
                    $bad += [pscustomobject]@{ App=$a.DisplayName; AppId=$a.AppId; Type='Cert'; Start=$start; End=$end }
                }
            }
        }
        if ($bad.Count -eq 0) { @{ Status='Pass'; Actual='No app credentials older than 365 days'; Evidence=$null } }
        else { @{ Status='Fail'; Actual="$($bad.Count) app credential(s) need attention (old or no expiry)"; Evidence=($bad | Select-Object -First 50) } }
    }
}

Register-Check @{
    CheckID='EXT-004'; CISControlID='-'; Section='11. Extras (Governance)'
    Title='Detect classic (ASM) resources still deployed in subscription'
    Severity='High'; Level=1
    Description='Azure Service Management resources are deprecated and lack modern security controls.'
    BestPractice='No Microsoft.Classic* resources present.'
    Remediation='Migrate to ARM-based resources (Classic VM > VM, Classic Storage > Storage, Classic VNet > VNet).'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $hits = @()
        foreach ($t in 'microsoft.classiccompute/virtualmachines','microsoft.classicstorage/storageaccounts','microsoft.classicnetwork/virtualnetworks') {
            $r = Get-CachedResources -Type $t -SubscriptionId $Scope.Id
            if ($r.Count -gt 0) { $hits += "$t : $($r.Count)" }
        }
        if ($hits.Count -eq 0) { @{ Status='Pass'; Actual='No classic resources'; Evidence=$null } }
        else { @{ Status='Fail'; Actual='Classic resources still deployed'; Evidence=$hits } }
    }
}

Register-Check @{
    CheckID='EXT-005'; CISControlID='-'; Section='11. Extras (Governance)'
    Title='Flag subscriptions with > 3 standing Owner role assignments'
    Severity='Medium'; Level=2
    Description='Too many Owners enlarges blast radius.'
    BestPractice='<= 3 subscription Owners; remainder PIM-eligible or removed.'
    Remediation='Remove unneeded Owner assignments; convert remaining to PIM-eligible.'
    RequiresPerms=@('Reader'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $owners = Get-AzRoleAssignment -Scope ("/subscriptions/" + $Scope.Id) -RoleDefinitionName 'Owner' -ErrorAction Stop
        if ($owners.Count -le 3) { @{ Status='Pass'; Actual="$($owners.Count) Owner assignment(s)"; Evidence=($owners | Select-Object DisplayName,SignInName,PrincipalType) } }
        else { @{ Status='Fail'; Actual="$($owners.Count) Owner assignment(s) -- exceeds recommended 3"; Evidence=($owners | Select-Object DisplayName,SignInName,PrincipalType) } }
    }
}

Register-Check @{
    CheckID='EXT-006'; CISControlID='-'; Section='11. Extras (Governance)'
    Title='Surface coverage banner -- caller permission profile per subscription'
    Severity='Info'; Level=0
    Description='Self-documenting check that records what scopes the caller could read. Important for reading other results correctly.'
    BestPractice='Reader + Security Reader on every audited subscription.'
    Remediation='Assign Reader and Security Reader at MG / subscription scope.'
    RequiresPerms=@('-'); ScopeType='Subscription'
    Run = {
        param($Scope)
        $cov = $script:Inventory.Coverage[$Scope.Id]
        $score = ($cov.Values | Where-Object { $_ }).Count
        @{ Status='Manual'
           Actual="Caller scope coverage: Reader=$($cov.Reader) SecurityReader=$($cov.SecurityReader) GraphPolicy=$($cov.GraphPolicy)"
           Evidence=$cov }
    }
}

#endregion Extras

# --------------------------------------------------------------------------- #
#  Reporters
# --------------------------------------------------------------------------- #
function _Convert-EvidenceToText {
    param($Evidence, [int]$Limit = 4000)
    if ($null -eq $Evidence) { return '' }
    try {
        $json = $Evidence | ConvertTo-Json -Depth 6 -Compress:$false -WarningAction SilentlyContinue
        if ($json.Length -gt $Limit) { $json = $json.Substring(0, $Limit) + "`n... [truncated]" }
        return $json
    } catch {
        return ($Evidence | Out-String).Trim()
    }
}

function _HtmlEncode {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'", '&#39;')
}

function Export-JsonReport {
    param([string]$Path, $Results, $Inventory)
    $bundle = [ordered]@{
        Meta = @{
            ScriptVersion = $script:ScriptVersion
            CISVersion    = $script:CISVersion
            StartedAt     = $script:StartedAt
            CompletedAt   = (Get-Date)
            TenantId      = $Inventory.Tenant
            CallerUpn     = $Inventory.CallerUpn
            Cloud         = $Inventory.Cloud
        }
        Subscriptions = $Inventory.Subscriptions | Select-Object Name, Id, State, TenantId
        Coverage      = $Inventory.Coverage
        Findings      = $Results
    }
    $bundle | ConvertTo-Json -Depth 10 -WarningAction SilentlyContinue | Out-File -FilePath $Path -Encoding utf8
}

function Export-InventoryJson {
    param([string]$Path, $Inventory)
    $invSlim = [ordered]@{}
    foreach ($k in $Inventory.Resources.Keys) {
        $invSlim[$k] = $Inventory.Resources[$k] | Select-Object id, name, type, location, subscriptionId, resourceGroup
    }
    $invSlim | ConvertTo-Json -Depth 6 -WarningAction SilentlyContinue | Out-File -FilePath $Path -Encoding utf8
}

function Export-CsvReport {
    param([string]$Path, $Results)
    $flat = $Results | ForEach-Object {
        $evi = _Convert-EvidenceToText $_.Evidence -Limit 8000
        [pscustomobject]@{
            CheckID          = $_.CheckID
            CISControlID     = $_.CISControlID
            Section          = $_.Section
            Title            = $_.Title
            Severity         = $_.Severity
            Level            = $_.Level
            Status           = $_.Status
            ScopeName        = $_.ScopeName
            ScopeId          = $_.ScopeId
            ActualResult     = $_.ActualResult
            BestPractice     = $_.BestPractice
            Remediation      = $_.Remediation
            RequiresPerms    = $_.RequiresPerms
            Description      = $_.Description
            DurationMs       = $_.DurationMs
            ExceptionType    = $_.ExceptionType
            ExceptionMessage = $_.ExceptionMessage
            Evidence         = $evi
        }
    }
    $flat | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
}

function Export-HtmlReport {
    param([string]$Path, $Results, $Inventory)

    $statusColors = @{
        'Pass'='#1a7f37'; 'Fail'='#c93131'; 'Manual'='#b88600'
        'NoAccess'='#475569'; 'NotApplicable'='#7d7d7d'; 'Error'='#7a3eb3'
    }
    $sevColors = @{ 'High'='#c93131'; 'Medium'='#b88600'; 'Low'='#1a7f37'; 'Info'='#3b82f6' }

    $totals = @{}
    foreach ($s in 'Pass','Fail','Manual','NoAccess','NotApplicable','Error') {
        $totals[$s] = @($Results | Where-Object Status -eq $s).Count
    }
    $failBySev = @{}
    foreach ($sev in 'High','Medium','Low','Info') {
        $failBySev[$sev] = @($Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq $sev }).Count
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    [void]$sb.AppendLine("<title>$($script:ProjectName) - Azure CIS Audit - $(_HtmlEncode $Inventory.Tenant)</title>")
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(@'
:root { --bg:#f5f7fb; --fg:#1f2937; --muted:#6b7280; --card:#ffffff; --border:#e5e7eb;
        --pass:#1a7f37; --fail:#c93131; --manual:#b88600; --noaccess:#475569; --na:#7d7d7d; --error:#7a3eb3; }
* { box-sizing:border-box }
body { font:14px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin:0; background:var(--bg); color:var(--fg); }
header { background:#0f172a; color:#fff; padding:20px 28px; }
header h1 { margin:0 0 6px; font-size:20px; }
header .meta { color:#cbd5e1; font-size:13px; }
header .meta b { color:#fff; font-weight:600; }
.container { padding:18px 28px 64px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin:14px 0 20px; }
.tile { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px; }
.tile .n { font-size:24px; font-weight:600; }
.tile .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
.tile.pass .n { color:var(--pass) } .tile.fail .n { color:var(--fail) } .tile.manual .n { color:var(--manual) }
.tile.noaccess .n { color:var(--noaccess) } .tile.na .n { color:var(--na) } .tile.error .n { color:var(--error) }
.sevbar { display:flex; gap:8px; flex-wrap:wrap; margin:0 0 18px; }
.sevbar .pill { background:var(--card); border:1px solid var(--border); border-radius:999px; padding:4px 12px; font-size:12px; }
.sevbar .pill b { font-weight:600 }
.filter { position:sticky; top:0; z-index:10; background:var(--bg); padding:10px 0; border-bottom:1px solid var(--border); margin-bottom:14px; display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.filter input, .filter select { padding:6px 10px; border:1px solid var(--border); border-radius:6px; background:#fff; font:inherit; }
.filter input[type=text] { min-width:260px; }
.filter label { font-size:13px; color:var(--muted); display:inline-flex; align-items:center; gap:4px; }
details.section { background:var(--card); border:1px solid var(--border); border-radius:8px; margin-bottom:10px; overflow:hidden; }
details.section > summary { padding:10px 14px; cursor:pointer; font-weight:600; background:#fafbff; user-select:none; list-style:none; }
details.section > summary::-webkit-details-marker { display:none }
details.section > summary::before { content:'>'; display:inline-block; width:14px; transition:transform .15s; }
details.section[open] > summary::before { transform:rotate(90deg); }
.section-body { padding:0; }
table { width:100%; border-collapse:collapse; }
tr.row { border-top:1px solid var(--border); }
tr.row.hidden { display:none; }
td { padding:8px 12px; vertical-align:top; font-size:13px; }
td.id { font-family:ui-monospace,Menlo,Consolas,monospace; color:var(--muted); white-space:nowrap; }
td.title { width:55%; }
.badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; font-weight:600; color:#fff; }
.badge.pass { background:var(--pass) } .badge.fail { background:var(--fail) } .badge.manual { background:var(--manual) }
.badge.noaccess { background:var(--noaccess) } .badge.notapplicable { background:var(--na) } .badge.error { background:var(--error) } .badge.info { background:#3b82f6 }
.sev { font-size:11px; padding:1px 6px; border-radius:4px; border:1px solid; }
.sev.high { color:var(--fail); border-color:var(--fail) }
.sev.medium { color:var(--manual); border-color:var(--manual) }
.sev.low { color:var(--pass); border-color:var(--pass) }
.sev.info { color:#3b82f6; border-color:#3b82f6 }
details.row-detail summary { cursor:pointer; padding:6px 0; color:#0b66b3; }
details.row-detail summary::-webkit-details-marker { display:none }
details.row-detail summary::before { content:'> '; }
details.row-detail[open] summary::before { content:'v '; }
.kvgrid { display:grid; grid-template-columns:140px 1fr; gap:6px 14px; margin-top:6px; }
.kvgrid .k { color:var(--muted); }
pre.evidence { background:#0f172a; color:#e2e8f0; padding:10px 12px; border-radius:6px; overflow:auto; white-space:pre-wrap; word-break:break-word; max-height:360px; font:12px/1.4 ui-monospace,Menlo,Consolas,monospace; }
footer { color:var(--muted); padding:24px 28px; font-size:12px; }
footer a { color:#0b66b3; }
.warn { background:#fff8e1; border-left:4px solid #b88600; padding:10px 14px; border-radius:4px; margin:8px 0; font-size:13px; }
'@)
    [void]$sb.AppendLine('</style></head><body>')

    # Header
    $runtime = (Get-Date) - $script:StartedAt
    [void]$sb.AppendLine('<header>')
    [void]$sb.AppendLine("<h1>$($script:ProjectName) &middot; Azure Tenant Security Audit &middot; CIS Foundations v$($script:CISVersion)</h1>")
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine("<b>Tenant:</b> $(_HtmlEncode $Inventory.Tenant) &nbsp;.&nbsp; <b>Cloud:</b> $(_HtmlEncode $Inventory.Cloud) &nbsp;.&nbsp; <b>Caller:</b> $(_HtmlEncode $Inventory.CallerUpn)<br>")
    [void]$sb.AppendLine("<b>Started:</b> $($script:StartedAt.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;.&nbsp; <b>Runtime:</b> $([math]::Round($runtime.TotalMinutes,1)) min &nbsp;.&nbsp; <b>Script:</b> v$($script:ScriptVersion)<br>")
    [void]$sb.AppendLine("<b>Subscriptions audited:</b> $($Inventory.Subscriptions.Count)")
    [void]$sb.AppendLine('</div></header>')

    [void]$sb.AppendLine('<div class="container">')

    # Coverage banner
    $lowCov = $Inventory.Coverage.Values | Where-Object { -not $_.Reader -or -not $_.SecurityReader -or -not $_.GraphPolicy }
    if ($lowCov.Count -gt 0) {
        [void]$sb.AppendLine('<div class="warn">! Coverage may be partial -- the auditing principal lacks Reader / Security Reader / Graph Policy.Read.All on one or more subscriptions. Many <span class="badge noaccess">NoAccess</span> results below are caused by these missing roles, not by misconfiguration.</div>')
    }

    # Summary tiles
    [void]$sb.AppendLine('<div class="tiles">')
    foreach ($k in 'Pass','Fail','Manual','NoAccess','NotApplicable','Error') {
        $cls = $k.ToLower()
        [void]$sb.AppendLine("<div class=`"tile $cls`"><div class=`"n`">$($totals[$k])</div><div class=`"l`">$k</div></div>")
    }
    [void]$sb.AppendLine('</div>')

    # Severity bar
    [void]$sb.AppendLine('<div class="sevbar">')
    [void]$sb.AppendLine("<span class=`"pill`">Fails by severity:</span>")
    foreach ($sev in 'High','Medium','Low','Info') {
        $col = $sevColors[$sev]
        [void]$sb.AppendLine("<span class=`"pill`" style=`"border-color:$col;color:$col`"><b>$($failBySev[$sev])</b> $sev</span>")
    }
    [void]$sb.AppendLine('</div>')

    # Filter bar
    [void]$sb.AppendLine('<div class="filter">')
    [void]$sb.AppendLine('<input type="text" id="q" placeholder="Search CheckID, title, scope, evidence...">')
    [void]$sb.AppendLine('<label><input type="checkbox" class="fs" data-status="Pass" checked> Pass</label>')
    [void]$sb.AppendLine('<label><input type="checkbox" class="fs" data-status="Fail" checked> Fail</label>')
    [void]$sb.AppendLine('<label><input type="checkbox" class="fs" data-status="Manual" checked> Manual</label>')
    [void]$sb.AppendLine('<label><input type="checkbox" class="fs" data-status="NoAccess" checked> NoAccess</label>')
    [void]$sb.AppendLine('<label><input type="checkbox" class="fs" data-status="NotApplicable" checked> NotApplicable</label>')
    [void]$sb.AppendLine('<label><input type="checkbox" class="fs" data-status="Error" checked> Error</label>')
    [void]$sb.AppendLine('<select id="sev"><option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select>')
    [void]$sb.AppendLine('</div>')

    # Results grouped by section then sorted by CheckID
    $sections = $Results | Group-Object Section | Sort-Object Name
    foreach ($grp in $sections) {
        $name = $grp.Name
        $rows = $grp.Group | Sort-Object CheckID, ScopeName
        $passCount = @($rows | Where-Object Status -eq 'Pass').Count
        $failCount = @($rows | Where-Object Status -eq 'Fail').Count
        [void]$sb.AppendLine("<details class=`"section`" open><summary>$(_HtmlEncode $name) &nbsp;<span style=`"color:#6b7280;font-weight:400;font-size:12px;`">($($rows.Count) results . $passCount Pass . $failCount Fail)</span></summary>")
        [void]$sb.AppendLine('<table>')
        foreach ($r in $rows) {
            $sev = if ($r.Severity) { $r.Severity } else { 'Info' }
            $statusClass = $r.Status.ToLower()
            $title = _HtmlEncode $r.Title
            $checkId = _HtmlEncode $r.CheckID
            $scopeName = _HtmlEncode $r.ScopeName
            $actual = _HtmlEncode $r.ActualResult
            $bp = _HtmlEncode $r.BestPractice
            $rem = _HtmlEncode $r.Remediation
            $desc = _HtmlEncode $r.Description
            $req = _HtmlEncode $r.RequiresPerms
            $evi = _HtmlEncode (_Convert-EvidenceToText $r.Evidence)
            $exType = _HtmlEncode $r.ExceptionType
            $exMsg = _HtmlEncode $r.ExceptionMessage
            $sevLower = $sev.ToLower()
            $rowSearch = (_HtmlEncode "$($r.CheckID) $($r.Title) $($r.ScopeName) $($r.ActualResult) $evi").ToLower()
            [void]$sb.AppendLine("<tr class=`"row`" data-status=`"$($r.Status)`" data-sev=`"$sev`" data-search=`"$rowSearch`">")
            [void]$sb.AppendLine("<td class=`"id`">$checkId</td>")
            [void]$sb.AppendLine("<td class=`"title`"><div><b>$title</b></div>")
            [void]$sb.AppendLine("<div style=`"color:#6b7280;font-size:12px;margin-top:2px`">Scope: $scopeName</div>")
            [void]$sb.AppendLine("<details class=`"row-detail`"><summary>Details</summary>")
            [void]$sb.AppendLine('<div class="kvgrid">')
            [void]$sb.AppendLine("<div class=`"k`">Description</div><div>$desc</div>")
            [void]$sb.AppendLine("<div class=`"k`">Best practice</div><div>$bp</div>")
            [void]$sb.AppendLine("<div class=`"k`">Actual result</div><div>$actual</div>")
            [void]$sb.AppendLine("<div class=`"k`">Remediation</div><div>$rem</div>")
            [void]$sb.AppendLine("<div class=`"k`">Permissions</div><div>$req</div>")
            if ($exType) { [void]$sb.AppendLine("<div class=`"k`">Exception</div><div>$exType : $exMsg</div>") }
            [void]$sb.AppendLine('</div>')
            if ($evi) { [void]$sb.AppendLine("<pre class=`"evidence`">$evi</pre>") }
            [void]$sb.AppendLine('</details></td>')
            [void]$sb.AppendLine("<td><span class=`"badge $statusClass`">$($r.Status)</span></td>")
            [void]$sb.AppendLine("<td><span class=`"sev $sevLower`">$sev</span></td>")
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</table></details>')
    }

    [void]$sb.AppendLine('</div>') # /container

    # Footer
    [void]$sb.AppendLine('<footer>')
    [void]$sb.AppendLine("Generated by $($script:ProjectName) (Invoke-AzBench.ps1) v$($script:ScriptVersion) anchored to CIS Microsoft Azure Foundations Benchmark v$($script:CISVersion).<br>")
    [void]$sb.AppendLine('Self-contained HTML -- no external CDN/JS/CSS required. Status definitions: <span class="badge pass">Pass</span> compliant . <span class="badge fail">Fail</span> non-compliant . <span class="badge manual">Manual</span> requires human judgement . <span class="badge noaccess">NoAccess</span> insufficient permissions . <span class="badge notapplicable">NotApplicable</span> resource type absent . <span class="badge error">Error</span> unexpected exception.')
    [void]$sb.AppendLine('</footer>')

    # JS filter
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine(@'
(function() {
  const q = document.getElementById('q');
  const sev = document.getElementById('sev');
  const checks = Array.from(document.querySelectorAll('.fs'));
  const rows = Array.from(document.querySelectorAll('tr.row'));
  function apply() {
    const text = (q.value || '').toLowerCase();
    const allowed = new Set(checks.filter(c => c.checked).map(c => c.dataset.status));
    const sevFilter = sev.value;
    rows.forEach(r => {
      const okStatus = allowed.has(r.dataset.status);
      const okSev = !sevFilter || r.dataset.sev === sevFilter;
      const okText = !text || (r.dataset.search || '').indexOf(text) !== -1;
      r.classList.toggle('hidden', !(okStatus && okSev && okText));
    });
  }
  q.addEventListener('input', apply);
  sev.addEventListener('change', apply);
  checks.forEach(c => c.addEventListener('change', apply));
})();
'@)
    [void]$sb.AppendLine('</script></body></html>')

    $sb.ToString() | Out-File -FilePath $Path -Encoding utf8
}

# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
$exitCode = 0
try {
    Write-Step "$($script:ProjectName) v$($script:ScriptVersion) -- CIS Microsoft Azure Foundations Benchmark v$($script:CISVersion)" 'Step'

    # Cloud Shell: auto-detect unless the caller is driving auth another way (SP params).
    if (-not $CloudShell -and -not ($SpAppId -and $SpTenantId -and $SpSecret) -and (Test-IsCloudShell)) {
        Write-Step 'Azure Cloud Shell detected; enabling -CloudShell mode automatically.' 'Info'
        $CloudShell = $true
    }
    if ($CloudShell) {
        Initialize-CloudShellEnvironment
        # The bootstrap has installed/aligned modules and established both contexts,
        # so downstream steps should reuse them rather than install or reconnect.
        $SkipModuleInstall    = $true
        $AlreadyAuthenticated = $true
    }

    Ensure-Modules
    Initialize-AuditAzContext
    Initialize-AuditGraphContext

    # Permission preflight: verify entitlements before building inventory or running checks.
    $preflight = Invoke-PermissionPreflight
    $proceed   = $true
    if ($PreflightOnly) {
        Write-Step 'PreflightOnly set: no audit performed.' 'Info'
        $proceed = $false
        if ($preflight.HasGaps) { $exitCode = 2 }
    }
    elseif ($preflight.HasGaps) {
        $spAuth = ($SpAppId -and $SpTenantId -and $SpSecret)
        if ($StopOnMissingPermissions) {
            Write-Step ("Aborting before the audit: {0} required/recommended permission(s) missing and -StopOnMissingPermissions was set." -f $preflight.MissingCount) 'Err'
            $proceed  = $false
            $exitCode = 2
        }
        elseif ([Environment]::UserInteractive -and -not $CloudShell -and -not $spAuth) {
            $answer = Read-Host 'Permission gaps found. Continue the audit anyway? [y/N]'
            if ($answer -notmatch '^\s*(y|yes)\s*$') {
                Write-Step 'Stopped at user request due to missing permissions.' 'Warn'
                $proceed  = $false
                $exitCode = 2
            }
        }
        else {
            Write-Step 'Continuing despite permission gaps; missing controls will report NoAccess. Use -StopOnMissingPermissions to hard-stop, or -SkipGraph to intentionally drop Graph checks.' 'Warn'
        }
    }

    if ($proceed) {
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        Write-Step "Outputs will be written to: $OutputPath" 'Info'

        Build-Inventory
        Invoke-AllChecks

        Export-JsonReport       -Path (Join-Path $OutputPath 'findings.json')    -Results $script:Results -Inventory $script:Inventory
        Export-InventoryJson    -Path (Join-Path $OutputPath 'inventory.json')   -Inventory $script:Inventory
        Export-CsvReport        -Path (Join-Path $OutputPath 'findings.csv')     -Results $script:Results
        Export-HtmlReport       -Path (Join-Path $OutputPath 'report.html')      -Results $script:Results -Inventory $script:Inventory

        Write-Step "Report:        $(Join-Path $OutputPath 'report.html')"    'Ok'
        Write-Step "CSV:           $(Join-Path $OutputPath 'findings.csv')"   'Ok'
        Write-Step "JSON findings: $(Join-Path $OutputPath 'findings.json')"  'Ok'
        Write-Step "JSON inventory:$(Join-Path $OutputPath 'inventory.json')" 'Ok'

        $totals = @{}
        foreach ($s in 'Pass','Fail','Manual','NoAccess','NotApplicable','Error') {
            $totals[$s] = @($script:Results | Where-Object Status -eq $s).Count
        }
        Write-Host ""
        Write-Step ("Summary: Pass=$($totals.Pass) Fail=$($totals.Fail) Manual=$($totals.Manual) NoAccess=$($totals.NoAccess) NotApplicable=$($totals.NotApplicable) Error=$($totals.Error)") 'Step'
    }
} catch {
    Write-Step ("Fatal error: {0}" -f $_.Exception.Message) 'Err'
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    $exitCode = 1
} finally {
    # Only tear down contexts this script established. When we reused a caller-provided
    # context (-AlreadyAuthenticated or Cloud Shell), leave their session intact.
    if (-not $AlreadyAuthenticated) {
        try { Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null } catch {}
        try { Disconnect-MgGraph   -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}
exit $exitCode










