# AzBench

**Single-file Azure CIS benchmark auditor.** One PowerShell script (`Invoke-AzBench.ps1`) that audits an Azure tenant against the **CIS Microsoft Azure Foundations Benchmark v2.1.0** plus governance extras (PIM standing assignments, stale service-principal credentials, classic resources, resource locks, Defender Secure Score, subscription Owner counts, diagnostic-settings sweep). ~130 checks across Sections 1-10 of the benchmark (127 automated/evidence CIS controls plus 6 governance extras). The [coverage matrix](CIS_v2.1_Coverage_Matrix.md) lists every control including manual-only ones.

Read-only. No tenant changes are ever attempted.

> **Not affiliated with Microsoft or the Center for Internet Security.** AzBench is an independent community project anchored to public CIS guidance. "Azure" is a trademark of Microsoft; "CIS Microsoft Azure Foundations Benchmark" is a trademark of CIS.

## What ships in this kit

| File                              | Purpose                                                                  |
|-----------------------------------|--------------------------------------------------------------------------|
| `Invoke-AzBench.ps1`        | The auditor. One self-contained file, ~4,000 lines. Does everything.     |
| `Test-ScriptSyntax.ps1`           | Parse-only diagnostic. Run when "the file won't even start" errors.       |
| `CIS_v2.1_Coverage_Matrix.md`     | Every CIS control listed with automation status (A/P/M) and cmdlet used. |
| `README.md`                       | This file.                                                               |
| `LICENSE`                         | MIT license.                                                             |

The auditor is a single standalone script -- no launcher, no helper modules to ship
alongside it. Everything (module bootstrap, all three auth flows, the Cloud Shell
token bridge, checks, and report generation) lives in `Invoke-AzBench.ps1`.

## What the audit produces

In `<OutputPath>/` (defaults to a timestamped folder in the current directory):

| File             | Purpose                                                                          |
|------------------|----------------------------------------------------------------------------------|
| `report.html`    | Self-contained interactive report. No external CDN/JS/CSS - opens offline.       |
| `findings.csv`   | One row per check x scope. Excel-friendly. Pivots cleanly by Section / Severity. |
| `findings.json`  | Structured findings plus metadata (tenant, caller, runtime).                     |
| `inventory.json` | Slim resource inventory captured via Azure Resource Graph.                       |

Every check resolves to exactly one Status:

| Status          | Meaning                                                                  |
|-----------------|--------------------------------------------------------------------------|
| `Pass`          | Compliant.                                                               |
| `Fail`          | Non-compliant.                                                           |
| `Manual`        | Requires human judgement; evidence captured.                             |
| `NoAccess`      | Caller lacks the required role/scope. Informational, not red.            |
| `NotApplicable` | Resource type absent or scope disabled.                                  |
| `Error`         | Unexpected exception; investigate.                                       |

---

## Pick your auth flow

The script supports three. **Service Principal is what we proved works in restrictive environments** (Conditional Access blocking interactive flows, locked-down endpoints, etc.) and is what we recommend for production use.

### Flow A: Interactive user (your own workstation, no Conditional Access friction)

```powershell
.\Invoke-AzBench.ps1
```

The script handles browser-based sign-in for both Az and Microsoft Graph, installs missing modules to `CurrentUser` scope on first run, and consents to the required Graph delegated scopes.

### Flow B: Service Principal (recommended for production / restrictive environments)

This is the only flow we've seen survive Conditional Access policies that require compliant devices, regardless of where you launch from.

**One-time setup with a tenant admin:**

1. Create an app registration. Note the **Application (client) ID** and **Tenant ID**.
2. Add a **client secret** under Certificates & secrets. Copy the value immediately.
3. In API permissions, add as **Application permissions** (not Delegated):
   - `Directory.Read.All`
   - `Policy.Read.All`
   - `RoleManagement.Read.Directory`
   - `Application.Read.All`
   - `AuditLog.Read.All`
   - `UserAuthenticationMethod.Read.All`
   - `Group.Read.All`
4. Click **Grant admin consent for <tenant>** (requires Global Admin or Privileged Role Admin).
5. Assign Azure RBAC at the **Tenant Root Management Group** (requires User Access Administrator at that scope):
   - **Reader**
   - **Security Reader**

**Optional add-ons** that unlock specific checks:
- **Key Vault Reader** + **Key Vault Crypto Officer** + **Key Vault Secrets User** at any KV scope -> data-plane checks (CIS-8.1-8.4, 8.8).
- **Storage Blob Data Reader** -> CIS-5.1.3 (activity log container ACL).
- **Az.PostgreSql module installed** on the runner -> CIS-4.3.x PostgreSQL parameter checks. (Cloud Shell does not ship it; `Install-Module Az.PostgreSql -Scope CurrentUser`.)

**Run it (preferred - script handles both Az and Graph SP auth internally):**

```powershell
$tenantId = '<guid>'
$appId    = '<guid>'
$secret   = Read-Host 'Client secret' -AsSecureString

.\Invoke-AzBench.ps1 `
    -SpAppId    $appId `
    -SpTenantId $tenantId `
    -SpSecret   $secret
```

That single invocation calls `Connect-AzAccount -ServicePrincipal` and `Connect-MgGraph -ClientSecretCredential` itself, inside its own scope - the most reliable path because both auth contexts are established in the same scope the per-check cmdlets run in.

**Alternate (pre-authenticate outside the script):**

```powershell
$cred = New-Object System.Management.Automation.PSCredential($appId, $secret)
Connect-AzAccount -ServicePrincipal -TenantId $tenantId -Credential $cred
Connect-MgGraph   -TenantId $tenantId -ClientSecretCredential $cred -NoWelcome

.\Invoke-AzBench.ps1 -SkipModuleInstall -AlreadyAuthenticated
```

Either path runs in ~5-30 minutes depending on tenant size. No prompts, no device codes.

**Rotate the secret** the moment you're done. Treat any secret that has been pasted into a console or saved anywhere as tainted.

### Flow C: Azure Cloud Shell (`-CloudShell`)

Cloud Shell pre-installs `Az.*` and `Microsoft.Graph.Authentication` but not the full Graph submodule set, and version mismatches cause "assembly already loaded" errors. The `-CloudShell` mode handles all of that inside the one script -- there is no separate launcher:

1. Upload `Invoke-AzBench.ps1` via Cloud Shell's upload icon (or clone the repo).
2. Run it:

```powershell
./Invoke-AzBench.ps1 -CloudShell
```

`-CloudShell` reuses the existing Cloud Shell Az context (falling back to `Connect-AzAccount -Identity`), installs/imports the six Graph submodules **pinned to Cloud Shell's already-loaded `Microsoft.Graph.Authentication` version**, and bridges the Az access token to Microsoft Graph with `Get-AzAccessToken` + `Connect-MgGraph -AccessToken` -- no device code, no Conditional Access prompt.

Cloud Shell is **auto-detected**, so plain `./Invoke-AzBench.ps1` does the same thing; pass `-CloudShell` to force it. All other parameters work as normal:

```powershell
./Invoke-AzBench.ps1 -CloudShell -ChecksFilter '^CIS-3\.'
```

**Cloud Shell caveat:** if your tenant's Conditional Access policy requires a compliant device, Cloud Shell sign-in itself will fail because Cloud Shell isn't a managed device. In that case, use Flow A (Service Principal) instead -- SPs aren't subject to user CA policies.

---

## Parameters

| Parameter                | Type     | Default | Purpose                                                                                       |
|--------------------------|----------|---------|-----------------------------------------------------------------------------------------------|
| `-OutputPath`            | string   | `./AzureCISAudit_<timestamp>` | Folder for `report.html`, `findings.csv`, `findings.json`, `inventory.json`.   |
| `-TenantId`              | string   | (none)  | Entra tenant GUID. Required for multi-tenant accounts.                                        |
| `-SubscriptionIds`       | string[] | (all)   | Allow-list of subscription GUIDs to audit.                                                    |
| `-UseDeviceCode`         | switch   | off     | Force device-code auth (when interactive browser is blocked).                                  |
| `-SkipModuleInstall`     | switch   | off     | Don't try to `Install-Module`. Modules must already be present.                                |
| `-ChecksFilter`          | string   | (all)   | Regex over CheckID. `^CIS-3\.` runs just Storage; `^EXT-` runs just governance extras.        |
| `-MaxParallelism`        | int      | 8       | Per-sub parallelism cap (PS 7+ only; PS 5.1 runs serial).                                     |
| `-IncludeExtras`         | bool     | `$true` | Run non-CIS governance extras (PIM, stale SP creds, classic resources, locks, etc.).          |
| `-AlreadyAuthenticated`  | switch   | off     | Reuse existing Az + Graph contexts instead of calling `Connect-AzAccount` / `Connect-MgGraph`. |
| `-SkipGraph`             | switch   | off     | Skip every Microsoft Graph operation. Drops Section 1 + EXT-002/003. ~80% coverage remains.   |
| `-CloudShell`            | switch   | auto    | Azure Cloud Shell one-shot mode: reuse the Az context, version-align the Graph submodules, and bridge the Az token to Graph. Auto-detected in Cloud Shell; pass to force. |
| `-StopOnMissingPermissions` | switch | off   | Abort before inventory/checks (exit code 2) if the permission preflight finds any required or recommended gap. On an interactive host you're also prompted to continue/stop. |
| `-PreflightOnly`         | switch   | off     | Run auth + the permission preflight, print the report, then exit (0 = all present, 2 = gaps). No inventory, no checks, no output files. |
| `-SpAppId`               | string   | (none)  | Service Principal application (client) ID. Set with `-SpTenantId` and `-SpSecret` for native SP auth -- the script calls `Connect-AzAccount -ServicePrincipal` and `Connect-MgGraph -ClientSecretCredential` itself. |
| `-SpTenantId`            | string   | (none)  | Entra tenant ID for the SP auth path.                                                          |
| `-SpSecret`              | SecureString | (none) | SP client secret as a SecureString (`Read-Host '...' -AsSecureString`).                       |

## Permissions and what you lose without each

| Role                                                              | What it unlocks                                                                 |
|-------------------------------------------------------------------|---------------------------------------------------------------------------------|
| **Reader** at MG root (or every sub)                              | Almost all resource-plane checks (Sections 3-10).                                |
| **Security Reader** at MG root (or every sub)                     | Section 2 Defender for Cloud checks; Secure Score; security contacts.            |
| **Application permissions on Graph** (with admin consent)         | Section 1 IAM checks (CA policies, MFA, auth methods, directory settings).       |
| **Key Vault Reader + Crypto Officer + Secrets User** (data plane) | CIS-8.1-8.4 (key/secret expiration) and 8.8 (rotation policy).                    |
| **Storage Blob Data Reader**                                      | CIS-5.1.3 (activity log container ACL).                                          |

Without these, the script doesn't crash -- it produces clean `NoAccess` rows so reviewers can see exactly which controls were unevaluated and why.

## Permission preflight

Immediately after authenticating -- **before** it builds any inventory or runs a single check -- AzBench probes the exact roles and Graph scopes it needs and prints a go/no-go table:

```
  Permission                         Category     Plane  Status
  ----------------------------------------------------------------------
  Azure subscriptions visible        Required     Azure  Granted
  Azure Reader (resource read)       Required     Azure  Granted
  Azure Resource Graph               Required     Azure  Granted
  Security Reader (Defender)         Recommended  Azure  Missing
  Directory.Read.All                 Recommended  Graph  Granted
  Policy.Read.All                    Recommended  Graph  Granted
  RoleManagement.Read.Directory      Recommended  Graph  Granted
  Application.Read.All               Recommended  Graph  Granted
  Group.Read.All                     Recommended  Graph  Granted
  AuditLog.Read.All                  Recommended  Graph  Granted
  UserAuthenticationMethod.Read.All  Recommended  Graph  Granted
```

Each row is a **functional probe** (an actual cheap read call), not a guess from the token's claimed scopes, so it reflects what the principal can really do. Statuses: `Granted`, `Missing` (a real 401/403/RequestDenied), `Unverified` (the probe failed for a non-permission reason like throttling or licensing -- not counted as a gap), and `Skipped` (e.g. Graph when `-SkipGraph` is set).

What happens when gaps are found:

| Situation | Behavior |
|-----------|----------|
| Default (no switch), interactive host | Prints the table, then prompts **"Continue the audit anyway? [y/N]"**. |
| Default, non-interactive (SP / Cloud Shell / CI) | Prints the table, warns, and continues -- missing controls become `NoAccess` rows. |
| `-StopOnMissingPermissions` | **Aborts before the audit** and exits `2`. Nothing is written. |
| `-PreflightOnly` | Runs only the preflight, prints the table, exits `0` (all present) or `2` (gaps). No audit, no output files. |

Use `-PreflightOnly` as a fast entitlement check in CI/CD or before kicking off a long run:

```powershell
.\Invoke-AzBench.ps1 -SpAppId $appId -SpTenantId $tenantId -SpSecret $secret -PreflightOnly
if ($LASTEXITCODE -ne 0) { throw 'Service principal is missing required permissions.' }
```

---

## Output explained

`report.html` is the consumable view. It's a single self-contained file with:
- **Summary tiles** at the top: counts of Pass / Fail / Manual / NoAccess / NotApplicable / Error.
- **Severity bar**: Fails broken out into High / Medium / Low / Info.
- **Sticky filter bar**: text search + status checkboxes + severity dropdown + section dropdown. All filtering is client-side, no network access needed.
- **Collapsible sections**: one per CIS section plus the Extras. Each section is collapsed by default; click to expand.
- **Collapsible row details**: click a row to see Description, Best Practice, Actual Result, Remediation, Permissions required, and JSON evidence.
- **Coverage banner** at top: warns when the auditor lacked Reader / Security Reader / Graph access on any subscription. Many `NoAccess` rows are explained by these gaps, not by misconfiguration.

`findings.csv` is identical content as a flat one-row-per-check table. Best for pivoting in Excel.

`findings.json` is the same data structurally with full metadata (tenant, caller, runtime, exception types). Best for downstream tooling / re-analysis.

`inventory.json` is the slim Resource Graph snapshot taken at the start of the run. Each resource has id / name / type / location / subscriptionId / resourceGroup. Useful for separate inventory views or for re-running specific checks without rebuilding the cache.

---

## Performance notes

- Inventory is built **once** via `Search-AzGraph` at the start, then every per-resource check reads from cache. Much faster than per-subscription `Get-Az*` loops on large tenants.
- PowerShell 7+ uses `ForEach-Object -Parallel` per subscription (capped by `-MaxParallelism`). PowerShell 5.1 runs serial.
- ARM throttling (429) is handled transparently with exponential backoff inside the check wrapper.
- Typical runtime: ~5-10 minutes for a tenant with 10-30 subscriptions and a few hundred resources. A 24-subscription run with ~3,700 checks completed in ~30 minutes in our reference environment.

---

## Troubleshooting

### Parse-time errors on PowerShell 5.1 ("missing ) in method call", "the < operator is reserved", etc.)
The script ships as UTF-8-with-BOM with CRLF line endings, which PS 5.1 requires. If your environment strips the BOM, re-add it (or use PowerShell 7). Run `Test-ScriptSyntax.ps1` to confirm:
```powershell
.\Test-ScriptSyntax.ps1
```
It reports parse errors with line and column numbers, plus confirms BOM and line-ending state.

### Conditional Access blocks Cloud Shell sign-in
Cloud Shell is not a compliant device. Two options:
1. Switch to **Flow A (Service Principal)**. SPs aren't subject to user CA policies. This is the proven path.
2. Ask security to add Cloud Shell's IP ranges as a Trusted Location in CA, or add an exclusion for your account on cloud apps "Microsoft Azure Management" + "Microsoft Graph". Less common.

### Device-code prompt appears mid-run
This means a cmdlet triggered token refresh and your CA policy doesn't accept the resulting auth. Use `-SkipGraph` to bypass Graph operations, or switch to SP auth.

### Assembly conflicts when installing `Microsoft.Graph.*` modules
Happens in Cloud Shell when `Microsoft.Graph.Authentication` is already loaded at one version and you try to install siblings at another. Run with `-CloudShell` (or just let it auto-detect): it pins the sibling submodules to the in-memory `Authentication` version instead of the script's minimum versions.

### "Get-MgDirectorySetting is not recognized"
Some directory-setting checks (CIS-1.10, 1.14, 1.18, 1.19) rely on a cmdlet that's been renamed/moved between Graph SDK major versions. They produce `Error` rows when unavailable. The Description and Best Practice fields still convey the intent so the row is reviewable by hand.

### EDR blocks the script on a managed endpoint
The script's behavior (enumerating role assignments, listing service principal credentials, calling Defender APIs, installing modules from PSGallery) overlaps heavily with attacker reconnaissance patterns. Modern EDRs (CrowdStrike, Defender for Endpoint) routinely block or quarantine it. Options in order of preference:
1. Run via **Flow A (SP)** from a development VM / personal machine without that EDR.
2. Get an EDR allowlist for the file hash with an expiry.
3. Switch to Microsoft Defender for Cloud's built-in CIS Benchmark dashboard for a baseline (Portal -> Defender for Cloud -> Regulatory compliance). Less complete but no script execution required.

### "Az.PostgreSql was not loaded"
Cloud Shell doesn't ship it. The CIS-4.3.x PostgreSQL parameter checks will return `Error` rows. Install separately:
```powershell
Install-Module Az.PostgreSql -Scope CurrentUser -Force
```

### Errors in CIS-2.1.16/17/18 + 2.2.2 ("Unable to deserialize the response")
The `Get-AzSecurityContact` cmdlet's response shape changed in recent Az.Security versions. The script's parser hasn't been updated for the new structure. Verify Defender for Cloud security contact configuration manually in the portal for now.

---

## Versioning and provenance

- Script version constant: `$script:ScriptVersion = '1.0.0'` (top of the script).
- CIS version constant: `$script:CISVersion = '2.1.0'`. Surfaced in the HTML header so reviewers know which benchmark the report aligns to.
- `CIS_v2.1_Coverage_Matrix.md` lists every CIS control with its automation status (A = fully automated, P = evidence captured + human judgement required, M = manual-only skeleton row).

## Getting help

The script ships full PowerShell comment-based help. From a shell with the file present:

```powershell
Get-Help .\Invoke-AzBench.ps1 -Full        # every parameter + examples
Get-Help .\Invoke-AzBench.ps1 -Examples     # just the usage examples
Get-Help .\Invoke-AzBench.ps1 -Parameter CloudShell
```

## License & attribution

Released under the [MIT License](LICENSE).

Independent script anchored to public CIS guidance. No affiliation with the Center for Internet Security. CIS Microsoft Azure Foundations Benchmark is a trademark of CIS.

> **Read-only by design.** The auditor only calls `Get-*` / `Search-*` / read cmdlets and never writes to your tenant. Review the source before running it in a sensitive environment -- that's the point of shipping it as a single readable file.
