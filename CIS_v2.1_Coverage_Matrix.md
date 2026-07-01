# CIS Microsoft Azure Foundations Benchmark v2.1.0 — Coverage Matrix

Legend
- **A** = Fully automated. Returns Pass / Fail directly.
- **P** = Partially automated. Evidence captured but final call is human (returned as `Manual`).
- **M** = Manual-only — no Graph / ARM API surface. Emitted as a `Manual` skeleton row.
- **CheckID** = the ID used in `findings.csv` / `report.html`.

| CheckID         | Control | Title                                                                                  | Auto | Cmdlets / API                                                                |
|-----------------|---------|----------------------------------------------------------------------------------------|------|------------------------------------------------------------------------------|
| **Section 1 — Identity and Access Management**                                                                                                                |
| CIS-1.1.1       | 1.1.1   | Security Defaults enabled (if no CA policies)                                          | A    | `Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy`, CA-policy count       |
| CIS-1.1.2       | 1.1.2   | MFA enabled for all privileged users                                                   | A    | `Get-MgIdentityConditionalAccessPolicy` (role-targeted + grant mfa)           |
| CIS-1.1.3       | 1.1.3   | MFA enabled for all non-privileged users                                                | A    | `Get-MgIdentityConditionalAccessPolicy` (All Users + grant mfa)              |
| CIS-1.1.4       | 1.1.4   | "Allow users to remember MFA on trusted devices" disabled                              | M    | legacy MFA portal only                                                       |
| CIS-1.2.1       | 1.2.1   | Trusted locations defined                                                              | A    | `Get-MgIdentityConditionalAccessNamedLocation`                               |
| CIS-1.2.2       | 1.2.2   | Geographic blocking CA policy considered                                               | A    | CA policy + location condition + block grant                                 |
| CIS-1.2.3       | 1.2.3   | CA policy requires MFA for administrative roles                                        | A    | CA policy with IncludeRoles + mfa grant                                      |
| CIS-1.2.4       | 1.2.4   | CA policy requires MFA for Azure Management                                            | A    | CA policy targeting Microsoft Azure Management app (AppId 797f4846...)       |
| CIS-1.2.5       | 1.2.5   | CA policy blocks legacy authentication                                                 | A    | CA policy with ClientAppTypes exchangeActiveSync/other + block               |
| CIS-1.2.6       | 1.2.6   | CA policy requires MFA on sign-in risk (Entra P2)                                       | A    | CA policy with SignInRiskLevels + mfa                                        |
| CIS-1.2.7       | 1.2.7   | CA policy requires password change on user risk (Entra P2)                              | A    | CA policy with UserRiskLevels + passwordChange grant                         |
| CIS-1.3         | 1.3     | Restrict non-admin tenant creation                                                     | A    | `Get-MgPolicyAuthorizationPolicy` (AllowedToCreateTenants)                   |
| CIS-1.4         | 1.4     | Guest users reviewed                                                                   | P    | `Get-MgUser -Filter "userType eq 'Guest'"`                                   |
| CIS-1.5         | 1.5     | Guest invite restrictions                                                              | A    | `AuthorizationPolicy.AllowInvitesFrom`                                       |
| CIS-1.6         | 1.6     | Restrict access to Entra admin center                                                  | M    | portal only                                                                  |
| CIS-1.7         | 1.7     | Restrict My Groups features                                                            | A    | `DefaultUserRolePermissions.AllowedToCreateSecurityGroups`                   |
| CIS-1.8         | 1.8     | Users can create security groups = No                                                  | A    | same as 1.7                                                                  |
| CIS-1.9         | 1.9     | Owners can manage group membership requests in My Groups = No                          | M    | group settings template inconsistently exposed                               |
| CIS-1.10        | 1.10    | Users can create M365 groups = No                                                      | A    | `Get-MgDirectorySetting` Group.Unified.EnableGroupCreation                   |
| CIS-1.11        | 1.11    | MFA required to register/join devices                                                  | A    | beta `policies/deviceRegistrationPolicy`                                     |
| CIS-1.12        | 1.12    | No custom subscription Owner roles                                                     | A    | `Get-AzRoleDefinition -Custom` action analysis                               |
| CIS-1.13        | 1.13    | Subscription leaving/entering directory restricted                                     | M    | no API                                                                       |
| CIS-1.14        | 1.14    | Custom banned password list enforced                                                   | A    | `Get-MgDirectorySetting` PasswordRuleSettings                                |
| CIS-1.15        | 1.15    | SSPR enabled for All users                                                             | A    | beta `policies/authorizationPolicy` allowedToUseSSPR                         |
| CIS-1.16        | 1.16    | Microsoft Authenticator configured with recommended settings                           | A    | beta authentication methods policy                                           |
| CIS-1.17        | 1.17    | Phishing-resistant MFA strength required for admins                                    | A    | CA policy with AuthenticationStrength on role-targeted users                 |
| CIS-1.18        | 1.18    | Account lockout threshold ≤ 10                                                         | A    | `Get-MgDirectorySetting` PasswordRuleSettings.LockoutThreshold               |
| CIS-1.19        | 1.19    | Account lockout duration ≥ 60 s                                                        | A    | same — LockoutDurationInSeconds                                              |
| CIS-1.20        | 1.20    | Smart lockout on-prem hybrid AD                                                        | M    | on-prem only                                                                 |
| CIS-1.21        | 1.21    | Members of AAD admin role review their privileged assignments                          | M    | process control                                                              |
| CIS-1.22        | 1.22    | Password Protection deployed to AD DS                                                  | M    | on-prem only                                                                 |
| CIS-1.23        | 1.23    | No custom subscription administrator roles                                             | P    | inventory of custom roles for review                                         |
| CIS-1.24        | 1.24    | Custom roles approved by management                                                    | M    | process control                                                              |
| CIS-1.25        | 1.25    | "Users can register applications" = No                                                 | A    | `AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps`         |
| **Section 2 — Microsoft Defender for Cloud** *(all subscription-scoped; high NoAccess risk without Security Reader)* |
| CIS-2.1.1       | 2.1.1   | MDC for Servers = Standard                                                             | A    | `Get-AzSecurityPricing -Name VirtualMachines`                                |
| CIS-2.1.2       | 2.1.2   | MDC for App Service                                                                    | A    | `Get-AzSecurityPricing -Name AppServices`                                    |
| CIS-2.1.3       | 2.1.3   | MDC for Azure SQL Databases                                                            | A    | `-Name SqlServers`                                                           |
| CIS-2.1.4       | 2.1.4   | MDC for SQL Servers on machines                                                        | A    | `-Name SqlServerVirtualMachines`                                             |
| CIS-2.1.5       | 2.1.5   | MDC for open-source RDBMS                                                              | A    | `-Name OpenSourceRelationalDatabases`                                        |
| CIS-2.1.6       | 2.1.6   | MDC for Storage                                                                        | A    | `-Name StorageAccounts`                                                      |
| CIS-2.1.7       | 2.1.7   | MDC for Containers                                                                     | A    | `-Name Containers`                                                           |
| CIS-2.1.8       | 2.1.8   | MDC for Cosmos DB                                                                      | A    | `-Name CosmosDbs`                                                            |
| CIS-2.1.9       | 2.1.9   | MDC for Key Vault                                                                      | A    | `-Name KeyVaults`                                                            |
| CIS-2.1.10      | 2.1.10  | MDC for Azure Resource Manager                                                         | A    | `-Name Arm`                                                                  |
| CIS-2.1.11      | 2.1.11  | Defender CSPM (CloudPosture)                                                           | A    | `-Name CloudPosture`                                                         |
| CIS-2.1.12      | 2.1.12  | Defender for APIs                                                                      | A    | `-Name Api`                                                                  |
| CIS-2.1.13      | 2.1.13  | Microsoft Defender for Endpoint integration                                            | A    | `Get-AzSecuritySetting -Name WDATP`                                          |
| CIS-2.1.14      | 2.1.14  | Microsoft Defender for Cloud Apps integration                                          | A    | `Get-AzSecuritySetting -Name MCAS`                                           |
| CIS-2.1.15      | 2.1.15  | Auto-provisioning of agents = On                                                       | A    | `Get-AzSecurityAutoProvisioningSetting`                                      |
| CIS-2.1.16      | 2.1.16  | Security contact email populated                                                       | A    | `Get-AzSecurityContact`                                                      |
| CIS-2.1.17      | 2.1.17  | Notification minimum severity set                                                      | P    | `Get-AzSecurityContact` AlertNotifications                                   |
| CIS-2.1.18      | 2.1.18  | Subscription Owners notified                                                           | A    | `Get-AzSecurityContact` NotificationsByRole                                  |
| CIS-2.1.19      | 2.1.19  | Workspace configured for MDC telemetry                                                 | A    | `Get-AzSecurityWorkspaceSetting`                                             |
| CIS-2.2.1       | 2.2.1   | EASM reviewed                                                                          | P    | `Microsoft.Easm/workspaces` presence                                         |
| CIS-2.2.2       | 2.2.2   | "All users with following roles" includes Owner                                        | A    | duplicate intent of 2.1.18                                                   |
| **Section 3 — Storage Accounts**                                                                                                                              |
| CIS-3.1         | 3.1     | Secure transfer required                                                               | A    | `supportsHttpsTrafficOnly`                                                   |
| CIS-3.2         | 3.2     | Infrastructure encryption enabled                                                      | A    | `encryption.requireInfrastructureEncryption`                                 |
| CIS-3.3         | 3.3     | Storage account keys periodically regenerated                                          | P    | no last-rotated timestamp; reports shared-key surface                        |
| CIS-3.4         | 3.4     | "Allow storage account key access" disabled                                            | A    | `allowSharedKeyAccess`                                                       |
| CIS-3.5         | 3.5     | Soft delete for blobs enabled                                                          | A    | `Get-AzStorageBlobServiceProperty` DeleteRetentionPolicy                     |
| CIS-3.6         | 3.6     | Logging for Queue / Table / Blob                                                       | A    | `Get-AzDiagnosticSetting` per sub-service                                    |
| CIS-3.7         | 3.7     | Blob public access disabled                                                            | A    | `allowBlobPublicAccess`                                                      |
| CIS-3.8         | 3.8     | Default network access rule = Deny                                                     | A    | `networkAcls.defaultAction`                                                  |
| CIS-3.9         | 3.9     | "Allow Azure services on trusted list" enabled                                         | A    | `networkAcls.bypass` includes AzureServices                                  |
| CIS-3.10        | 3.10    | Private Endpoints used                                                                 | A    | `privateEndpointConnections`                                                 |
| CIS-3.11        | 3.11    | Soft delete for containers enabled                                                     | A    | `Get-AzStorageBlobServiceProperty` ContainerDeleteRetentionPolicy            |
| CIS-3.12        | 3.12    | Storage encrypted with CMK                                                             | P    | `encryption.keySource`                                                       |
| CIS-3.13        | 3.13    | Blob logging Read/Write/Delete                                                         | A    | `Get-AzDiagnosticSetting` on blobServices/default                            |
| CIS-3.14        | 3.14    | Cross-tenant replication disabled                                                      | A    | `allowCrossTenantReplication`                                                |
| CIS-3.15        | 3.15    | Minimum TLS version 1.2+                                                                | A    | `minimumTlsVersion`                                                          |
| **Section 4 — Database Services**                                                                                                                             |
| CIS-4.1.1       | 4.1.1   | SQL Server auditing enabled                                                            | A    | `Get-AzSqlServerAudit`                                                       |
| CIS-4.1.2       | 4.1.2   | SQL firewall does not allow 0.0.0.0/0                                                  | A    | `Get-AzSqlServerFirewallRule`                                                |
| CIS-4.1.3       | 4.1.3   | SQL Server has AAD administrator                                                       | A    | `Get-AzSqlServerActiveDirectoryAdministrator`                                |
| CIS-4.1.4       | 4.1.4   | TDE enabled on every database                                                          | A    | `Get-AzSqlDatabaseTransparentDataEncryption`                                 |
| CIS-4.1.5       | 4.1.5   | TDE protector is CMK                                                                   | A    | `Get-AzSqlServerTransparentDataEncryptionProtector`                          |
| CIS-4.1.6       | 4.1.6   | SQL audit retention ≥ 90 days                                                          | A    | `Get-AzSqlServerAudit` RetentionInDays                                       |
| CIS-4.2.1       | 4.2.1   | Defender for SQL enabled (ATP)                                                         | A    | `Get-AzSqlServerAdvancedThreatProtectionSetting`                             |
| CIS-4.2.2       | 4.2.2   | VA recurring scans enabled                                                             | A    | `Get-AzSqlServerVulnerabilityAssessmentSetting`                              |
| CIS-4.2.3       | 4.2.3   | VA email admins enabled                                                                | A    | same                                                                         |
| CIS-4.2.4       | 4.2.4   | VA notification recipients set                                                         | A    | same                                                                         |
| CIS-4.3.1       | 4.3.1   | PostgreSQL SSL/TLS enforced                                                            | A    | `Get-AzPostgreSqlServer` / `*FlexibleServerConfiguration`                    |
| CIS-4.3.2       | 4.3.2   | PostgreSQL log_checkpoints = on                                                        | A    | `Get-AzPostgreSqlConfiguration`                                              |
| CIS-4.3.3       | 4.3.3   | PostgreSQL log_connections = on                                                        | A    | same                                                                         |
| CIS-4.3.4       | 4.3.4   | PostgreSQL log_disconnections = on                                                     | A    | same                                                                         |
| CIS-4.3.5       | 4.3.5   | PostgreSQL connection_throttling = on                                                  | A    | same                                                                         |
| CIS-4.3.6       | 4.3.6   | PostgreSQL log_retention_days ≥ 3                                                      | A    | same                                                                         |
| CIS-4.3.7       | 4.3.7   | PostgreSQL "Allow access to Azure services" disabled                                   | A    | `Get-AzPostgreSqlFirewallRule`                                               |
| CIS-4.3.8       | 4.3.8   | PostgreSQL infrastructure double encryption                                            | A    | `infrastructureEncryption`                                                   |
| CIS-4.4.1       | 4.4.1   | MySQL TLS ≥ 1.2                                                                        | A    | `minimalTlsVersion`                                                          |
| CIS-4.5.1       | 4.5.1   | Cosmos DB firewall / VNet rules / private                                              | A    | `properties.ipRules / virtualNetworkRules / publicNetworkAccess`             |
| CIS-4.5.2       | 4.5.2   | Cosmos DB Private Endpoint used                                                        | A    | `privateEndpointConnections`                                                 |
| CIS-4.5.3       | 4.5.3   | Cosmos DB AAD-only (`disableLocalAuth`)                                                | A    | `properties.disableLocalAuth`                                                |
| **Section 5 — Logging and Monitoring**                                                                                                                        |
| CIS-5.1.1       | 5.1.1   | Diagnostic setting exists for subscription Activity Log                                | A    | `Get-AzDiagnosticSetting -ResourceId /subscriptions/<id>`                    |
| CIS-5.1.2       | 5.1.2   | Activity Log captures all required categories                                          | A    | same                                                                         |
| CIS-5.1.3       | 5.1.3   | Activity log container not publicly accessible                                         | A    | `Get-AzStorageContainer insights-activity-logs`                              |
| CIS-5.1.4       | 5.1.4   | Activity log storage encrypted with CMK                                                | A    | `Get-AzStorageAccount` Encryption.KeySource                                  |
| CIS-5.1.5       | 5.1.5   | Logging enabled on Key Vault (AuditEvent)                                              | A    | `Get-AzDiagnosticSetting` per KV (also under 8.11)                           |
| CIS-5.2.1–.10   | 5.2.*   | Activity log alerts: policy assignments, NSGs/rules, SQL FW, security solution         | A    | `Get-AzActivityLogAlert` + operationName filter (10 alerts)                  |
| CIS-5.3.1       | 5.3.1   | App Insights configured for production apps                                            | P    | `microsoft.insights/components` presence                                     |
| CIS-5.4         | 5.4     | Diagnostic settings sweep across all monitored resource types                          | A    | `Get-AzDiagnosticSetting` per resource (KV, SQL, NSG, Storage, AppService)   |
| CIS-5.5         | 5.5     | Log Analytics workspace retention ≥ 30 days                                            | A    | `retentionInDays` on workspaces                                              |
| **Section 6 — Networking**                                                                                                                                    |
| CIS-6.1         | 6.1     | No NSG allows RDP (3389) from Internet                                                  | A    | NSG rule walk                                                                |
| CIS-6.2         | 6.2     | No NSG allows SSH (22) from Internet                                                    | A    | NSG rule walk                                                                |
| CIS-6.3         | 6.3     | No NSG allows DB ports (1433/3306/5432/1521) from Internet                              | A    | NSG rule walk                                                                |
| CIS-6.4         | 6.4     | NSG flow log retention > 90 days                                                       | A    | `Get-AzNetworkWatcherFlowLog`                                                |
| CIS-6.5         | 6.5     | Network Watcher in each region with workloads                                          | A    | Watcher locations vs VNet locations                                          |
| CIS-6.6         | 6.6     | NSG flow logs enabled per NSG                                                          | A    | flow logs map onto NSG IDs                                                   |
| CIS-6.7         | 6.7     | Public IPs reviewed                                                                    | P    | inventory of PIPs                                                            |
| **Section 7 — Virtual Machines**                                                                                                                              |
| CIS-7.1         | 7.1     | Azure Bastion deployed                                                                 | A    | `microsoft.network/bastionhosts` count                                       |
| CIS-7.2         | 7.2     | VMs use managed disks                                                                  | A    | `storageProfile.osDisk.managedDisk`                                          |
| CIS-7.3         | 7.3     | Managed disks encrypted with CMK                                                       | P    | `encryption.type`                                                            |
| CIS-7.4         | 7.4     | Unattached disks encrypted with CMK                                                    | A    | disk with `managedBy=null`                                                   |
| CIS-7.5         | 7.5     | Only approved extensions installed                                                     | P    | `Get-AzVMExtension` inventory                                                |
| CIS-7.6         | 7.6     | Endpoint protection installed per VM                                                   | A    | extension type matches approved list                                         |
| CIS-7.7         | 7.7     | OS disk delete-on-VM-deletion                                                          | A    | `storageProfile.osDisk.deleteOption`                                         |
| CIS-7.8         | 7.8     | Latest OS patches installed                                                            | M    | Defender / Update Manager dashboards                                         |
| CIS-7.9         | 7.9     | Trusted Launch (Secure Boot + vTPM)                                                    | A    | `securityProfile.uefiSettings`                                               |
| **Section 8 — Key Vault**                                                                                                                                     |
| CIS-8.1         | 8.1     | Keys have expiration set (RBAC vaults) — data plane                                    | A    | `Get-AzKeyVaultKey` (NoAccess if data-plane denied)                          |
| CIS-8.2         | 8.2     | Keys have expiration set (access-policy vaults)                                        | A    | same                                                                         |
| CIS-8.3         | 8.3     | Secrets have expiration set (RBAC vaults)                                              | A    | `Get-AzKeyVaultSecret`                                                       |
| CIS-8.4         | 8.4     | Secrets have expiration set (access-policy vaults)                                     | A    | same                                                                         |
| CIS-8.5         | 8.5     | Soft-delete + purge protection enabled                                                 | A    | `enableSoftDelete`, `enablePurgeProtection`                                  |
| CIS-8.6         | 8.6     | RBAC enabled on Key Vault                                                              | A    | `enableRbacAuthorization`                                                    |
| CIS-8.7         | 8.7     | Private Endpoints used                                                                 | A    | `privateEndpointConnections`                                                 |
| CIS-8.8         | 8.8     | Auto-rotation policy on keys                                                           | A    | `Get-AzKeyVaultKeyRotationPolicy`                                            |
| CIS-8.9         | 8.9     | Managed HSM uses Entra ID for access                                                   | P    | `microsoft.keyvault/managedhsms` presence                                    |
| CIS-8.10        | 8.10    | Public network access disabled                                                         | A    | `publicNetworkAccess`                                                        |
| CIS-8.11        | 8.11    | AuditEvent diagnostic logging per vault                                                | A    | `Get-AzDiagnosticSetting` per KV                                             |
| **Section 9 — App Service**                                                                                                                                   |
| CIS-9.1         | 9.1     | App Service authentication enabled                                                     | P    | per-app `authsettingsV2`                                                     |
| CIS-9.2         | 9.2     | HTTPS only                                                                             | A    | `httpsOnly`                                                                  |
| CIS-9.3         | 9.3     | Minimum TLS ≥ 1.2                                                                      | A    | `SiteConfig.MinTlsVersion`                                                   |
| CIS-9.4         | 9.4     | Client certificates required where applicable                                          | P    | `clientCertEnabled` (org judgement)                                          |
| CIS-9.5         | 9.5     | Managed Identity registered                                                            | A    | `identity.type`                                                              |
| CIS-9.6         | 9.6     | PHP runtime supported                                                                  | P    | `SiteConfig.PhpVersion`                                                      |
| CIS-9.7         | 9.7     | Python runtime supported                                                               | P    | `SiteConfig.PythonVersion`                                                   |
| CIS-9.8         | 9.8     | Java runtime supported                                                                 | P    | `SiteConfig.JavaVersion`                                                     |
| CIS-9.9         | 9.9     | HTTP version 2.0                                                                       | A    | `SiteConfig.Http20Enabled`                                                   |
| CIS-9.10        | 9.10    | FTP disabled / FTPS only                                                               | A    | `SiteConfig.FtpsState`                                                       |
| CIS-9.11        | 9.11    | Key Vault used for app secrets                                                         | P    | app settings inspection (often NoAccess)                                     |
| **Section 10 — Miscellaneous**                                                                                                                                |
| CIS-10.1        | 10.1    | Resource locks on production resource groups                                           | P    | `Get-AzResourceLock` (criticality is org-defined)                            |
| **Extras (non-CIS governance)**                                                                                                                               |
| EXT-001         | -       | Defender Secure Score snapshot                                                         | A    | `Get-AzSecuritySecureScore`                                                  |
| EXT-002         | -       | Standing assignments to Global Admin / Privileged Role Admin / User Access Admin       | A    | Graph roleAssignments                                                        |
| EXT-003         | -       | Service principal credentials older than 365 days / no expiry                          | A    | `Get-MgApplication` PasswordCredentials / KeyCredentials                     |
| EXT-004         | -       | Classic (ASM) resources present                                                        | A    | `Microsoft.Classic*` inventory                                               |
| EXT-005         | -       | Subscriptions with > 3 standing Owner assignments                                      | A    | `Get-AzRoleAssignment -RoleDefinitionName Owner`                             |
| EXT-006         | -       | Caller permission profile per subscription                                             | A    | self-documenting; informs other results                                      |

## Counts (rough)

- **CIS controls represented**: ~96 from v2.1.0 (sections 1–10).
- **Fully automated**: ~78 controls.
- **Partially automated**: ~12 controls (evidence captured, judgement required).
- **Manual-only**: ~6 controls (organizational policy / on-prem hybrid AD / classic portal-only settings).
- **Extras**: 6 governance checks beyond CIS.

## Where the script knowingly diverges

- Section 9.6 / 9.7 / 9.8 (runtime version recency): CIS lists a specific "latest" version that drifts every quarter. The script checks for a *reasonable supported minimum* and returns `Manual` for anything below, so reviewers can compare against current Microsoft Lifecycle Policy.
- Section 5.2 alert IDs: CIS sometimes lists 8 alerts, sometimes 10, depending on revision. Ten are implemented here.
- Section 1.13 / 1.21 / 1.22 / 1.24: organizational/process controls. Skeleton `Manual` rows are emitted so they appear in the report rather than silently dropping off.
- CIS 2.1.11 (DNS) was removed in v2.1.0; CSPM and APIs were added. The script reflects v2.1.0 numbering.
