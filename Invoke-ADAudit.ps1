<#
.SYNOPSIS
    Read-only Active Directory health and security audit, exported as a single HTML report.

.DESCRIPTION
    Invoke-ADAudit reads your Active Directory (it never writes anything) and produces a
    self-contained HTML report: a score, findings sorted by severity with the accounts
    concerned and how to fix them, the password policy, domain controllers and members
    of privileged groups.

    Privileged groups are found by their well-known SID, so the audit works on French,
    German or any other language version of Windows Server.

    Run it from a domain-joined machine with the ActiveDirectory module (RSAT).
    A standard domain user account is enough for almost every check.

.PARAMETER OutputPath
    Folder or .html file for the report. Default: current folder.

.PARAMETER InactiveDays
    An enabled account that has not logged on for this many days is "inactive". Default: 90.

.PARAMETER ExpiringDays
    Warn about passwords expiring within this many days. Default: 14.

.PARAMETER Server
    Domain controller to query. Default: the one chosen by Windows.

.PARAMETER Language
    Report language: en or fr. Default: the language of Windows.

.PARAMETER Csv
    Also export every finding with its accounts to a CSV file next to the report.

.PARAMETER Open
    Open the report in the default browser when done.

.PARAMETER Demo
    Build the report from a fictitious domain. No Active Directory needed.

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Open

.EXAMPLE
    .\Invoke-ADAudit.ps1 -InactiveDays 60 -OutputPath C:\Reports -Csv

.EXAMPLE
    .\Invoke-ADAudit.ps1 -Demo -Language fr -Open

.LINK
    https://github.com/B2ZO0/ad-audit-report
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [ValidateRange(1, 365)][int]$ExpiringDays = 14,
    [string]$Server,
    [ValidateSet('en', 'fr')][string]$Language,
    [switch]$Csv,
    [switch]$Open,
    [switch]$Demo
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

if (-not $Language) {
    $Language = if ((Get-Culture).TwoLetterISOLanguageName -eq 'fr') { 'fr' } else { 'en' }
}

# --------------------------------------------------------------------------------------------
# Texts
# --------------------------------------------------------------------------------------------
$T = @{
    en = @{
        title = 'Active Directory audit'; generated = 'Generated'; by = 'by'
        score = 'Score'; users = 'Users'; enabledUsers = 'enabled'; computers = 'Computers'
        privileged = 'Privileged accounts'; findings = 'Findings'; none = 'Nothing to report. Well done.'
        critical = 'Critical'; warning = 'Warning'; info = 'Info'
        accounts = 'account(s)'; fix = 'How to fix:'; showAccounts = 'Show the accounts'
        policy = 'Password policy'; dcs = 'Domain controllers'; groups = 'Privileged groups'
        setting = 'Setting'; value = 'Value'; host = 'Host'; os = 'Operating system'; site = 'Site'; gc = 'Global catalog'
        group = 'Group'; members = 'Members'; yes = 'yes'; no = 'no'; never = 'never'
        name = 'Name'; account = 'Account'; lastLogon = 'Last logon'; pwdSet = 'Password set'; detail = 'Detail'
        minLength = 'Minimum length'; complexity = 'Complexity'; maxAge = 'Maximum age (days)'; history = 'History'
        lockout = 'Lockout threshold'; lockoutOff = '0 (never locks)'
        domainMode = 'Domain functional level'; forestMode = 'Forest functional level'
        readOnly = 'Read-only audit: nothing was changed in Active Directory.'
        demo = 'Demo report: fictitious domain'; theme = 'Theme'
        gradeA = 'Healthy'; gradeB = 'Good, a few things to tidy'; gradeC = 'Needs attention'; gradeD = 'At risk'; gradeF = 'Act now'
        f_inactive_users = 'Enabled users inactive for {0}+ days'
        f_inactive_users_fix = 'Disable them, move them to an "archive" OU, and delete after a grace period. Check service accounts before.'
        f_never_logged = 'Enabled users that never logged on (created {0}+ days ago)'
        f_never_logged_fix = 'Usually forgotten or test accounts. Disable or delete them.'
        f_inactive_computers = 'Enabled computers inactive for {0}+ days'
        f_inactive_computers_fix = 'Machines that no longer exist keep valid credentials. Disable, then delete after a grace period.'
        f_pwd_never_expires = 'Enabled users whose password never expires'
        f_pwd_never_expires_fix = 'Remove the flag, or use a gMSA for service accounts so the password rotates automatically.'
        f_pwd_not_required = 'Accounts allowed to have an empty password'
        f_pwd_not_required_fix = 'Clear the flag: Set-ADUser <account> -PasswordNotRequired $false'
        f_no_preauth = 'Accounts without Kerberos pre-authentication (AS-REP roasting)'
        f_no_preauth_fix = 'Re-enable pre-authentication: Set-ADAccountControl <account> -DoesNotRequirePreAuth $false'
        f_spn_users = 'User accounts with an SPN (Kerberoasting targets)'
        f_spn_users_fix = 'Use long random passwords (25+ characters) or a gMSA; remove SPNs that are no longer used.'
        f_admin_old_pwd = 'Privileged accounts with a password older than 1 year'
        f_admin_old_pwd_fix = 'Change these passwords and use separate admin accounts for daily work.'
        f_admin_disabled = 'Disabled accounts still in privileged groups'
        f_admin_disabled_fix = 'Remove them from the groups: re-enabling the account would give back full rights.'
        f_too_many_admins = 'Many direct or nested members in Domain Admins'
        f_too_many_admins_fix = 'Keep Domain Admins for a handful of named admin accounts; delegate the rest.'
        f_krbtgt = 'krbtgt password not changed for 180+ days'
        f_krbtgt_fix = 'Rotate it twice, 10+ hours apart, with Microsoft''s New-KrbtgtKeys script.'
        f_guest = 'Guest account enabled'
        f_guest_fix = 'Disable the Guest account.'
        f_min_length = 'Minimum password length below 12'
        f_min_length_fix = 'Raise it to 12-14 in the Default Domain Policy, or use a fine-grained policy.'
        f_lockout = 'No account lockout'
        f_lockout_fix = 'Set a lockout threshold (for example 10 attempts) to slow down password guessing.'
        f_complexity = 'Password complexity disabled'
        f_complexity_fix = 'Enable complexity, or rely on long passphrases with a banned-password list.'
        f_obsolete_os = 'Computers on an unsupported Windows version'
        f_obsolete_os_fix = 'Upgrade or isolate them: they no longer receive security updates.'
        f_expiring = 'Passwords expiring in the next {0} days'
        f_expiring_fix = 'Remind the users; nothing is wrong, this is to avoid help-desk calls.'
        f_old_dc_os = 'Domain controllers on an unsupported Windows version'
        f_old_dc_os_fix = 'Promote new domain controllers and demote these ones.'
    }
    fr = @{
        title = 'Audit Active Directory'; generated = 'Généré le'; by = 'par'
        score = 'Score'; users = 'Utilisateurs'; enabledUsers = 'actifs'; computers = 'Ordinateurs'
        privileged = 'Comptes à privilèges'; findings = 'Constats'; none = 'Rien à signaler. Bravo.'
        critical = 'Critique'; warning = 'Attention'; info = 'Info'
        accounts = 'compte(s)'; fix = 'Comment corriger :'; showAccounts = 'Voir les comptes'
        policy = 'Stratégie de mots de passe'; dcs = 'Contrôleurs de domaine'; groups = 'Groupes à privilèges'
        setting = 'Paramètre'; value = 'Valeur'; host = 'Serveur'; os = 'Système'; site = 'Site'; gc = 'Catalogue global'
        group = 'Groupe'; members = 'Membres'; yes = 'oui'; no = 'non'; never = 'jamais'
        name = 'Nom'; account = 'Compte'; lastLogon = 'Dernière connexion'; pwdSet = 'Mot de passe changé'; detail = 'Détail'
        minLength = 'Longueur minimale'; complexity = 'Complexité'; maxAge = 'Durée maximale (jours)'; history = 'Historique'
        lockout = 'Seuil de verrouillage'; lockoutOff = '0 (jamais verrouillé)'
        domainMode = 'Niveau fonctionnel du domaine'; forestMode = 'Niveau fonctionnel de la forêt'
        readOnly = 'Audit en lecture seule : rien n''a été modifié dans l''Active Directory.'
        demo = 'Rapport de démonstration : domaine fictif'; theme = 'Thème'
        gradeA = 'En bonne santé'; gradeB = 'Bien, quelques points à ranger'; gradeC = 'À surveiller'; gradeD = 'À risque'; gradeF = 'À traiter maintenant'
        f_inactive_users = 'Utilisateurs actifs sans connexion depuis {0} jours ou plus'
        f_inactive_users_fix = 'Désactive-les, déplace-les dans une OU « archive », puis supprime-les après un délai. Vérifie avant les comptes de service.'
        f_never_logged = 'Utilisateurs actifs jamais connectés (créés il y a {0} jours ou plus)'
        f_never_logged_fix = 'Souvent des comptes oubliés ou de test. Désactive-les ou supprime-les.'
        f_inactive_computers = 'Ordinateurs actifs sans connexion depuis {0} jours ou plus'
        f_inactive_computers_fix = 'Des machines qui n''existent plus gardent des identifiants valides. Désactive-les, puis supprime-les après un délai.'
        f_pwd_never_expires = 'Utilisateurs actifs dont le mot de passe n''expire jamais'
        f_pwd_never_expires_fix = 'Retire l''option, ou utilise un gMSA pour les comptes de service : le mot de passe tourne tout seul.'
        f_pwd_not_required = 'Comptes autorisés à avoir un mot de passe vide'
        f_pwd_not_required_fix = 'Retire l''option : Set-ADUser <compte> -PasswordNotRequired $false'
        f_no_preauth = 'Comptes sans pré-authentification Kerberos (AS-REP roasting)'
        f_no_preauth_fix = 'Réactive la pré-authentification : Set-ADAccountControl <compte> -DoesNotRequirePreAuth $false'
        f_spn_users = 'Comptes utilisateurs avec un SPN (cibles de Kerberoasting)'
        f_spn_users_fix = 'Mots de passe longs et aléatoires (25 caractères ou plus) ou gMSA ; retire les SPN inutilisés.'
        f_admin_old_pwd = 'Comptes à privilèges avec un mot de passe de plus d''un an'
        f_admin_old_pwd_fix = 'Change ces mots de passe et utilise des comptes d''administration séparés du compte de tous les jours.'
        f_admin_disabled = 'Comptes désactivés encore membres de groupes à privilèges'
        f_admin_disabled_fix = 'Retire-les des groupes : réactiver le compte redonnerait tous les droits.'
        f_too_many_admins = 'Beaucoup de membres, directs ou imbriqués, dans Admins du domaine'
        f_too_many_admins_fix = 'Réserve Admins du domaine à quelques comptes d''administration nominatifs ; délègue le reste.'
        f_krbtgt = 'Mot de passe de krbtgt inchangé depuis 180 jours ou plus'
        f_krbtgt_fix = 'Change-le deux fois, à plus de 10 heures d''intervalle, avec le script New-KrbtgtKeys de Microsoft.'
        f_guest = 'Compte Invité activé'
        f_guest_fix = 'Désactive le compte Invité.'
        f_min_length = 'Longueur minimale des mots de passe inférieure à 12'
        f_min_length_fix = 'Passe-la à 12 ou 14 dans la Default Domain Policy, ou utilise une stratégie affinée.'
        f_lockout = 'Aucun verrouillage de compte'
        f_lockout_fix = 'Définis un seuil de verrouillage (par exemple 10 essais) pour freiner les attaques par mot de passe.'
        f_complexity = 'Complexité des mots de passe désactivée'
        f_complexity_fix = 'Active la complexité, ou impose des phrases de passe longues avec une liste de mots de passe interdits.'
        f_obsolete_os = 'Ordinateurs sous une version de Windows plus supportée'
        f_obsolete_os_fix = 'Mets-les à jour ou isole-les : ils ne reçoivent plus de correctifs de sécurité.'
        f_expiring = 'Mots de passe qui expirent dans les {0} prochains jours'
        f_expiring_fix = 'Préviens les utilisateurs ; rien d''anormal, c''est pour éviter les appels au support.'
        f_old_dc_os = 'Contrôleurs de domaine sous une version de Windows plus supportée'
        f_old_dc_os_fix = 'Promeus de nouveaux contrôleurs de domaine et rétrograde ceux-ci.'
    }
}[$Language]

function Enc([object]$s) { if ($null -eq $s) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Fmt-Date($d) { if ($null -eq $d -or $d -eq [datetime]::MinValue) { return $T.never } ([datetime]$d).ToString('yyyy-MM-dd') }

# Windows versions without security updates (client and server)
$ObsoleteOs = 'Windows (XP|Vista|7|8|8\.1)\b|Windows 10 (?!.*(LTSC|LTSB|Enterprise 2019|Enterprise 2021))|Server 200[038]|Server 2012'

# --------------------------------------------------------------------------------------------
# Data collection (Active Directory, read-only)
# --------------------------------------------------------------------------------------------
function Get-AuditData {
    Import-Module ActiveDirectory -ErrorAction Stop
    $p = @{}
    if ($Server) { $p.Server = $Server }

    $domain = Get-ADDomain @p
    $forest = Get-ADForest @p
    $sid = $domain.DomainSID.Value
    $rootSid = (Get-ADDomain -Identity $forest.RootDomain @p).DomainSID.Value

    $userProps = 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired',
                 'DoesNotRequirePreAuth', 'ServicePrincipalName', 'whenCreated', 'DisplayName', 'SID',
                 'msDS-UserPasswordExpiryTimeComputed'
    $users = foreach ($u in Get-ADUser -Filter * -Properties $userProps @p) {
        $exp = $null
        $raw = $u.'msDS-UserPasswordExpiryTimeComputed'
        if ($raw -and $raw -gt 0 -and $raw -lt [int64]::MaxValue) { $exp = [datetime]::FromFileTime($raw) }
        [pscustomobject]@{
            Sam = $u.SamAccountName; Name = $u.DisplayName; Enabled = [bool]$u.Enabled
            LastLogon = $u.LastLogonDate; PwdLastSet = $u.PasswordLastSet; Created = $u.whenCreated
            PwdNeverExpires = [bool]$u.PasswordNeverExpires; PwdNotRequired = [bool]$u.PasswordNotRequired
            NoPreAuth = [bool]$u.DoesNotRequirePreAuth; HasSpn = (@($u.ServicePrincipalName).Count -gt 0)
            PwdExpires = $exp; Rid = [int]($u.SID.Value.Split('-')[-1])
        }
    }
    $computers = foreach ($c in Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, whenCreated @p) {
        [pscustomobject]@{ Name = $c.Name; Enabled = [bool]$c.Enabled; LastLogon = $c.LastLogonDate
                           Os = $c.OperatingSystem; Created = $c.whenCreated }
    }

    # Privileged groups by well-known SID: language independent
    $wellKnown = [ordered]@{
        DomainAdmins = "$sid-512"; EnterpriseAdmins = "$rootSid-519"; SchemaAdmins = "$rootSid-518"
        Administrators = 'S-1-5-32-544'; AccountOperators = 'S-1-5-32-548'; ServerOperators = 'S-1-5-32-549'
        PrintOperators = 'S-1-5-32-550'; BackupOperators = 'S-1-5-32-551'; GpoCreators = "$sid-520"
    }
    $groups = foreach ($k in $wellKnown.Keys) {
        try { $g = Get-ADGroup -Identity $wellKnown[$k] @p } catch { continue }
        try { $raw = @(Get-ADGroupMember -Identity $g -Recursive @p) }
        catch { Write-Warning "Could not list members of $($g.Name): $($_.Exception.Message)"; $raw = @() }
        $members = foreach ($m in $raw) {
            $enabled = $true
            if ($m.objectClass -eq 'user') { $enabled = [bool](Get-ADUser $m -Properties Enabled @p).Enabled }
            [pscustomobject]@{ Sam = $m.SamAccountName; Type = $m.objectClass; Enabled = $enabled }
        }
        [pscustomobject]@{ Key = $k; Name = $g.Name; Members = @($members) }
    }
    try {
        $dns = Get-ADGroup -Identity 'DnsAdmins' @p
        $groups = @($groups) + [pscustomobject]@{ Key = 'DnsAdmins'; Name = $dns.Name
            Members = @(Get-ADGroupMember $dns -Recursive @p | ForEach-Object { [pscustomobject]@{ Sam = $_.SamAccountName; Type = $_.objectClass; Enabled = $true } }) }
    } catch { Write-Verbose 'DnsAdmins not found' }

    $pol = Get-ADDefaultDomainPasswordPolicy @p
    $dcs = foreach ($d in Get-ADDomainController -Filter * @p) {
        [pscustomobject]@{ Host = $d.HostName; Os = $d.OperatingSystem; Site = $d.Site; GC = [bool]$d.IsGlobalCatalog }
    }
    $krbtgt = Get-ADUser -Identity "$sid-502" -Properties PasswordLastSet @p

    [pscustomobject]@{
        Domain = $domain.DNSRoot; NetBIOS = $domain.NetBIOSName
        DomainMode = [string]$domain.DomainMode; ForestMode = [string]$forest.ForestMode
        Users = @($users); Computers = @($computers); Groups = @($groups); DCs = @($dcs)
        Policy = [pscustomobject]@{ MinLength = $pol.MinPasswordLength; Complexity = [bool]$pol.ComplexityEnabled
            MaxAgeDays = [int]$pol.MaxPasswordAge.TotalDays; History = $pol.PasswordHistoryCount; Lockout = $pol.LockoutThreshold }
        KrbtgtPwdLastSet = $krbtgt.PasswordLastSet
        Demo = $false
    }
}

# --------------------------------------------------------------------------------------------
# Fictitious domain for the demo
# --------------------------------------------------------------------------------------------
function Get-DemoData {
    $null = Get-Random -SetSeed 42
    $now = Get-Date
    $first = 'Alice', 'Bruno', 'Chloe', 'David', 'Emma', 'Farid', 'Gaelle', 'Hugo', 'Ines', 'Jules', 'Karim', 'Lea', 'Malik', 'Nina', 'Oscar', 'Paul', 'Quentin', 'Rose', 'Sami', 'Theo'
    $last = 'Martin', 'Bernard', 'Durand', 'Petit', 'Leroy', 'Moreau', 'Simon', 'Laurent', 'Garnier', 'Faure'
    $users = New-Object System.Collections.Generic.List[object]
    $i = 1100
    foreach ($l in $last) {
        foreach ($f in $first | Get-Random -Count 9) {
            $i++
            $logon = $now.AddDays(-(Get-Random -Minimum 0 -Maximum 30))
            $users.Add([pscustomobject]@{ Sam = ($f.Substring(0, 1) + $l).ToLower(); Name = "$f $l"; Enabled = $true
                LastLogon = $logon; PwdLastSet = $now.AddDays(-(Get-Random -Minimum 5 -Maximum 170)); Created = $now.AddDays(-(Get-Random -Minimum 200 -Maximum 2000))
                PwdNeverExpires = $false; PwdNotRequired = $false; NoPreAuth = $false; HasSpn = $false
                PwdExpires = $null; Rid = $i })
        }
    }
    foreach ($u in $users) { $u.PwdExpires = $u.PwdLastSet.AddDays(180) }
    $ua = $users.ToArray()
    # a few realistic problems
    foreach ($u in $ua[3, 17, 28, 44, 51, 63, 77]) { $u.LastLogon = $now.AddDays(-(Get-Random -Minimum 120 -Maximum 700)) }
    foreach ($u in $ua[9, 34]) { $u.LastLogon = $null; $u.Created = $now.AddDays(-400) }
    foreach ($u in $ua[5, 12, 40, 61, 70]) { $u.PwdExpires = $now.AddDays((Get-Random -Minimum 1 -Maximum 13)) }
    $ua[22].Enabled = $false
    $svc = @(
        @{ Sam = 'svc-sql'; Name = 'SQL Server service'; Spn = $true; Never = $true; Pwd = 1400 }
        @{ Sam = 'svc-backup'; Name = 'Backup service'; Spn = $false; Never = $true; Pwd = 900 }
        @{ Sam = 'svc-web'; Name = 'Intranet app pool'; Spn = $true; Never = $true; Pwd = 600 }
        @{ Sam = 'scanner'; Name = 'Scan to folder'; Spn = $false; Never = $true; Pwd = 2100; NoPre = $true }
    )
    foreach ($s in $svc) {
        $i++
        $users.Add([pscustomobject]@{ Sam = $s.Sam; Name = $s.Name; Enabled = $true; LastLogon = $now.AddDays(-1)
            PwdLastSet = $now.AddDays(-$s.Pwd); Created = $now.AddDays(-2500); PwdNeverExpires = $s.Never; PwdNotRequired = $false
            NoPreAuth = [bool]$s["NoPre"]; HasSpn = $s.Spn; PwdExpires = $null; Rid = $i })
    }
    $admins = @(
        @{ Sam = 'Administrator'; Rid = 500; Pwd = 1650; En = $true }
        @{ Sam = 'adm-enzo'; Rid = 1301; Pwd = 60; En = $true }
        @{ Sam = 'adm-lucas'; Rid = 1302; Pwd = 420; En = $true }
        @{ Sam = 'adm-old'; Rid = 1303; Pwd = 1200; En = $false }
        @{ Sam = 'it-support'; Rid = 1304; Pwd = 30; En = $true; NotReq = $true }
    )
    foreach ($a in $admins) {
        $users.Add([pscustomobject]@{ Sam = $a.Sam; Name = $a.Sam; Enabled = $a.En; LastLogon = $now.AddDays(-2)
            PwdLastSet = $now.AddDays(-$a.Pwd); Created = $now.AddDays(-2500); PwdNeverExpires = ($a.Rid -eq 500); PwdNotRequired = [bool]$a["NotReq"]
            NoPreAuth = $false; HasSpn = $false; PwdExpires = $null; Rid = $a.Rid })
    }
    $users.Add([pscustomobject]@{ Sam = 'Guest'; Name = 'Guest'; Enabled = $false; LastLogon = $null; PwdLastSet = $null; Created = $now.AddDays(-2500)
        PwdNeverExpires = $true; PwdNotRequired = $true; NoPreAuth = $false; HasSpn = $false; PwdExpires = $null; Rid = 501 })

    $computers = New-Object System.Collections.Generic.List[object]
    $oses = 'Windows 11 Pro', 'Windows 11 Pro', 'Windows 11 Enterprise', 'Windows 10 Pro'
    for ($n = 1; $n -le 64; $n++) {
        $computers.Add([pscustomobject]@{ Name = ('PC-{0:000}' -f $n); Enabled = $true; LastLogon = $now.AddDays(-(Get-Random -Minimum 0 -Maximum 25))
            Os = ($oses | Get-Random); Created = $now.AddDays(-900) })
    }
    foreach ($n in 7, 19, 33, 48, 55, 60) { $computers[[int]$n].LastLogon = $now.AddDays(-(Get-Random -Minimum 100 -Maximum 500)) }
    $servers = @(
        @('DC01', 'Windows Server 2022 Standard'), @('DC02', 'Windows Server 2016 Standard'), @('FILES01', 'Windows Server 2022 Standard'),
        @('SQL01', 'Windows Server 2019 Standard'), @('APP01', 'Windows Server 2012 R2 Standard'), @('PRINT01', 'Windows Server 2016 Standard'),
        @('OLD-ERP', 'Windows Server 2008 R2 Standard'), @('LAB-W7', 'Windows 7 Professional')
    )
    foreach ($s in $servers) {
        $computers.Add([pscustomobject]@{ Name = $s[0]; Enabled = $true; LastLogon = $now.AddDays(-1); Os = $s[1]; Created = $now.AddDays(-2000) })
    }

    $grp = {
        param($key, $name, [string[]]$members)
        [pscustomobject]@{ Key = $key; Name = $name; Members = @($members | ForEach-Object {
            $m = $_; $u = $users | Where-Object { $_.Sam -eq $m } | Select-Object -First 1
            [pscustomobject]@{ Sam = $m; Type = 'user'; Enabled = if ($u) { $u.Enabled } else { $true } } }) }
    }
    $groups = @(
        (& $grp 'DomainAdmins' 'Domain Admins' @('Administrator', 'adm-enzo', 'adm-lucas', 'adm-old', 'it-support', 'svc-backup'))
        (& $grp 'EnterpriseAdmins' 'Enterprise Admins' @('Administrator'))
        (& $grp 'SchemaAdmins' 'Schema Admins' @('Administrator'))
        (& $grp 'Administrators' 'Administrators' @('Administrator', 'adm-enzo', 'adm-lucas', 'adm-old', 'it-support', 'svc-backup', 'svc-sql'))
        (& $grp 'AccountOperators' 'Account Operators' @())
        (& $grp 'BackupOperators' 'Backup Operators' @('svc-backup'))
        (& $grp 'ServerOperators' 'Server Operators' @())
        (& $grp 'PrintOperators' 'Print Operators' @())
        (& $grp 'GpoCreators' 'Group Policy Creator Owners' @('Administrator'))
        (& $grp 'DnsAdmins' 'DnsAdmins' @('adm-lucas'))
    )

    [pscustomobject]@{
        Domain = 'corp.example'; NetBIOS = 'CORP'; DomainMode = 'Windows2016Domain'; ForestMode = 'Windows2016Forest'
        Users = $users.ToArray(); Computers = $computers.ToArray(); Groups = $groups
        DCs = @([pscustomobject]@{ Host = 'dc01.corp.example'; Os = 'Windows Server 2022 Standard'; Site = 'HQ'; GC = $true },
                [pscustomobject]@{ Host = 'dc02.corp.example'; Os = 'Windows Server 2016 Standard'; Site = 'Branch'; GC = $true })
        Policy = [pscustomobject]@{ MinLength = 8; Complexity = $true; MaxAgeDays = 180; History = 12; Lockout = 0 }
        KrbtgtPwdLastSet = $now.AddDays(-1460)
        Demo = $true
    }
}

# --------------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------------
function Get-Findings($d) {
    $now = Get-Date
    $list = New-Object System.Collections.Generic.List[object]
    $add = {
        param($id, $sev, $title, $fix, $items, [string[]]$cols)
        $items = @($items | Where-Object { $null -ne $_ })
        if ($items.Count -gt 0) {
            $list.Add([pscustomobject]@{ Id = $id; Severity = $sev; Title = $title; Fix = $fix; Items = $items; Columns = $cols })
        }
    }
    $u = $d.Users | Where-Object { $_.Enabled -and $_.Rid -ne 502 }
    $cut = $now.AddDays(-$InactiveDays)
    $userCols = 'Sam', 'Name', 'LastLogon', 'PwdLastSet'

    & $add 'inactive_users' 'warning' ($T.f_inactive_users -f $InactiveDays) $T.f_inactive_users_fix `
        ($u | Where-Object { $_.LastLogon -and $_.LastLogon -lt $cut } | Sort-Object LastLogon) $userCols
    & $add 'never_logged' 'info' ($T.f_never_logged -f $InactiveDays) $T.f_never_logged_fix `
        ($u | Where-Object { -not $_.LastLogon -and $_.Created -lt $cut -and $_.Rid -ge 1000 }) $userCols
    & $add 'inactive_computers' 'warning' ($T.f_inactive_computers -f $InactiveDays) $T.f_inactive_computers_fix `
        ($d.Computers | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt $cut } | Sort-Object LastLogon) @('Name', 'Os', 'LastLogon')
    & $add 'pwd_not_required' 'critical' $T.f_pwd_not_required $T.f_pwd_not_required_fix `
        ($u | Where-Object { $_.PwdNotRequired }) $userCols
    & $add 'no_preauth' 'critical' $T.f_no_preauth $T.f_no_preauth_fix ($u | Where-Object { $_.NoPreAuth }) $userCols
    & $add 'spn_users' 'warning' $T.f_spn_users $T.f_spn_users_fix ($u | Where-Object { $_.HasSpn }) $userCols
    & $add 'pwd_never_expires' 'warning' $T.f_pwd_never_expires $T.f_pwd_never_expires_fix `
        ($u | Where-Object { $_.PwdNeverExpires }) $userCols

    # privileged accounts
    $privSam = @{}
    foreach ($g in $d.Groups) { foreach ($m in $g.Members) { if ($m.Type -eq 'user') { $privSam[$m.Sam] = $true } } }
    $priv = $d.Users | Where-Object { $privSam.ContainsKey($_.Sam) }
    & $add 'admin_old_pwd' 'critical' $T.f_admin_old_pwd $T.f_admin_old_pwd_fix `
        ($priv | Where-Object { $_.Enabled -and $_.PwdLastSet -and $_.PwdLastSet -lt $now.AddDays(-365) } | Sort-Object PwdLastSet) $userCols
    & $add 'admin_disabled' 'warning' $T.f_admin_disabled $T.f_admin_disabled_fix ($priv | Where-Object { -not $_.Enabled }) $userCols
    $da = $d.Groups | Where-Object { $_.Key -eq 'DomainAdmins' } | Select-Object -First 1
    if ($da -and @($da.Members).Count -gt 5) {
        & $add 'too_many_admins' 'warning' $T.f_too_many_admins $T.f_too_many_admins_fix ($da.Members) @('Sam', 'Type', 'Enabled')
    }
    if ($d.KrbtgtPwdLastSet -and $d.KrbtgtPwdLastSet -lt $now.AddDays(-180)) {
        & $add 'krbtgt' 'warning' $T.f_krbtgt $T.f_krbtgt_fix ([pscustomobject]@{ Sam = 'krbtgt'; Name = 'krbtgt'; LastLogon = $null; PwdLastSet = $d.KrbtgtPwdLastSet }) @('Sam', 'PwdLastSet')
    }
    & $add 'guest' 'critical' $T.f_guest $T.f_guest_fix ($d.Users | Where-Object { $_.Rid -eq 501 -and $_.Enabled }) @('Sam')

    # policy
    $pol = $d.Policy
    $pl = { param($k, $v) [pscustomobject]@{ Setting = $k; Value = $v } }
    if ($pol.MinLength -lt 12) { & $add 'min_length' 'warning' $T.f_min_length $T.f_min_length_fix (& $pl $T.minLength $pol.MinLength) @('Setting', 'Value') }
    if ($pol.Lockout -eq 0) { & $add 'lockout' 'warning' $T.f_lockout $T.f_lockout_fix (& $pl $T.lockout $T.lockoutOff) @('Setting', 'Value') }
    if (-not $pol.Complexity) { & $add 'complexity' 'warning' $T.f_complexity $T.f_complexity_fix (& $pl $T.complexity $T.no) @('Setting', 'Value') }

    & $add 'old_dc_os' 'critical' $T.f_old_dc_os $T.f_old_dc_os_fix ($d.DCs | Where-Object { $_.Os -match $ObsoleteOs }) @('Host', 'Os')
    & $add 'obsolete_os' 'warning' $T.f_obsolete_os $T.f_obsolete_os_fix `
        ($d.Computers | Where-Object { $_.Enabled -and $_.Os -match $ObsoleteOs } | Sort-Object Os) @('Name', 'Os', 'LastLogon')
    & $add 'expiring' 'info' ($T.f_expiring -f $ExpiringDays) $T.f_expiring_fix `
        ($u | Where-Object { $_.PwdExpires -and $_.PwdExpires -gt $now -and $_.PwdExpires -lt $now.AddDays($ExpiringDays) } | Sort-Object PwdExpires) @('Sam', 'Name', 'PwdExpires')

    $order = @{ critical = 0; warning = 1; info = 2 }
    @($list | Sort-Object { $order[$_.Severity] }, { - $_.Items.Count })
}

function Get-Score($findings) {
    $score = 100
    foreach ($f in $findings) {
        switch ($f.Severity) { 'critical' { $score -= 9 } 'warning' { $score -= 3 } 'info' { $score -= 1 } }
    }
    [math]::Max(0, $score)
}

# --------------------------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------------------------
function ConvertTo-AuditHtml($d, $findings, [int]$score) {
    $grade = if ($score -ge 90) { 'A', $T.gradeA } elseif ($score -ge 75) { 'B', $T.gradeB } elseif ($score -ge 60) { 'C', $T.gradeC } elseif ($score -ge 40) { 'D', $T.gradeD } else { 'F', $T.gradeF }
    $ring = if ($score -ge 75) { 'var(--ok)' } elseif ($score -ge 50) { 'var(--warn)' } else { 'var(--crit)' }
    $enabledUsers = @($d.Users | Where-Object { $_.Enabled }).Count
    $privCount = @($d.Groups | ForEach-Object { $_.Members } | Where-Object { $_.Type -eq 'user' } | Select-Object -ExpandProperty Sam -Unique).Count
    $count = @{ critical = 0; warning = 0; info = 0 }
    foreach ($f in $findings) { $count[$f.Severity]++ }
    $colName = @{ Sam = $T.account; Name = $T.name; LastLogon = $T.lastLogon; PwdLastSet = $T.pwdSet; Os = $T.os; Host = $T.host
                  Type = 'Type'; Enabled = $T.enabledUsers; PwdExpires = 'Expire'; Setting = $T.setting; Value = $T.value }

    $sb = New-Object System.Text.StringBuilder
    foreach ($f in $findings) {
        $rows = foreach ($it in $f.Items | Select-Object -First 200) {
            '<tr>' + (($f.Columns | ForEach-Object {
                $v = $it.$_
                if ($v -is [datetime]) { $v = Fmt-Date $v } elseif ($v -is [bool]) { $v = if ($v) { $T.yes } else { $T.no } } elseif ($null -eq $v -and $_ -match 'Logon|Pwd') { $v = $T.never }
                '<td>' + (Enc $v) + '</td>' }) -join '') + '</tr>'
        }
        $head = ($f.Columns | ForEach-Object { '<th>' + (Enc $colName[$_]) + '</th>' }) -join ''
        $n = @($f.Items).Count
        [void]$sb.Append(@"
<details class="finding $($f.Severity)">
  <summary><span class="badge $($f.Severity)">$(Enc $T[$f.Severity])</span><span class="ftitle">$(Enc $f.Title)</span><span class="count">$n</span></summary>
  <div class="body"><p class="fix"><b>$(Enc $T.fix)</b> $(Enc $f.Fix)</p>
  <table><thead><tr>$head</tr></thead><tbody>$($rows -join "`n")</tbody></table></div>
</details>
"@)
    }
    if ($findings.Count -eq 0) { [void]$sb.Append("<p class='none'>$(Enc $T.none)</p>") }

    $p = $d.Policy
    $policyRows = @(
        @($T.minLength, $p.MinLength), @($T.complexity, $(if ($p.Complexity) { $T.yes } else { $T.no })),
        @($T.maxAge, $p.MaxAgeDays), @($T.history, $p.History), @($T.lockout, $(if ($p.Lockout -eq 0) { $T.lockoutOff } else { $p.Lockout })),
        @($T.domainMode, $d.DomainMode), @($T.forestMode, $d.ForestMode)
    ) | ForEach-Object { "<tr><td>$(Enc $_[0])</td><td>$(Enc $_[1])</td></tr>" }
    $dcRows = $d.DCs | ForEach-Object { "<tr><td>$(Enc $_.Host)</td><td>$(Enc $_.Os)</td><td>$(Enc $_.Site)</td><td>$(if ($_.GC) { $T.yes } else { $T.no })</td></tr>" }
    $groupRows = $d.Groups | ForEach-Object {
        $names = ($_.Members | ForEach-Object { if ($_.Enabled) { Enc $_.Sam } else { "<s>$(Enc $_.Sam)</s>" } }) -join ', '
        "<tr><td>$(Enc $_.Name)</td><td class='num'>$(@($_.Members).Count)</td><td>$names</td></tr>"
    }
    $demoBanner = if ($d.Demo) { "<div class='demo'>$(Enc $T.demo)</div>" } else { '' }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    $dash = [math]::Round(2 * [math]::PI * 52 * $score / 100, 1)

    @"
<!DOCTYPE html>
<html lang="$Language"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Enc $T.title) · $(Enc $d.Domain)</title>
<style>
:root{--bg:#0c0e16;--panel:#141725;--line:#262a3d;--text:#e8e9f3;--muted:#9096b4;--accent:#8a6cff;--accent2:#d16bff;--ok:#35d07f;--warn:#f5b13d;--crit:#ff5c7a;--info:#4cc9f0}
:root.day{--bg:#f6f6fb;--panel:#fff;--line:#e3e4ef;--text:#171a2b;--muted:#5d6382;--accent:#6d4cf0;--accent2:#b13ad6;--ok:#14a35b;--warn:#c27c00;--crit:#d6264a;--info:#0f8fb8}
@media (prefers-color-scheme: light){:root:not(.night){--bg:#f6f6fb;--panel:#fff;--line:#e3e4ef;--text:#171a2b;--muted:#5d6382;--accent:#6d4cf0;--accent2:#b13ad6;--ok:#14a35b;--warn:#c27c00;--crit:#d6264a;--info:#0f8fb8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 24px 60px}
header{display:flex;align-items:center;gap:16px;margin-bottom:22px}header h1{font-size:24px;margin:0}header .sub{color:var(--muted)}
.logo{width:44px;height:44px}.spacer{flex:1}
button.theme{background:var(--panel);color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:6px 12px;cursor:pointer}
.demo{background:linear-gradient(90deg,var(--accent),var(--accent2));color:#fff;padding:8px 14px;border-radius:10px;margin-bottom:18px;font-weight:600}
.top{display:grid;grid-template-columns:300px 1fr;gap:16px;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px}
.scorecard{display:flex;align-items:center;gap:18px}.scorecard .big{font-size:40px;font-weight:700}.scorecard .grade{color:var(--muted)}
.ring circle{fill:none;stroke-width:10}.ring .bg{stroke:var(--line)}.ring .fg{stroke:$ring;stroke-linecap:round;transform:rotate(-90deg);transform-origin:60px 60px}
.ring text{fill:var(--text);font-size:30px;font-weight:700;text-anchor:middle;dominant-baseline:central}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;align-items:center}.stat .v{font-size:28px;font-weight:700}.stat .l{color:var(--muted)}
.stat .v.crit{color:var(--crit)}.stat .v.warn{color:var(--warn)}
h2{font-size:17px;margin:28px 0 12px}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:12px;margin-bottom:10px}
.finding.critical{border-left-color:var(--crit)}.finding.warning{border-left-color:var(--warn)}
.finding summary{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;list-style:none}.finding summary::-webkit-details-marker{display:none}
.ftitle{flex:1;font-weight:600}.count{background:var(--bg);border:1px solid var(--line);border-radius:999px;padding:1px 10px;color:var(--muted);font-variant-numeric:tabular-nums}
.badge{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:6px;color:#fff;background:var(--info)}
.badge.critical{background:var(--crit)}.badge.warning{background:var(--warn);color:#1b1300}
.body{padding:0 16px 14px}.fix{margin:0 0 10px;color:var(--muted)}.fix b{color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:6px 8px}
td{border-bottom:1px solid var(--line);padding:6px 8px}td.num{font-variant-numeric:tabular-nums}s{color:var(--muted)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.none{color:var(--ok);font-weight:600}
footer{margin-top:34px;color:var(--muted);font-size:12px;display:flex;gap:8px;flex-wrap:wrap}footer a{color:var(--accent)}
@media (max-width:800px){.top,.grid2{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}
@media print{button.theme{display:none}details{break-inside:avoid}details:not([open]) .body{display:block}}
</style></head><body><div class="wrap">
<header>
<svg class="logo" viewBox="0 0 128 128"><rect x="4" y="4" width="120" height="120" rx="24" fill="#11131d"/><g fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="8"><path d="M64 26 96 38v24c0 20-14 34-32 40-18-6-32-20-32-40V38z" stroke="#8a6cff"/><path d="m48 64 11 11 21-22" stroke="#d16bff" stroke-width="8.5"/></g></svg>
<div><h1>$(Enc $T.title) · $(Enc $d.Domain)</h1><div class="sub">$(Enc $T.generated) $generated · $(Enc $d.NetBIOS)</div></div>
<div class="spacer"></div><button class="theme" onclick="toggle()">◐ $(Enc $T.theme)</button>
</header>
$demoBanner
<div class="top">
<div class="card scorecard"><svg class="ring" width="120" height="120"><circle class="bg" cx="60" cy="60" r="52"/><circle class="fg" cx="60" cy="60" r="52" stroke-dasharray="$dash 400"/><text x="60" y="60">$($grade[0])</text></svg>
<div><div class="big">$score<span style="font-size:18px;color:var(--muted)">/100</span></div><div class="grade">$(Enc $grade[1])</div></div></div>
<div class="card stats">
<div class="stat"><div class="v">$enabledUsers</div><div class="l">$(Enc $T.users) $(Enc $T.enabledUsers) / $(@($d.Users).Count)</div></div>
<div class="stat"><div class="v">$(@($d.Computers | Where-Object { $_.Enabled }).Count)</div><div class="l">$(Enc $T.computers)</div></div>
<div class="stat"><div class="v">$privCount</div><div class="l">$(Enc $T.privileged)</div></div>
<div class="stat"><div class="v"><span class="crit" style="color:var(--crit)">$($count.critical)</span> · <span style="color:var(--warn)">$($count.warning)</span> · <span style="color:var(--info)">$($count.info)</span></div><div class="l">$(Enc $T.critical) · $(Enc $T.warning) · $(Enc $T.info)</div></div>
</div></div>
<h2>$(Enc $T.findings)</h2>
$($sb.ToString())
<div class="grid2">
<div><h2>$(Enc $T.policy)</h2><div class="card"><table><thead><tr><th>$(Enc $T.setting)</th><th>$(Enc $T.value)</th></tr></thead><tbody>$($policyRows -join '')</tbody></table></div></div>
<div><h2>$(Enc $T.dcs)</h2><div class="card"><table><thead><tr><th>$(Enc $T.host)</th><th>$(Enc $T.os)</th><th>$(Enc $T.site)</th><th>$(Enc $T.gc)</th></tr></thead><tbody>$($dcRows -join '')</tbody></table></div></div>
</div>
<h2>$(Enc $T.groups)</h2><div class="card"><table><thead><tr><th>$(Enc $T.group)</th><th>#</th><th>$(Enc $T.members)</th></tr></thead><tbody>$($groupRows -join '')</tbody></table></div>
<footer><span>$(Enc $T.readOnly)</span><span>·</span><span>ad-audit-report $ScriptVersion $(Enc $T.by) <a href="https://github.com/B2ZO0/ad-audit-report">B2ZO0</a></span></footer>
</div>
<script>
function toggle(){var r=document.documentElement;var day=r.classList.contains('day')||(!r.classList.contains('night')&&matchMedia('(prefers-color-scheme: light)').matches);r.classList.remove('day','night');r.classList.add(day?'night':'day');}
</script>
</body></html>
"@
}

# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------
Write-Host "ad-audit-report $ScriptVersion" -ForegroundColor Magenta
if ($Demo) {
    $data = Get-DemoData
} else {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory PowerShell module is missing. Install RSAT (Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0), or try -Demo.'
    }
    Write-Host 'Reading Active Directory (read-only)...'
    $data = Get-AuditData
}
$findings = @(Get-Findings $data)
$score = Get-Score $findings

if ($OutputPath -match '\.html?$') { $file = $OutputPath } else {
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $file = Join-Path $OutputPath ('ad-audit-{0}-{1}.html' -f ($data.Domain -replace '[^\w.-]', '_'), (Get-Date -Format 'yyyyMMdd-HHmm'))
}
ConvertTo-AuditHtml $data $findings $score | Out-File -FilePath $file -Encoding utf8
Write-Host ("Score {0}/100 · {1} finding(s) · report: {2}" -f $score, $findings.Count, (Resolve-Path $file)) -ForegroundColor Green

if ($Csv) {
    $csvFile = [System.IO.Path]::ChangeExtension($file, '.csv')
    $findings | ForEach-Object {
        $f = $_
        foreach ($it in $f.Items) {
            [pscustomobject]@{ Severity = $f.Severity; Finding = $f.Title
                Object = if ($it.PSObject.Properties['Sam']) { $it.Sam } elseif ($it.PSObject.Properties['Name']) { $it.Name } elseif ($it.PSObject.Properties['Host']) { $it.Host } else { $it.Setting }
                Detail = ($f.Columns | ForEach-Object { '{0}={1}' -f $_, $it.$_ }) -join '; ' }
        }
    } | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $csvFile"
}
if ($Open) { Invoke-Item $file }
