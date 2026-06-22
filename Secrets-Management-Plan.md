# Expertflow Secrets & Credential Management Plan

> **Version:** 1.0  
> **Status:** Draft — Pending Review  
> **Owner:** IT Infrastructure Team  
> **Stakeholders:** All Department Heads, Security, DevOps, Agentic Dev Team  
> **Last Updated:** 2026-06-22

---

## 1. Executive Summary

Expertflow operates a hybrid infrastructure spanning **5 cloud providers** (DigitalOcean, GCP, AWS, Azure, Hetzner/Contabo) and a **local datacenter / lab** with physical servers, hypervisors, virtual machines, and network equipment. Secrets are currently stored in spreadsheets and shared documents — a **critical security and compliance risk**.

This plan defines a **Two-Vault Architecture** using:

- **HashiCorp Vault** (`vault.expertflow.com`) — for machine-readable infrastructure secrets, API tokens, dynamic credentials, and automation
- **Vaultwarden** (`secrets.expertflow.com`) — for human-shared passwords, SaaS admin accounts, and break-glass credentials

The plan explicitly addresses **local lab infrastructure** (physical servers, iLO/iDRAC, hypervisors, lab VMs, network switches) which has been historically under-documented and under-secured.

---

## 2. Current State Assessment

### 2.1 Secrets Storage Maturity

| Domain | Current State | Risk Level | Evidence |
|--------|--------------|------------|----------|
| Cloud API keys | Spreadsheets | 🔴 Critical | Google Sheets shared internally |
| DB credentials | Spreadsheets + hardcoded | 🔴 Critical | Found in config files, chat logs |
| SaaS passwords | No central store | 🔴 Critical | Individual browser saves, sticky notes |
| **iLO/iDRAC passwords** | **Spreadsheets / verbal** | 🔴 **Critical** | Physical server BMC access uncontrolled |
| **Lab VM root passwords** | **Shared document** | 🔴 **Critical** | Same password reused across multiple VMs |
| **Hypervisor credentials** | **Unknown / undocumented** | 🔴 **Critical** | No owner assigned, no rotation history |
| **Network switch credentials** | **Spreadsheet (Ports Detail)** | 🔴 **Critical** | Switch admin access uncontrolled |
| SSH keys | Partially in Vault | 🟡 Medium | `vault.expertflow.com` exists but unused |
| LLM API tokens | Spreadsheet | 🟡 Medium | Kimi/DeepSeek/Claude tokens in docs |
| TLS certificates | Manual management | 🟡 Medium | No auto-renewal or centralized tracking |

### 2.2 Local Lab Infrastructure Inventory

Based on ITAM sheet data, the local datacenter contains:

| Category | ITAM Sheet | Secret Types | Current Storage |
|----------|-----------|--------------|-----------------|
| **Physical Servers** | Lab Servers | iLO/iDRAC IPs, BMC creds, BIOS passwords | Spreadsheet |
| **Server Management** | iLO/iDRAC | Web admin passwords, SNMP communities | Verbal / shared doc |
| **Lab VMs** | Lab VM List | Root/admin passwords, SSH keys, sudoers | Shared document |
| **Network Equipment** | Ports Detail | Switch admin passwords, VLAN configs, console creds | Spreadsheet |
| **Free/Spare VMs** | Free VMs | Stale credentials (orphaned risk) | Unknown |

> **Critical Gap:** Local lab secrets are the most exposed because they lack the audit trails and access controls that cloud providers offer natively. A single compromised spreadsheet gives an attacker root on physical infrastructure.

### 2.3 HashiCorp Vault (`vault.expertflow.com`)

| Attribute | Status |
|-----------|--------|
| Hosting | GCP VM |
| URL | `https://vault.expertflow.com` |
| Seal status | Unknown — may require unseal after restart |
| Auth methods | Likely token-only; Entra ID not configured |
| Secret engines | Likely KV v1/v2 only; dynamic secrets not enabled |
| Audit logging | Unknown / not configured |
| Backup | Unknown |
| **Usage** | **Low — teams not onboarded** |

### 2.4 Vaultwarden

| Attribute | Status |
|-----------|--------|
| Deployment | **Not deployed** |
| Hosting | TBD (recommendation: Hetzner) |
| Domain | TBD (`secrets.expertflow.com`) |
| Organization | Not created |
| Collections | Not defined |
| Users | 0 |

---

## 3. Target Architecture: Two-Vault Strategy

### 3.1 Architectural Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IDENTITY & ACCESS LAYER                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Microsoft Entra ID  <--->  Google Workspace Groups  <--->  Keycloak   │  │
│  │       (Central IDP)        (Role-based groups)        (SSO/MFA)       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
                    ▼                                   ▼
┌─────────────────────────────────┐   ┌─────────────────────────────────────┐
│   HASHICORP VAULT               │   │   VAULTWARDEN                       │
│   vault.expertflow.com          │   │   secrets.expertflow.com            │
│   (GCP)                         │   │   (Hetzner)                         │
├─────────────────────────────────┤   ├─────────────────────────────────────┤
│ • SSH keys (cloud + lab)        │   │ • SaaS admin passwords              │
│ • DB credentials                │   │ • iLO/iDRAC web UI passwords        │
│ • API tokens (LLM, cloud)       │   │ • Hypervisor web UI passwords       │
│ • Dynamic cloud creds           │   │ • Lab VM console passwords          │
│ • TLS certificates (PKI)        │   │ • Network switch admin passwords    │
│ • CI/CD secrets (AppRole)       │   │ • Shared email accounts             │
│ • Encryption keys (Transit)     │   │ • Break-glass emergency creds       │
│ • Lab VM SSH keys (signed)      │   │ • Domain registrar logins           │
│ • iLO/iDRAC API keys            │   │ • Banking / payroll portals         │
│ • SNMP communities              │   │ • Social media accounts             │
└─────────────────────────────────┘   └─────────────────────────────────────┘
         │                                         │
         ▼                                         ▼
    ┌─────────┐                              ┌─────────┐
    │ Machines│                              │ Humans  │
    │ CI/CD   │                              │ Browser │
    │ Scripts │                              │ Mobile  │
    └─────────┘                              └─────────┘
```

### 3.2 Separation of Concerns

| Criterion | HashiCorp Vault | Vaultwarden |
|-----------|-----------------|-------------|
| **Primary consumer** | Machines, applications, CI/CD pipelines | Humans (employees) |
| **Access method** | API / CLI (`vault kv get`) | Browser extension, mobile app |
| **Auth method** | JWT (Entra ID), AppRole, Kubernetes | Master password + optional 2FA |
| **Secret lifetime** | Short-lived (leased), auto-rotated | Long-lived, manual rotation |
| **Audit granularity** | Every read/write logged with identity | Organization-level event log |
| **Best for** | SSH keys, DB creds, API tokens, certs | Web passwords, shared accounts |
| **Local lab use** | SSH key injection, dynamic DB creds | iLO web UI, hypervisor GUI, switch GUI |

---

## 4. Local Datacenter & Lab VM Secret Management

Local infrastructure requires special attention because it lacks cloud-native IAM, audit logs, or API-driven access control. This section defines how Vault and Vaultwarden cover the full local stack.

### 4.1 Local Infrastructure Secret Categories

```
Local Datacenter Stack
│
├── Physical Layer
│   ├── iLO / iDRAC / IPMI (out-of-band management)
│   ├── BIOS / UEFI passwords
│   ├── KVM-over-IP switches
│   └── PDU (power distribution unit) web interfaces
│
├── Hypervisor Layer
│   ├── Proxmox / ESXi / XenServer web UI
│   ├── Hypervisor SSH / console
│   ├── Storage (SAN/NAS) management
│   └── vCenter / Proxmox cluster credentials
│
├── Virtual Machine Layer
│   ├── Root / administrator passwords
│   ├── SSH key pairs (host-specific vs. shared)
│   ├── Sudoers / local admin accounts
│   ├── Service accounts (DB, app runtime)
│   └── Application secrets inside VMs
│
└── Network Layer
    ├── Core switch admin passwords
    ├── Access switch admin passwords
    ├── VLAN configuration passwords
    ├── SNMP read/write communities
    └── Firewall / router admin credentials
```

### 4.2 Mapping to Vault vs. Vaultwarden

| Asset | Secret Type | Store | Path / Collection | Rationale |
|-------|-------------|-------|-------------------|-----------|
| **iLO/iDRAC** | Web admin password | **Vaultwarden** | `Admin Collection > iLO-iDRAC` | Humans log into web UI |
| **iLO/iDRAC** | API key / Redfish token | **Vault** | `secret-standard/lab/ilo/<host>` | Automation (firmware updates) |
| **BIOS** | Setup password | **Vaultwarden** | `Admin Collection > Physical` | Rarely changed, human-only |
| **Hypervisor** | Web UI password | **Vaultwarden** | `Admin Collection > Hypervisors` | Human GUI access |
| **Hypervisor** | API token / SSH key | **Vault** | `secret-standard/lab/hv/<host>` | Automation (VM provisioning) |
| **Lab VM** | Root password | **Vaultwarden** | `Dev Collection > Lab VMs` | Emergency console access |
| **Lab VM** | SSH private key | **Vault** | `secret-standard/lab/ssh/<vm>` | Standard SSH access |
| **Lab VM** | Service DB password | **Vault** | `secret-standard/lab/db/<service>` | App runtime injection |
| **Network Switch** | Admin password | **Vaultwarden** | `Admin Collection > Network` | Human GUI/CLI access |
| **Network Switch** | SNMP community | **Vault** | `secret-standard/lab/snmp/<switch>` | Monitoring automation |
| **PDU** | Web admin password | **Vaultwarden** | `Admin Collection > Physical` | Rare human access |
| **KVM-over-IP** | Admin password | **Vaultwarden** | `Admin Collection > Physical` | Remote physical access |

### 4.3 Lab VM SSH Key Strategy

**Problem:** Reusing the same SSH key across all lab VMs means one compromise = full lab access.

**Solution: Per-Host SSH Keys + Vault SSH OTP**

```
┌─────────────────────────────────────────────────────────────┐
│                 LAB VM SSH ACCESS MODEL                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Option A: Per-VM SSH Key Pairs (Recommended for Lab)       │
│  ─────────────────────────────────────────────────────      │
│  vault.expertflow.com                                       │
│  ├── secret-standard/lab/ssh/vm-prod-db-01/               │
│  │   ├── private_key  (read: developers, support)          │
│  │   └── public_key   (pre-installed on VM)                │
│  ├── secret-standard/lab/ssh/vm-prod-app-01/              │
│  │   └── ...                                               │
│  └── secret-standard/lab/ssh/vm-lab-jenkins-01/           │
│      └── ...                                                │
│                                                             │
│  Option B: Vault SSH OTP (Advanced)                         │
│  ─────────────────────────────────────────────────────      │
│  Vault acts as SSH CA — signs short-lived SSH certificates  │
│  ┌──────────┐     ┌──────────┐     ┌──────────────────┐     │
│  │  User    │────>│  Vault   │────>│  SSH CA signed   │     │
│  │  (CLI)   │     │  (auth)  │     │  cert (5m TTL)   │     │
│  └──────────┘     └──────────┘     └──────────────────┘     │
│                                               │             │
│                                               ▼             │
│                                        ┌──────────────┐     │
│                                        │  Lab VM      │     │
│                                        │  (trusts CA) │     │
│                                        └──────────────┘     │
│                                                             │
│  -> No persistent keys to steal. Audit trail of every login.│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Recommendation:** Start with **Option A** (per-VM keys in Vault KV). Migrate to **Option B** (Vault SSH OTP/CA) in Phase 4 as lab automation maturity increases.

### 4.4 iLO/iDRAC & Physical Infrastructure Policy

| Policy | Rule | Rationale |
|--------|------|-----------|
| **Network Isolation** | iLO/iDRAC must be on a dedicated management VLAN (no direct internet) | Prevents external BMC exploitation |
| **Password Complexity** | 32+ character random, unique per host | BMCs are high-value targets |
| **Access Logging** | Enable iLO/iDRAC audit logging to syslog server | Detect unauthorized access |
| **Firmware Updates** | Quarterly review; patch critical CVEs within 14 days | BMC vulnerabilities are common |
| **Two-Person Rule** | Break-glass physical access requires 2 infra-admins | Prevents insider threat |
| **Certificate Validation** | Replace default iLO/iDRAC TLS certs with internal CA certs | Prevent MITM on BMC web UI |

### 4.5 Network Equipment Credentials

Network switches (documented in ITAM `Ports Detail` sheet) are often forgotten in secret management.

```
Vaultwarden: Admin Collection > Network
├── Core Switch (core-sw-01.expertflow.local)
│   ├── Admin password
│   ├── Enable/secret password
│   └── Console port password
├── Access Switches (access-sw-<rack>)
│   └── ...
└── Firewall / Router (fw-01.expertflow.local)
    └── Admin password

Vault: secret-standard/lab/network/
├── snmp/
│   ├── read-community  (monitoring)
│   └── write-community (infra-admins only)
├── ssh/
│   └── switch-automation-key  (Ansible/Rancid backups)
└── api/
    └── firewall-api-token  (automation)
```

---

## 5. Vault Configuration & Policy Design

### 5.1 Authentication Methods

```
vault.expertflow.com/auth/
├── jwt/              # Microsoft Entra ID (primary human auth)
├── approle/          # CI/CD pipelines, GitHub Actions
├── kubernetes/       # K8s service accounts (if EFCX K8s uses Vault)
└── token/            # Emergency break-glass only
```

#### Entra ID JWT Configuration
```bash
# Enable JWT auth
vault auth enable jwt

# Configure for Microsoft Entra ID
vault write auth/jwt/config \
  oidc_discovery_url="https://login.microsoftonline.com/<tenant-id>/v2.0" \
  oidc_client_id="<vault-app-registration-client-id>" \
  oidc_client_secret="<secret>" \
  default_role="developers"
```

#### AppRole for CI/CD
```bash
# Enable AppRole for GitHub Actions / Jenkins
vault auth enable approle

# Role for EFInternalTools CI
vault write auth/approle/role/ef-internal-tools-ci \
  token_policies="ci-read-dev-secrets" \
  secret_id_ttl=0 \
  token_ttl=1h \
  token_max_ttl=4h
```

### 5.2 Secret Engines

| Engine | Path | Purpose | Status |
|--------|------|---------|--------|
| KV v2 | `secret-standard/` | Static secrets (API keys, passwords) | **Enable & populate** |
| KV v2 | `secret-ef-agentic/` | Agentic tooling secrets | **Enable & populate** |
| PKI | `pki/` | Internal TLS certificate issuance | **Enable (Phase 3)** |
| SSH | `ssh/` | SSH OTP / signed certificates for lab | **Enable (Phase 4)** |
| Database | `database/` | Dynamic DB credentials | **Enable (Phase 3)** |
| AWS | `aws/` | Dynamic AWS credentials | **Evaluate (Phase 5)** |
| Transit | `transit/` | Encryption as a service | **Evaluate (Phase 5)** |

### 5.3 KV v2 Path Structure

```
secret-standard/
├── dev/
│   ├── do/
│   │   ├── ssh-keys/
│   │   └── api-token
│   ├── gcp/
│   │   └── service-account-key
│   └── github/
│       └── actions-token
│
├── marketing/
│   ├── hubspot/
│   │   └── api-key
│   ├── mautic/
│   │   └── db-credentials
│   └── wordpress/
│       └── admin-password        # Reference to Vaultwarden item
│
├── hr/
│   └── bs4/
│       └── service-account
│
├── llm/
│   ├── kimi/
│   │   └── api-key
│   ├── deepseek/
│   │   └── api-key
│   └── claude/
│       └── api-key               # Limited access
│
├── customers/
│   ├── mea/
│   │   └── a1-project/
│   │       └── ssh-keys/
│   └── eu/
│       └── ...
│
├── infra/
│   ├── cloudflare/
│   │   └── api-token
│   ├── dns/
│   │   └── tsig-key
│   └── monitoring/
│       └── grafana-admin
│
├── lab/                          # ★ NEW: Local datacenter
│   ├── ilo/
│   │   ├── lab-server-01/
│   │   │   ├── api-key
│   │   │   └── ip-address
│   │   └── lab-server-02/
│   │       └── ...
│   ├── hypervisor/
│   │   ├── proxmox-01/
│   │   │   ├── api-token
│   │   │   └── ssh-key
│   │   └── ...
│   ├── ssh/
│   │   ├── vm-lab-db-01/
│   │   │   ├── private-key
│   │   │   └── public-key
│   │   └── ...
│   ├── db/
│   │   ├── lab-postgres/
│   │   │   ├── username
│   │   │   └── password
│   │   └── ...
│   ├── network/
│   │   ├── snmp/
│   │   │   ├── read-community
│   │   │   └── write-community
│   │   └── ssh/
│   │       └── automation-key
│   └── physical/
│       ├── bios-password
│       ├── kvm-over-ip/
│       │   └── admin-password
│       └── pdu/
│           └── admin-password
│
└── breakglass/
    ├── vault-unseal/
    │   └── (Shamir shares — see §7.1)
    ├── cloud-emergency/
    │   └── ...
    └── lab-emergency/
        └── ilo-master-credentials

secret-ef-agentic/
├── llm-proxy/
│   └── litellm-api-key
├── jira/
│   └── automation-token
├── confluence/
│   └── automation-token
└── postman/
    └── api-key
```

### 5.4 Access Control Policies (ACLs)

```hcl
# policy: lab-secrets-read.hcl
# Assigned to: developers, support, infra-admins
path "secret-standard/lab/ssh/*" {
  capabilities = ["read", "list"]
}

path "secret-standard/lab/db/*" {
  capabilities = ["read", "list"]
}

path "secret-standard/lab/hypervisor/*" {
  capabilities = ["read", "list"]
}

# Deny access to physical layer and break-glass
path "secret-standard/lab/physical/*" {
  capabilities = ["deny"]
}

path "secret-standard/lab/ilo/*" {
  capabilities = ["deny"]
}
```

```hcl
# policy: lab-infra-admin.hcl
# Assigned to: infra-admins only
path "secret-standard/lab/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

```hcl
# policy: network-secrets-read.hcl
# Assigned to: infra-admins, network-admin (if created)
path "secret-standard/lab/network/*" {
  capabilities = ["read", "list"]
}
```

### 5.5 Role-to-Policy Mapping

| Entra ID / Google Group | Vault Policies | Access Scope |
|------------------------|----------------|--------------|
| `developers` | `dev-secrets-read`, `lab-secrets-read`, `llm-all-read` | Cloud dev + lab VMs + Kimi/DeepSeek |
| `marketing` | `marketing-secrets-read` | HubSpot, Mautic, WordPress |
| `hr-finance` | `hr-secrets-read` | BS4, payroll |
| `support` | `support-secrets-read`, `customer-secrets-read` | OTRS, customer secrets (region-scoped) |
| `infra-admins` | `vault-admin`, `lab-infra-admin`, `network-secrets-read`, `breakglass-read` | **Full Vault + all lab infrastructure** |
| `agentic-devs` | `agentic-secrets-read`, `dev-secrets-read`, `llm-claude-read` | EFAgenticSpec, Claude API |
| `llm-users-senior` | `llm-claude-read` | Claude API only |
| `llm-users-all` | `llm-all-read` | Kimi, DeepSeek |
| `presales` | `presales-secrets-read`, `customer-secrets-read` | Demo envs, customer secrets |

---

## 6. Vaultwarden Configuration & Collections

### 6.1 Deployment Specification

| Attribute | Value |
|-----------|-------|
| **Provider** | Hetzner Cloud |
| **VM Type** | CX11 (1 vCPU, 2 GB RAM) |
| **Cost** | ~€4.51/month |
| **OS** | Ubuntu 24.04 LTS |
| **Domain** | `secrets.expertflow.com` |
| **Reverse Proxy** | Caddy (auto HTTPS) or nginx |
| **SSL** | Let's Encrypt |
| **Backup** | Daily Hetzner volume snapshot + weekly encrypted export to GCP |
| **SMTP** | `smtp.expertflow.com` (for invites, 2FA alerts) |

### 6.2 Security Hardening

```yaml
# docker-compose.yml
services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: vaultwarden
    restart: always
    environment:
      # —— Core ——
      - WEBSOCKET_ENABLED=true
      - WEB_VAULT_ENABLED=true
      
      # —— Signup & Access ——
      - SIGNUPS_ALLOWED=false           # Admin invites only
      - SIGNUPS_VERIFY=true             # Require email verification
      - INVITATIONS_ALLOWED=true        # Admin can invite
      - EMERGENCY_ACCESS_ALLOWED=true   # Break-glass inheritance
      
      # —— Admin ——
      - ADMIN_TOKEN_FILE=/run/secrets/admin_token
      
      # —— 2FA Enforcement ——
      - REQUIRE_EMAIL_2FA=false         # Evaluate after rollout
      - REQUIRE_ORG_2FA=false           # Evaluate after rollout
      
      # —— SMTP ——
      - SMTP_HOST=smtp.expertflow.com
      - SMTP_PORT=587
      - SMTP_FROM=security@expertflow.com
      - SMTP_FROM_NAME="Expertflow Security"
      - SMTP_SECURITY=starttls
      
      # —— Security Headers ——
      - DISABLE_ICON_DOWNLOAD=false
      - DISABLE_2FA_REMEMBER=false
      
      # —— Logging ——
      - LOG_LEVEL=warn
      - EXTENDED_LOGGING=true
      
    volumes:
      - vw-data:/data
    secrets:
      - admin_token
    ports:
      - "127.0.0.1:8080:80"            # Bind to localhost; Caddy reverse-proxies
    
  caddy:
    image: caddy:2-alpine
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config

volumes:
  vw-data:
  caddy-data:
  caddy-config:

secrets:
  admin_token:
    file: ./secrets/admin_token.txt   # 64+ char random string
```

```
# Caddyfile
secrets.expertflow.com {
    reverse_proxy vaultwarden:80
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
}
```

### 6.3 Organization & Collections (Detailed)

```
Expertflow Organization
│
├── 🔒 Admin Collection
│   ├── Cloudflare Dashboard (dash.cloudflare.com)
│   ├── Domain Registrar (various TLDs)
│   ├── iLO/iDRAC Master List (all BMCs)
│   ├── Hypervisor Web Consoles (Proxmox/ESXi)
│   ├── Network Switch Admin Panel
│   ├── PDU Management Interfaces
│   ├── Vault Root Break-Glass
│   └── Provider Admin Consoles (DO, AWS, GCP, Azure)
│
├── 💻 Dev Collection
│   ├── GitHub Organization Admin
│   ├── Docker Hub Team
│   ├── Internal Tool Admin Panels
│   ├── Lab VM Console Passwords (emergency)
│   └── Jenkins/CI Admin
│
├── 📢 Marketing Collection
│   ├── HubSpot Admin
│   ├── Mautic Admin
│   ├── WordPress Admin (www.expertflow.com)
│   ├── Social Media Accounts
│   └── Analytics / Ads Platforms
│
├── 💰 Finance Collection
│   ├── BS4 Admin
│   ├── Payroll Portal
│   ├── Banking / Wire Transfer
│   └── Invoice / Accounting SaaS
│
├── 🎧 Support Collection
│   ├── OTRS Admin
│   ├── Customer Portal Admin
│   └── Internal Ticketing Systems
│
├── 🤖 Agentic Collection
│   ├── Postman Team Admin
│   ├── Jira Automation Account
│   ├── Confluence Automation Account
│   └── LiteLLM Admin Panel
│
├── 🔬 Lab Infrastructure Collection
│   ├── iLO/iDRAC Per-Host (read-only for devs)
│   ├── Hypervisor Read-Only Accounts
│   ├── Lab VM Root Passwords (emergency)
│   └── Network Monitoring Read-Only
│
└── 🆘 Break-Glass Collection
    ├── Emergency Server Access (all providers)
    ├── Emergency iLO Credentials
    ├── Emergency Domain/DNS Access
    ├── Emergency Vault Unseal Contact Sheet
    └── Disaster Recovery Checklist
```

### 6.4 2FA Enforcement Matrix

| Collection | 2FA Required | Notes |
|------------|-------------|-------|
| Admin Collection | ✅ Mandatory | All infra-admins must have 2FA |
| Break-Glass Collection | ✅ Mandatory + physical token (YubiKey) | Highest sensitivity |
| Dev Collection | ✅ Mandatory | Developers handle production-adjacent creds |
| Finance Collection | ✅ Mandatory | SOX/compliance consideration |
| Marketing Collection | ⚠️ Recommended | Lower risk but good hygiene |
| Support Collection | ⚠️ Recommended | Customer data access |
| Agentic Collection | ✅ Mandatory | LLM tokens can be expensive if stolen |
| Lab Infrastructure | ✅ Mandatory | Physical infrastructure access |

---

## 7. Root Token Custody & Break-Glass

### 7.1 Vault Unseal Key Distribution (Shamir's Secret Sharing)

Vault uses **5 key shares** with a **3-of-5 threshold** for unsealing.

| Share # | Holder | Role | Storage |
|---------|--------|------|---------|
| 1 | `imran.ali@expertflow.com` | IT Lead / Security Lead | Hardware-encrypted USB (Personal safe) |
| 2 | `zaeem.ahmad@expertflow.com` | Infra Admin | Password manager (personal, non-EF) |
| 3 | `asjad.nawaz@expertflow.com` | Infra Admin | Hardware-encrypted USB (Personal safe) |
| 4 | `amir.ayub@expertflow.com` | Infra Admin | Printed paper in sealed envelope (Home safe) |
| 5 | **Offline Backup** | CEO / Board designated | Bank safe deposit box |

**Rules:**
- Unseal only during: Vault restart, disaster recovery, key rotation
- Minimum 3 people must be physically present or on a recorded video call
- Document unseal reason in incident log
- Rotate unseal keys annually or after any suspected compromise

### 7.2 Root Token Policy

```
┌─────────────────────────────────────────────┐
│           ROOT TOKEN LIFECYCLE              │
├─────────────────────────────────────────────┤
│ 1. Root token is generated during init      │
│ 2. Immediately used to create admin policy  │
│ 3. Root token is REVOKED within 1 hour      │
│ 4. Admin tokens used for day-to-day ops     │
│ 5. Root token regenerated only for:         │
│    - Policy recovery (admin lockout)        │
│    - Auth method disaster recovery          │
│    - Quarterly audit (with 3-of-5 unseal)   │
└─────────────────────────────────────────────┘
```

### 7.3 Break-Glass Procedures

#### Scenario A: Vault is Sealed (Unseal Required)
```
1. Page the 5 key holders
2. Schedule emergency call (recorded)
3. 3 holders provide shares via secure channel
4. Unseal Vault: vault operator unseal
5. Verify all mounts and auth methods
6. Document in security incident log
7. Re-seal shares in respective storage
```

#### Scenario B: Entra ID Outage (No JWT Auth)
```
1. Use emergency AppRole token (stored in break-glass collection)
2. Or: Use emergency token with `vault-admin` policy
3. Token is time-limited (1h TTL)
4. Document usage in audit log
```

#### Scenario C: Lab Infrastructure Total Lockout
```
1. Retrieve emergency iLO credentials from Vaultwarden Break-Glass
2. Access via iLO remote console (out-of-band)
3. Log in with emergency local admin account
4. Restore Vault / Vaultwarden connectivity
5. Rotate all break-glass credentials after resolution
```

---

## 8. Secret Lifecycle & Rotation

### 8.1 Rotation Schedule

| Secret Category | Rotation Frequency | Method | Owner |
|-----------------|-------------------|--------|-------|
| Cloud API keys (DO, AWS, GCP, Azure) | 90 days | Vault dynamic secrets or manual | Infra |
| Database credentials (cloud) | 90 days | Vault database engine | Infra |
| Database credentials (lab) | 90 days | Manual rotation + update Vault KV | Infra |
| SSH key pairs (cloud VMs) | 180 days | Terraform / Ansible regenerate | Infra |
| SSH key pairs (lab VMs) | 180 days | Ansible playbook + Vault KV update | Infra |
| iLO/iDRAC passwords | 90 days | Vaultwarden generate + apply via Redfish | Infra |
| Hypervisor passwords | 90 days | Vaultwarden generate + manual apply | Infra |
| Network switch passwords | 90 days | Vaultwarden generate + manual apply | Infra |
| SaaS admin passwords | 90 days | Vaultwarden generate + manual update | IT |
| LLM API tokens | On offboarding | Vault KV update | Infra |
| TLS certificates | Auto (30 days before expiry) | Vault PKI engine or certbot | Infra |
| CI/CD AppRole secrets | 90 days | `vault write -f auth/approle/role/...` | DevOps |
| Break-glass credentials | 90 days + after each use | Manual, 2-person rule | Security Lead |
| Vault unseal keys | Annually | `vault operator rekey` | 3-of-5 holders |

### 8.2 Rotation Runbook: Lab VM Root Password

```bash
#!/bin/bash
# rotate-lab-vm-password.sh
# Run from admin workstation with Vault/Vaultwarden CLI access

VM_NAME=$1
NEW_PASSWORD=$(openssl rand -base64 32)

# 1. Update Vaultwarden (human emergency access)
bw login
bw get item "Lab VM - $VM_NAME" | jq ".login.password=\"$NEW_PASSWORD\"" | bw encode | bw edit item

# 2. Update Vault KV (automation reference — if needed)
vault kv put secret-standard/lab/vms/$VM_NAME/root-password password="$NEW_PASSWORD"

# 3. Apply to VM via SSH (using existing Vault SSH key)
ssh -i $(vault kv get -field=private_key secret-standard/lab/ssh/$VM_NAME) \
  root@$VM_NAME.expertflow.local \
  "echo 'root:$NEW_PASSWORD' | chpasswd"

# 4. Verify
ssh -i ... root@$VM_NAME.expertflow.local "whoami"

# 5. Log rotation event
echo "$(date): Rotated root password for $VM_NAME" >> /var/log/secret-rotations.log
```

### 8.3 Secret Lifecycle Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   CREATE    │--->│   STORE     │--->│    USE      │--->│   ROTATE    │
└─────────────┘    └─────────────┘    └─────────────┘    └──────┬──────┘
     │                  │                  │                      │
     ▼                  ▼                  ▼                      ▼
Generate unique    Vault KV or      Machine: API/CLI      Auto/manual
32-64 char rand    Vaultwarden      Human: Browser ext.   per schedule
Store in Vault     Audit logged     Least privilege       Old = revoked
Never in email     TTL enforced     Track access          New = active
```

---

## 9. Integration with ITAM & Employee Lifecycle

### 9.1 ITAM Integration

The ITAM app (`itsm.expertflow.com`) should be the **system of record for asset inventory**, while Vault/Vaultwarden manage the **secrets attached to those assets**.

| ITAM Asset Type | ITAM Record Contains | Secret Stored In |
|-----------------|----------------------|------------------|
| Cloud VM | Provider, IP, FQDN, Owner | Vault: SSH keys, API tokens |
| Lab Server | Rack, model, serial, iLO IP | Vaultwarden: iLO password; Vault: API key |
| Lab VM | Host, memory, DNS | Vaultwarden: root password; Vault: SSH key |
| Network Switch | Rack, ports, management IP | Vaultwarden: admin password; Vault: SNMP |
| SaaS Subscription | URL, owner, cost | Vaultwarden: admin password; Vault: API key |

**Proposed Enhancement:** Add a `secret_reference` field to ITAM asset records:
```
ITAM Asset Record: "lab-vm-db-01"
  ├── secret_vault_path: "secret-standard/lab/ssh/vm-db-01"
  ├── secret_vaultwarden_id: "uuid-of-vaultwarden-item"
  └── secret_last_rotated: "2026-06-15"
```

### 9.2 Employee Onboarding: Secret Provisioning

```
New hire joins Expertflow
        │
        ▼
HR creates account in Entra ID + Google Workspace
        │
        ▼
IT assigns to role group(s) in Google Workspace
        │
        ├───> Group: developers
        │     ├── Auto-provision: Vault JWT policy (dev-secrets-read, lab-secrets-read)
        │     ├── Email invitation: Vaultwarden (Dev Collection + Lab Infrastructure Collection)
        │     └── API token delivered: Kimi, DeepSeek (Vault KV)
        │
        ├───> Group: marketing
        │     ├── Auto-provision: Vault JWT policy (marketing-secrets-read)
        │     └── Email invitation: Vaultwarden (Marketing Collection)
        │
        └───> Group: infra-admins
              ├── Auto-provision: Vault JWT policy (vault-admin, lab-infra-admin)
              └── Email invitation: Vaultwarden (Admin + Lab + Break-Glass)
        │
        ▼
Employee receives:
  1. Welcome email with Vaultwarden invitation link
  2. Confluence guide: "How to use Vault & Vaultwarden"
  3. ITAM dashboard access (if applicable)
  4. LLM API token access (if in llm-users-* group)
```

### 9.3 Employee Offboarding: Secret Revocation

**Target: 100% revocation within 4 hours of termination notice.**

| Step | Action | Tool | Owner |
|------|--------|------|-------|
| 1 | Disable Entra ID account | Microsoft Admin Center | IT |
| 2 | Remove from all Google Workspace groups | Google Admin Console | IT |
| 3 | Revoke Vault JWT token / lease | `vault token revoke` | Infra |
| 4 | Disable Vaultwarden account | Vaultwarden Admin Panel | Infra |
| 5 | Rotate any LLM API tokens they accessed | Vault KV update | Infra |
| 6 | Review Vault audit log for last 30 days | Vault audit log | Security |
| 7 | Remove from ITAM (if ITAM user) | ITAM admin panel | IT |
| 8 | Verify no orphaned SSH keys on lab VMs | Ansible audit script | Infra |
| 9 | Document in offboarding checklist | Confluence/ITAM | HR |

### 9.4 Lab VM Access Request Workflow

For temporary or project-specific lab VM access:

```
Developer needs access to lab VM for customer project
        │
        ▼
Submit request in ITAM or Jira (#it-requests)
        │
        ▼
IT Ops reviews and approves
        │
        ▼
┌────────────────────────────────────────────────────────────┐
│  IF temporary (<= 30 days):                                │
│    • Vault: Create wrapped token with lab-secrets-read    │
│    • Token TTL = requested duration                        │
│    • Auto-expires, no manual cleanup needed               │
│                                                            │
│  IF permanent:                                             │
│    • Add user to Google Workspace group: developers       │
│    • Auto-inherits Vault JWT policy                        │
│    • Vaultwarden invitation to Lab Infrastructure Collection│
└────────────────────────────────────────────────────────────┘
        │
        ▼
Developer authenticates to Vault:
  vault login -method=jwt role=developers
  vault kv get secret-standard/lab/ssh/vm-customer-a1
```

---

## 10. Audit, Monitoring & Compliance

### 10.1 Vault Audit Logging

```bash
# Enable file audit device
vault audit enable file file_path=/var/log/vault/audit.log

# Enable syslog for SIEM integration
vault audit enable syslog tag="vault-audit" facility="AUTH"
```

**Log Retention:**
| Log Type | Retention | Storage |
|----------|-----------|---------|
| Vault audit logs | 1 year | Secured log server (not on Vault VM) |
| Vaultwarden event log | 1 year | Exported to GCP Cloud Storage |
| Secret rotation log | 2 years | ITAM / BS4 |
| Access request log | 2 years | Jira / ITAM |

### 10.2 Alerting Rules

| Alert Condition | Severity | Response |
|-----------------|----------|----------|
| Vault seal status = sealed | Critical | Page all infra-admins |
| Vaultwarden down >5 min | Critical | Page infra-admins |
| Break-glass secret accessed | Critical | Page security lead + log review |
| Vault root token generated | High | Immediate investigation |
| Failed auth >10 attempts / 5 min | Medium | Review source IP |
| Secret TTL >90 days (not rotated) | Medium | Ticket to owner |
| Unknown IP accessing Vault API | Medium | Review and potentially block |
| Lab VM root password >90 days | Low | Auto-reminder to IT |

### 10.3 Quarterly Compliance Review

| Check | Evidence | Owner |
|-------|----------|-------|
| All Vault policies reviewed | `vault policy list` + diff | Security |
| All Vaultwarden collections reviewed | Admin panel export | Security |
| Orphaned accounts removed | Entra ID + Vault + VW cross-check | IT |
| Unused secrets archived | `vault kv list` + last-access audit | Infra |
| Rotation schedule compliance | Rotation log review | Infra |
| iLO/iDRAC firmware current | Vendor CVE feed comparison | Infra |
| Lab VM password audit | Ansible scan for weak/default passwords | Infra |
| Network switch password audit | Config review + password age check | Infra |

---

## 11. Implementation Roadmap

### Phase 1: Vault Hardening (Week 1)

| # | Task | Owner | Effort | Output |
|---|------|-------|--------|--------|
| 1.1 | Confirm Vault seal status; document unseal procedure | Infra | 2h | Runbook |
| 1.2 | Designate 5 unseal key holders; distribute shares securely | Security Lead | 4h | Key custody log |
| 1.3 | Enable Entra ID JWT auth; configure role mapping | Infra | 4h | Auth configured |
| 1.4 | Create Vault ACL policies (all 9+ policies) | Infra | 4h | Policies in repo |
| 1.5 | Enable KV v2 at `secret-standard/` and `secret-ef-agentic/` | Infra | 2h | Engines ready |
| 1.6 | Enable audit logging (file + syslog) | Infra | 2h | Logs flowing |
| 1.7 | **Create lab-specific KV paths** (`secret-standard/lab/*`) | Infra | 2h | Lab structure ready |

**Phase 1 Gate:** Vault is hardened, auth works, policies defined, audit enabled.

### Phase 2: Vaultwarden Deployment (Week 1–2)

| # | Task | Owner | Effort | Output |
|---|------|-------|--------|--------|
| 2.1 | Provision Hetzner CX11 VM | Infra | 1h | VM running |
| 2.2 | Deploy Vaultwarden + Caddy (docker-compose) | Infra | 2h | `secrets.expertflow.com` live |
| 2.3 | Configure DNS A record | Infra | 30m | DNS propagated |
| 2.4 | Create Expertflow Organization + 8 collections | Infra | 1h | Collections ready |
| 2.5 | Invite infra-admins; enforce 2FA | Infra | 1h | Core team onboarded |
| 2.6 | **Create Lab Infrastructure Collection** | Infra | 1h | Lab passwords organized |
| 2.7 | Configure daily snapshots + weekly encrypted export | Infra | 2h | Backup routine |

**Phase 2 Gate:** Vaultwarden operational. Infra team onboarded. Backups working.

### Phase 3: Secret Migration (Week 2–3)

| # | Task | Owner | Effort | Output |
|---|------|-------|--------|--------|
| 3.1 | **Audit all password spreadsheets / docs / chats** | IT + Infra | 8h | Inventory of secrets |
| 3.2 | Categorize: Vault (machine) vs Vaultwarden (human) | Infra | 2h | Migration plan |
| 3.3 | Generate new unique passwords for all shared accounts | Infra | 4h | Password list (temporary) |
| 3.4 | Populate Vault KV paths (cloud + lab) | Infra | 8h | Secrets in Vault |
| 3.5 | Populate Vaultwarden collections | IT | 8h | Passwords in VW |
| 3.6 | **Populate Lab Infrastructure secrets** (iLO, hypervisor, VMs, network) | Infra | 4h | Lab secured |
| 3.7 | Update all services to fetch from Vault | Infra + Dev | 16h | Apps using Vault |
| 3.8 | Securely destroy old spreadsheets | IT | 1h | Evidence of destruction |
| 3.9 | Announce: "Old passwords invalid as of [DATE]" | HR + IT | — | Communication sent |

**Phase 3 Gate:** Zero plaintext secrets remain. All creds in vaults.

### Phase 4: Automation & Advanced Features (Week 4–6)

| # | Task | Owner | Effort | Output |
|---|------|-------|--------|--------|
| 4.1 | Terraform Vault config as code | Infra | 8h | `infra/vault/` in repo |
| 4.2 | CI/CD AppRole setup (GitHub Actions, Jenkins) | DevOps | 4h | Pipelines using Vault |
| 4.3 | Vault PKI engine for internal TLS certs | Infra | 8h | Auto-cert issuance |
| 4.4 | **Ansible playbook: Lab VM SSH key rotation** | Infra | 8h | Automated rotation |
| 4.5 | **iLO/iDRAC Redfish automation for password rotation** | Infra | 8h | Automated BMC rotation |
| 4.6 | Enable Vault SSH OTP engine (evaluate) | Infra | 4h | PoC for lab |
| 4.7 | Onboard all role groups to Vault JWT | Infra | 4h | All teams have access |

**Phase 4 Gate:** Automation reduces manual secret ops by 70%.

### Phase 5: Optimization (Month 3–6)

| # | Task | Owner | Effort | Output |
|---|------|-------|--------|--------|
| 5.1 | Evaluate Vault database secrets engine for lab DBs | Infra | 8h | Dynamic DB creds |
| 5.2 | Integrate ITAM asset records with secret references | Dev | 16h | Linked inventory |
| 5.3 | Automate cost extraction for secret infrastructure | Finance | 8h | Budget tracking |
| 5.4 | Quarterly compliance review process | Security | 4h | Scheduled reviews |
| 5.5 | Disaster recovery drill (Vault seal + restore) | Infra | 4h | Validated recovery |
| 5.6 | **Lab infrastructure security audit** (penetration test) | Security | 16h | Audit report |

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation | Owner |
|------|------------|--------|------------|-------|
| Vault unseal keys lost / holder unavailable | Low | Critical | 3-of-5 threshold; offline backup in bank safe | Security Lead |
| Vaultwarden VM compromised | Low | Critical | Daily snapshots; encrypted exports; minimal attack surface | Infra |
| Spreadsheet copies survive "deletion" | Medium | High | Secure erase (not just delete); audit file shares | IT |
| Lab VM root password brute-forced | Medium | High | Unique per-VM passwords; network isolation; fail2ban | Infra |
| iLO/iDRAC exploited (CVE) | Medium | Critical | Quarterly firmware updates; VLAN isolation; strong passwords | Infra |
| Employee offboarding misses Vault access | Medium | High | Automated revocation via group removal; 30-day audit | IT |
| Vault JWT auth fails (Entra ID outage) | Low | High | Emergency AppRole tokens in break-glass | Infra |
| Network switch default/weak passwords | Medium | High | Audit all switches; enforce unique passwords; document in VW | Infra |
| Hypervisor compromise via weak creds | Low | Critical | Strong unique passwords; 2FA where supported; network isolation | Infra |

---

## 13. Quick Reference

### 13.1 URLs & Access

| Service | URL | Admin | Purpose |
|---------|-----|-------|---------|
| HashiCorp Vault | `https://vault.expertflow.com` | `infra-admins` | Infra secrets, API tokens, SSH keys |
| Vaultwarden | `https://secrets.expertflow.com` | `infra-admins` | Human passwords, shared accounts |
| ITAM Portal | `https://itsm.expertflow.com` | `IT_ASSET_MANAGER` | Asset inventory, requests, tickets |
| Entra ID Admin | `https://admin.cloud.microsoft/` | `imran.ali` | Identity provider |
| Google Admin | `https://admin.google.com` | IT | Workspace groups |

### 13.2 Emergency Contacts

| Scenario | Contact | Method |
|----------|---------|--------|
| Vault sealed (needs unseal) | Any 3 of 5 key holders | Emergency call |
| Vaultwarden down / locked out | Infra admin on-call | Pager / Slack #incidents |
| Suspected secret compromise | Security Lead | Immediate call |
| Lab infrastructure lockout | Infra admin + iLO access | On-site / iLO remote |

### 13.3 Essential Commands

```bash
# —— Vault ——
# Login with Entra ID
vault login -method=jwt role=developers

# Read a secret
vault kv get secret-standard/lab/ssh/vm-db-01

# Write a secret
vault kv put secret-standard/lab/ilo/server-01 api-key=... ip=10.0.0.5

# Check token info
vault token lookup

# Revoke a token (offboarding)
vault token revoke <token-id>

# Check seal status
vault status

# —— Vaultwarden (via Bitwarden CLI) ——
# Login
bw login username@expertflow.com

# Search for item
bw list items --search "iLO"

# Get password
bw get password "iLO - lab-server-01"
```

---

## 14. Decision Log

| ID | Decision | Date | Decision Maker | Status |
|----|----------|------|----------------|--------|
| SEC-001 | Two-Vault strategy: Vault + Vaultwarden | 2026-06-22 | IT Lead | Proposed |
| SEC-002 | Vaultwarden hosted on Hetzner | 2026-06-22 | Infra Lead | Proposed |
| SEC-003 | Vault unseal: 3-of-5 Shamir split | 2026-06-22 | Security Lead | Proposed |
| SEC-004 | Lab secrets split: Vault (automation) + Vaultwarden (human GUI) | 2026-06-22 | Infra Lead | Proposed |
| SEC-005 | Per-VM SSH keys for lab (not shared) | 2026-06-22 | Infra Lead | Proposed |
| SEC-006 | iLO/iDRAC on isolated management VLAN | 2026-06-22 | Infra Lead | Proposed |
| SEC-007 | 90-day rotation for all infrastructure secrets | 2026-06-22 | Security Lead | Proposed |
| SEC-008 | Terraform for Vault config as code | 2026-06-22 | Infra Lead | Proposed |

---

## 15. Appendix A: Lab Infrastructure Secret Inventory Template

Use this template to document secrets as they are migrated:

| Asset Name | Type | Location | Secret Store | Path / Item | Owner | Last Rotated | Rotation Due |
|-----------|------|----------|--------------|-------------|-------|--------------|--------------|
| lab-server-01 | Physical | Rack A1 | Vaultwarden | Admin > iLO-iDRAC > lab-server-01 | Infra | 2026-06-22 | 2026-09-22 |
| lab-server-01 | Physical | Rack A1 | Vault | secret-standard/lab/ilo/lab-server-01 | Infra | 2026-06-22 | 2026-09-22 |
| proxmox-01 | Hypervisor | Rack A1 | Vaultwarden | Admin > Hypervisors > proxmox-01 | Infra | 2026-06-22 | 2026-09-22 |
| vm-lab-db-01 | Lab VM | proxmox-01 | Vaultwarden | Dev > Lab VMs > vm-lab-db-01 | Infra | 2026-06-22 | 2026-09-22 |
| vm-lab-db-01 | Lab VM | proxmox-01 | Vault | secret-standard/lab/ssh/vm-lab-db-01 | Infra | 2026-06-22 | 2026-09-22 |
| core-sw-01 | Network | Rack A2 | Vaultwarden | Admin > Network > core-sw-01 | Infra | 2026-06-22 | 2026-09-22 |
| core-sw-01 | Network | Rack A2 | Vault | secret-standard/lab/network/snmp/core-sw-01 | Infra | 2026-06-22 | 2026-09-22 |

---

## 16. Appendix B: iLO/iDRAC Security Checklist

- [ ] Management interface on dedicated VLAN (no internet access)
- [ ] Default TLS certificate replaced with internal CA cert
- [ ] Strong unique password (32+ chars, random)
- [ ] IP access restriction (admin subnet only)
- [ ] Audit logging enabled to syslog
- [ ] Firmware updated to latest stable
- [ ] Redfish API key stored in Vault (not hardcoded)
- [ ] Documented in ITAM + Vaultwarden + Vault

---

*Next Review: 2026-07-22 (monthly)*  
*Document Owner: IT Infrastructure Team*  
*Related Documents: `Expertflow IT assets.md`, `ITAM-Strategy.md`, `IT-Open-Questions.md`, `ITAM-Documentation.md`*
