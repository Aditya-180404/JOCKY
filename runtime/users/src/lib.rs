//! JOCKEY Runtime - User Enumeration
//!
//! Collects local and domain users with attributes: SID/UID, status, last logon,
//! password age, group memberships.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UsersError {
    #[error("Failed to read user database: {0}")]
    ReadError(String),
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    #[error("Insufficient privileges: {0}")]
    InsufficientPrivileges(String),
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Unique identifier (SID on Windows, UID on Linux)
    pub id: String,
    /// Username
    pub name: String,
    /// Full name / display name
    pub full_name: Option<String>,
    /// User description/comment
    pub description: Option<String>,
    /// Home directory
    pub home_dir: Option<String>,
    /// Default shell (Linux) or profile path (Windows)
    pub shell: Option<String>,
    /// Account status
    pub status: UserStatus,
    /// Whether the account is disabled
    pub disabled: bool,
    /// Whether the account is locked out
    pub locked: bool,
    /// Whether password never expires
    pub password_never_expires: bool,
    /// Whether password is required
    pub password_required: bool,
    /// Last logon timestamp
    pub last_logon: Option<DateTime<Utc>>,
    /// Last password change timestamp
    pub password_last_set: Option<DateTime<Utc>>,
    /// Account creation timestamp
    pub created: Option<DateTime<Utc>>,
    /// Account expiration timestamp
    pub expires: Option<DateTime<Utc>>,
    /// Primary group ID
    pub primary_group_id: Option<String>,
    /// Group memberships (SIDs on Windows, GIDs on Linux)
    pub groups: Vec<String>,
    /// User privileges/rights
    pub privileges: Vec<String>,
    /// Source of this user info
    pub source: UserSource,
}

/// User account status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserStatus {
    Active,
    Disabled,
    Locked,
    Expired,
    Unknown,
}

/// Source of user enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserSource {
    Local,
    Domain,
    #[cfg(target_os = "linux")]
    NSS,
    #[cfg(target_os = "linux")]
    Shadow,
}

/// Group information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Unique identifier (SID on Windows, GID on Linux)
    pub id: String,
    /// Group name
    pub name: String,
    /// Group description
    pub description: Option<String>,
    /// Member user IDs
    pub members: Vec<String>,
    /// Source of this group info
    pub source: UserSource,
}

/// Result of user enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResult {
    pub users: Vec<UserInfo>,
    pub groups: Vec<GroupInfo>,
    pub collection_time: DateTime<Utc>,
    pub errors: Vec<String>,
}

impl Default for UsersResult {
    fn default() -> Self {
        Self::new()
    }
}

impl UsersResult {
    pub fn new() -> Self {
        Self {
            users: Vec::new(),
            groups: Vec::new(),
            collection_time: Utc::now(),
            errors: Vec::new(),
        }
    }
}

/// Enumerate all local users and groups
#[cfg(target_os = "linux")]
pub fn enumerate_users() -> Result<UsersResult> {
    use std::fs;
    use users::{get_group_by_gid, get_user_by_uid};

    let mut result = UsersResult::new();

    // Read /etc/passwd for all users
    let passwd_content = fs::read_to_string("/etc/passwd").context("Failed to read /etc/passwd")?;

    // Read /etc/shadow for password info (requires root)
    let shadow_content = fs::read_to_string("/etc/shadow").ok();

    // Read /etc/group for all groups
    let group_content = fs::read_to_string("/etc/group").context("Failed to read /etc/group")?;

    // Parse groups first
    let mut groups = HashMap::new();
    for line in group_content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let gid = parts[2].to_string();
            let members = if parts.len() > 3 && !parts[3].is_empty() {
                parts[3].split(',').map(|s| s.to_string()).collect()
            } else {
                Vec::new()
            };

            let group = GroupInfo {
                id: gid.clone(),
                name: name.clone(),
                description: None,
                members,
                source: UserSource::NSS,
            };
            groups.insert(gid.clone(), group);
        }
    }

    // Parse shadow file for password info
    let mut shadow_map = HashMap::new();
    if let Some(shadow) = shadow_content {
        for line in shadow.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 8 {
                let username = parts[0].to_string();
                let last_change = parts[2].parse::<i64>().ok();
                let min_age = parts[3].parse::<i64>().ok();
                let max_age = parts[4].parse::<i64>().ok();
                let warn_days = parts[5].parse::<i64>().ok();
                let inactive_days = parts[6].parse::<i64>().ok();
                let expire_date = parts[7].parse::<i64>().ok();

                shadow_map.insert(
                    username,
                    (
                        last_change,
                        min_age,
                        max_age,
                        warn_days,
                        inactive_days,
                        expire_date,
                    ),
                );
            }
        }
    }

    // Parse users from /etc/passwd
    for line in passwd_content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 7 {
            let name = parts[0].to_string();
            let _password = parts[1]; // x or * typically
            let uid = parts[2].to_string();
            let gid = parts[3].to_string();
            let gecos = parts[4].to_string();
            let home_dir = parts[5].to_string();
            let shell = parts[6].to_string();

            // Parse GECOS field
            let gecos_parts: Vec<&str> = gecos.split(',').collect();
            let full_name = if !gecos_parts[0].is_empty() {
                Some(gecos_parts[0].to_string())
            } else {
                None
            };

            // Get password info from shadow
            let (last_logon, password_last_set, expires, password_never_expires, password_required) =
                if let Some((
                    last_change,
                    _min_age,
                    max_age,
                    _warn_days,
                    _inactive_days,
                    expire_date,
                )) = shadow_map.get(&name)
                {
                    let password_last_set = last_change
                        .map(|days| DateTime::from_timestamp(days * 86400, 0).unwrap_or_default());
                    let expires = expire_date
                        .map(|days| DateTime::from_timestamp(days * 86400, 0).unwrap_or_default());
                    let password_never_expires = max_age.map_or(false, |m| m == -1 || m == 99999);
                    let password_required = true; // If in shadow, password is required
                    (
                        None,
                        password_last_set,
                        expires,
                        password_never_expires,
                        password_required,
                    )
                } else {
                    (None, None, None, false, false)
                };

            // Determine status
            let disabled =
                shell == "/usr/sbin/nologin" || shell == "/sbin/nologin" || shell == "/bin/false";
            let locked = false; // Would need to check /etc/shadow for ! or * prefix

            // Get group memberships
            let mut user_groups = vec![gid.clone()];
            for (gid, group) in &groups {
                if group.members.contains(&name) {
                    user_groups.push(gid.clone());
                }
            }

            let user = UserInfo {
                id: uid.clone(),
                name: name.clone(),
                full_name,
                description: None,
                home_dir: if home_dir.is_empty() {
                    None
                } else {
                    Some(home_dir)
                },
                shell: if shell.is_empty() { None } else { Some(shell) },
                status: if disabled {
                    UserStatus::Disabled
                } else {
                    UserStatus::Active
                },
                disabled,
                locked,
                password_never_expires,
                password_required,
                last_logon,
                password_last_set,
                created: None, // Not available from /etc/passwd
                expires,
                primary_group_id: Some(gid),
                groups: user_groups,
                privileges: Vec::new(),
                source: UserSource::NSS,
            };
            result.users.push(user);
        }
    }

    // Add groups to result
    result.groups = groups.into_values().collect();

    Ok(result)
}

/// Enumerate all local users and groups on Windows
#[cfg(target_os = "windows")]
pub fn enumerate_users() -> Result<UsersResult> {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut result = UsersResult::new();

    // Use NetUserEnum equivalent via WMI or direct API
    // For now, use registry enumeration of user profiles
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let profiles_key = hkcu
        .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        .context("Failed to open ProfileList key")?;

    for sid_str in profiles_key.enum_keys().flatten() {
        if let Ok(profile_key) = profiles_key.open_subkey(&sid_str) {
            let profile_path: String = profile_key
                .get_value("ProfileImagePath")
                .unwrap_or_default();
            let sid = sid_str.clone();

            // Skip system profiles
            if profile_path.contains("System32") || profile_path.contains("ServiceProfiles") {
                continue;
            }

            // Extract username from profile path
            let username = profile_path
                .split('\\')
                .next_back()
                .unwrap_or(&sid)
                .to_string();

            let user = UserInfo {
                id: sid,
                name: username,
                full_name: None,
                description: None,
                home_dir: Some(profile_path),
                shell: None,
                status: UserStatus::Active,
                disabled: false,
                locked: false,
                password_never_expires: false,
                password_required: true,
                last_logon: None,
                password_last_set: None,
                created: None,
                expires: None,
                primary_group_id: None,
                groups: Vec::new(),
                privileges: Vec::new(),
                source: UserSource::Local,
            };
            result.users.push(user);
        }
    }

    // Also enumerate via NetUserEnum if available (requires admin)
    // For now, registry-based enumeration

    Ok(result)
}

/// Enumerate groups on Windows
#[cfg(target_os = "windows")]
pub fn enumerate_groups() -> Result<Vec<GroupInfo>> {
    let mut groups = Vec::new();

    // Use well-known SIDs for built-in groups
    let builtin_groups = [
        ("S-1-5-32-544", "Administrators"),
        ("S-1-5-32-545", "Users"),
        ("S-1-5-32-546", "Guests"),
        ("S-1-5-32-547", "Power Users"),
        ("S-1-5-32-548", "Account Operators"),
        ("S-1-5-32-549", "Server Operators"),
        ("S-1-5-32-550", "Print Operators"),
        ("S-1-5-32-551", "Backup Operators"),
        ("S-1-5-32-552", "Replicators"),
    ];

    for (sid, name) in builtin_groups {
        groups.push(GroupInfo {
            id: sid.to_string(),
            name: name.to_string(),
            description: Some(format!("Built-in group: {}", name)),
            members: Vec::new(),
            source: UserSource::Local,
        });
    }

    Ok(groups)
}

/// Main entry point for user enumeration
pub fn collect_users() -> Result<UsersResult> {
    #[cfg(target_os = "linux")]
    {
        enumerate_users()
    }

    #[cfg(target_os = "windows")]
    {
        let mut result = enumerate_users()?;
        result.groups = enumerate_groups()?;
        Ok(result)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(UsersError::UnsupportedPlatform("Platform not supported".to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_users_result_creation() {
        let result = UsersResult::new();
        assert!(result.users.is_empty());
        assert!(result.groups.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_enumerate_users_linux() {
        let result = enumerate_users();
        assert!(result.is_ok());
        let users = result.unwrap();
        assert!(!users.users.is_empty());
        // Should at least have root user
        assert!(users.users.iter().any(|u| u.name == "root"));
    }
}
