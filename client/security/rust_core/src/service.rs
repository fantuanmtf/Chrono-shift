//! F2F Service Management (v7.7 — Phase 3)
//!
//! F2F = trust boundary = network boundary.
//! Services are created within F2F networks. Admin approves, daemon
//! opens local proxy ports that forward to the service owner.
//!
//! Access control: admin can allow/deny specific UIDs per service.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// A service running inside an F2F network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct F2fService {
    /// Unique service ID (UUID)
    pub id: String,
    /// Human-readable name (e.g. "bbs", "fileshare")
    pub name: String,
    /// Who created this service
    pub owner_uid: String,
    /// Which F2F network this belongs to
    pub network_name: String,
    /// The owner's local port where the actual service runs
    pub owner_port: u16,
    /// Current status
    pub status: ServiceStatus,
    /// Creation timestamp (Unix epoch seconds)
    pub created: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Pending,  // Waiting for admin approval
    Active,   // Running, proxy active
    Rejected, // Admin denied
    Closed,   // Owner shut it down
}

/// Configuration for one proxy tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub target_uid: String,
    pub target_port: u16,
    /// UIDs allowed to access this proxy (empty = all network members)
    pub allowed_clients: Vec<String>,
    /// Allow all network members?
    pub allow_all_members: bool,
}

/// Manages all F2F services and proxy tunnels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceManager {
    /// All known services: service_id → service
    pub services: HashMap<String, F2fService>,
    /// Active proxy tunnels: local_port → proxy config
    pub proxies: HashMap<u16, ProxyConfig>,
    /// Next available local port for proxies (starts at 18080)
    pub next_port: u16,
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            proxies: HashMap::new(),
            next_port: 18080,
        }
    }

    /// Request to create a new service (pending admin approval)
    pub fn create_service(
        &mut self,
        name: &str,
        owner_uid: &str,
        network_name: &str,
        owner_port: u16,
    ) -> F2fService {
        let id = Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let service = F2fService {
            id: id.clone(),
            name: name.to_string(),
            owner_uid: owner_uid.to_string(),
            network_name: network_name.to_string(),
            owner_port,
            status: ServiceStatus::Pending,
            created: now,
        };

        self.services.insert(id, service.clone());
        service
    }

    /// Admin approves a service — activates proxy
    pub fn accept_service(&mut self, service_id: &str) -> Result<(u16, ProxyConfig), String> {
        let service = self
            .services
            .get_mut(service_id)
            .ok_or("服务不存在".to_string())?;

        if service.status != ServiceStatus::Pending {
            return Err("服务不在待批准状态".to_string());
        }

        service.status = ServiceStatus::Active;
        let local_port = self.next_port;
        self.next_port += 1;

        let config = ProxyConfig {
            target_uid: service.owner_uid.clone(),
            target_port: service.owner_port,
            allowed_clients: Vec::new(),
            allow_all_members: true,
        };

        self.proxies.insert(local_port, config.clone());
        Ok((local_port, config))
    }

    /// Admin rejects a service
    pub fn reject_service(&mut self, service_id: &str) -> Result<(), String> {
        let service = self
            .services
            .get_mut(service_id)
            .ok_or("服务不存在".to_string())?;
        service.status = ServiceStatus::Rejected;
        Ok(())
    }

    /// Owner closes their service
    pub fn close_service(&mut self, service_id: &str, requester: &str) -> Result<(), String> {
        let service = self
            .services
            .get_mut(service_id)
            .ok_or("服务不存在".to_string())?;

        if service.owner_uid != requester {
            return Err("只有服务创建者可以关闭".to_string());
        }

        service.status = ServiceStatus::Closed;
        // Remove any active proxy
        self.proxies
            .retain(|_, cfg| cfg.target_uid != service.owner_uid);
        Ok(())
    }

    /// Allow a specific UID to access a service
    pub fn allow_client(&mut self, service_name: &str, uid: &str) -> Result<(), String> {
        let proxy = self
            .proxies
            .values_mut()
            .find(|p| {
                self.services
                    .values()
                    .any(|s| s.name == service_name && s.owner_uid == p.target_uid)
            })
            .ok_or("服务代理不存在".to_string())?;

        proxy.allow_all_members = false;
        if !proxy.allowed_clients.contains(&uid.to_string()) {
            proxy.allowed_clients.push(uid.to_string());
        }
        Ok(())
    }

    /// Deny a UID from accessing a service
    pub fn deny_client(&mut self, service_name: &str, uid: &str) -> Result<(), String> {
        let proxy = self
            .proxies
            .values_mut()
            .find(|p| {
                self.services
                    .values()
                    .any(|s| s.name == service_name && s.owner_uid == p.target_uid)
            })
            .ok_or("服务代理不存在".to_string())?;

        proxy.allowed_clients.retain(|c| c != uid);
        Ok(())
    }

    /// Check if a UID can access a given port
    pub fn can_access(&self, uid: &str, local_port: u16) -> bool {
        if let Some(cfg) = self.proxies.get(&local_port) {
            cfg.allow_all_members || cfg.allowed_clients.contains(&uid.to_string())
        } else {
            false
        }
    }

    /// List active services
    pub fn list_services(&self) -> Vec<&F2fService> {
        self.services
            .values()
            .filter(|s| s.status == ServiceStatus::Active)
            .collect()
    }

    /// List pending services
    pub fn list_pending(&self) -> Vec<&F2fService> {
        self.services
            .values()
            .filter(|s| s.status == ServiceStatus::Pending)
            .collect()
    }

    /// Service count by status
    pub fn active_count(&self) -> usize {
        self.list_services().len()
    }

    pub fn pending_count(&self) -> usize {
        self.list_pending().len()
    }

    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_accept_service() {
        let mut mgr = ServiceManager::new();
        let svc = mgr.create_service("bbs", "bob", "mygroup", 8080);
        assert_eq!(svc.status, ServiceStatus::Pending);
        assert_eq!(mgr.pending_count(), 1);

        let result = mgr.accept_service(&svc.id);
        assert!(result.is_ok());
        let (port, cfg) = result.unwrap();
        assert_eq!(port, 18080);
        assert_eq!(cfg.target_uid, "bob");
        assert_eq!(cfg.target_port, 8080);
        assert!(cfg.allow_all_members);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_reject_service() {
        let mut mgr = ServiceManager::new();
        let svc = mgr.create_service("web", "alice", "testnet", 3000);
        mgr.reject_service(&svc.id).unwrap();
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_access_control() {
        let mut mgr = ServiceManager::new();
        let svc = mgr.create_service("bbs", "bob", "mygroup", 8080);
        let (port, _) = mgr.accept_service(&svc.id).unwrap();

        // Default: all members allowed
        assert!(mgr.can_access("carol", port));

        // Restrict access
        mgr.allow_client("bbs", "carol").unwrap();
        assert!(mgr.can_access("carol", port));
        assert!(!mgr.can_access("eve", port));

        // Deny
        mgr.deny_client("bbs", "carol").unwrap();
        assert!(!mgr.can_access("carol", port));
    }

    #[test]
    fn test_close_service() {
        let mut mgr = ServiceManager::new();
        let svc = mgr.create_service("ftp", "bob", "mygroup", 21);
        mgr.accept_service(&svc.id).unwrap();
        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.proxy_count(), 1);

        // Only owner can close
        assert!(mgr.close_service(&svc.id, "alice").is_err());
        mgr.close_service(&svc.id, "bob").unwrap();
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.proxy_count(), 0);
    }

    #[test]
    fn test_cannot_accept_twice() {
        let mut mgr = ServiceManager::new();
        let svc = mgr.create_service("bbs", "bob", "mygroup", 8080);
        mgr.accept_service(&svc.id).unwrap();
        assert!(mgr.accept_service(&svc.id).is_err());
    }
}
