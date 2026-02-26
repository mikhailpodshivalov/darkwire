use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginBinding {
    pub login: String,
    pub ik_ed25519: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    LoginTaken,
}

#[derive(Debug, Default)]
pub struct LoginStore {
    by_login: HashMap<String, String>,
    by_ik: HashMap<String, String>,
}

impl LoginStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&mut self, login: String, ik_ed25519: String) -> Result<LoginBinding, BindError> {
        if let Some(existing_ik) = self.by_login.get(&login) {
            if existing_ik != &ik_ed25519 {
                return Err(BindError::LoginTaken);
            }
        }

        if let Some(old_login) = self.by_ik.get(&ik_ed25519).cloned() {
            if old_login != login {
                self.by_login.remove(&old_login);
            }
        }

        self.by_login.insert(login.clone(), ik_ed25519.clone());
        self.by_ik.insert(ik_ed25519.clone(), login.clone());

        Ok(LoginBinding { login, ik_ed25519 })
    }

    pub fn get_by_login(&self, login: &str) -> Option<LoginBinding> {
        let ik_ed25519 = self.by_login.get(login)?.clone();
        Some(LoginBinding {
            login: login.to_string(),
            ik_ed25519,
        })
    }

    pub fn get_by_ik(&self, ik_ed25519: &str) -> Option<LoginBinding> {
        let login = self.by_ik.get(ik_ed25519)?.clone();
        Some(LoginBinding {
            login,
            ik_ed25519: ik_ed25519.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_is_idempotent_for_same_login_and_key() {
        let mut store = LoginStore::new();

        let first = store
            .bind("mike".to_string(), "ik-1".to_string())
            .expect("first bind should pass");
        let second = store
            .bind("mike".to_string(), "ik-1".to_string())
            .expect("second bind should be idempotent");

        assert_eq!(first, second);
    }

    #[test]
    fn bind_rejects_login_taken_by_different_key() {
        let mut store = LoginStore::new();
        store
            .bind("mike".to_string(), "ik-1".to_string())
            .expect("first bind should pass");

        let err = store
            .bind("mike".to_string(), "ik-2".to_string())
            .expect_err("second bind should fail");
        assert_eq!(err, BindError::LoginTaken);
    }

    #[test]
    fn bind_moves_existing_key_to_new_login() {
        let mut store = LoginStore::new();
        store
            .bind("mike".to_string(), "ik-1".to_string())
            .expect("first bind should pass");
        store
            .bind("mike-alt".to_string(), "ik-1".to_string())
            .expect("key should be allowed to move to new login");

        assert!(store.get_by_login("mike").is_none());
        assert_eq!(
            store
                .get_by_login("mike-alt")
                .expect("new login should exist")
                .ik_ed25519,
            "ik-1"
        );
    }
}
