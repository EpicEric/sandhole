use log::error;
use serde_json::json;

pub(crate) struct ApiLogin {
    endpoint: String,
}

impl ApiLogin {
    pub(crate) fn new(endpoint: String) -> Self {
        ApiLogin { endpoint }
    }

    pub(crate) async fn authenticate(&self, user: &str, password: &str) -> bool {
        let client = reqwest::Client::new();
        let request = client.post(self.endpoint.clone()).body(
            json!({
                "user": user,
                "password": password,
            })
            .to_string(),
        );
        match request.send().await {
            Ok(response) => (200..=299).contains(&response.status().as_u16()),
            Err(err) => {
                error!(
                    "Unable to validate user and password through API: {:?}",
                    err
                );
                false
            }
        }
    }
}
