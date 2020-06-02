use ::std::sync::Mutex;
use async_trait::async_trait;
use yup_oauth2::authenticator::Authenticator;
use hyper::client::connect::Connect;
use std::sync::Arc;

pub fn from_authenticator<C, I, S>(auth: Authenticator<C>, scopes: I) -> impl crate::GetAccessToken
where
    C: Connect + Clone + Send + Sync + 'static,
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    YupAuthenticator {
        auth: Mutex::new(Arc::new(auth)),
        scopes: scopes.into_iter().map(Into::into).collect(),
    }
}

struct YupAuthenticator<C> {
    auth: Mutex<Arc<Authenticator<C>>>,
    scopes: Vec<String>,
}

impl<T> ::std::fmt::Debug for YupAuthenticator<T> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", "YupAuthenticator{..}")
    }
}

#[async_trait]
impl<C> crate::GetAccessToken for YupAuthenticator<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    async fn access_token(&self) -> Result<String, Box<dyn ::std::error::Error + Send + Sync>> {
        // This is for lifetime reasons.
        let auth: Arc<_> = {
            let guard = self
            .auth
            .lock()
            .expect("thread panicked while holding lock");

            guard.clone()
        };

        let tok = (*auth).token(&self.scopes).await?;
        Ok(tok.as_str().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GetAccessToken;
    use yup_oauth2 as oauth2;

    #[tokio::test]
    async fn it_works() {
        let auth = oauth2::InstalledFlowAuthenticator::builder(
            oauth2::ApplicationSecret::default(),
            yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
        ).build()
        .await
        .expect("failed to build");

        let auth = from_authenticator(auth, vec!["foo", "bar"]);

        fn this_should_work<T: GetAccessToken>(_x: T) {};
        this_should_work(auth);
    }
}
