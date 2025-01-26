use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    http::header::{self, HeaderValue},
    web, Error, HttpMessage, HttpResponse,
};
use anyhow;
use async_trait;
use awc::{self, http};
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{encode, EncodingKey, Header};
use openidconnect::{
    core::{CoreClient, CoreIdTokenClaims, CoreProviderMetadata},
    http::Method,
    AccessToken, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

// Session token claims that will be encoded in the JWT
#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    exp: u64,
    iat: u64,
    iss: String,
}

// Configuration for the OIDC middleware
pub struct OIDCConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub redirect_url: String,
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_max_age: i64,
    pub jwt_secret: String,
}

// Remove reqwest-specific import and add our own HTTP client implementation
pub struct AWCHttpClient(awc::Client);

fn convert_to_client_request(
    request: &openidconnect::HttpRequest,
    client: &awc::Client,
) -> Result<awc::ClientRequest, awc::error::SendRequestError> {
    let uri = request.uri();
    let url: awc::http::Uri = awc::http::Uri::builder()
        .scheme(uri.scheme_str().unwrap_or_default())
        .authority(uri.host().unwrap_or_default())
        .path_and_query(uri.path_and_query().map_or(uri.path(), |p| p.as_str()))
        .build()?;
    let mut req = client.request(
        match request.method() {
            &Method::GET => awc::http::Method::GET,
            &Method::POST => awc::http::Method::POST,
            other => awc::http::Method::from_bytes(other.as_str().as_bytes())
                .map_err(|e| awc::error::SendRequestError::Custom(
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>,
                    Box::new("Invalid HTTP method"),
                ))?,
        },
        url,
    );

    for (name, value) in request.headers() {
        req = req.insert_header((name.as_str(), value.as_bytes()));
    }
    Ok(req)
}

impl openidconnect::AsyncHttpClient<'_> for AWCHttpClient {
    type Error = awc::error::SendRequestError;
    type Future = Pin<
        Box<dyn Future<Output = Result<openidconnect::HttpResponse, Self::Error>>>,
    >;

    fn call(&self, request: openidconnect::HttpRequest) -> Self::Future {
        let client = self.0.clone();
        let req_r = convert_to_client_request(&request, &client);

        Box::pin(async move {
            let req = req_r?;

            let mut response = req.send_body(request.into_body()).await?;

            let status = response.status();
            let body = response.body().await.map_err(|e| {
                awc::error::SendRequestError::Custom(
                    Box::new(e) as Box<dyn std::error::Error + Send + Sync>,
                    Box::new("Failed to read response body"),
                )
            })?;
            let headers = response.headers();

            let mut resp = openidconnect::HttpResponse::new(body.into());
            *resp.status_mut() = status.as_u16().try_into().unwrap_or_default();
            for (key, value) in headers {
                let key = key.as_str().as_bytes();
                let key_into = openidconnect::http::header::HeaderName::from_bytes(key);
                if let (Ok(key), Ok(value)) = (key_into, value.as_bytes().try_into()) {
                    resp.headers_mut().append(key, value);
                }
            }
            Ok(resp)
        })
    }
}

// The middleware factory
pub struct OIDC {
    config: Arc<OIDCConfig>,
    client: Arc<CoreClient>,
    jwt_key: EncodingKey,
}

impl OIDC {
    pub async fn new(config: OIDCConfig) -> Result<Self, Error> {
        // Create AWC client with proper TLS configuration
        let client = awc::Client::builder()
            .connector(awc::Connector::new())
            .finish();

        let provider_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(config.issuer_url.clone())
                .map_err(|e| ErrorUnauthorized(format!("Invalid issuer URL: {}", e)))?,
            AWCHttpClient(client.clone()),
        )
        .await
        .map_err(|e| ErrorUnauthorized(format!("Failed to discover OIDC provider: {}", e)))?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_url.clone())
                .map_err(|e| ErrorUnauthorized(format!("Invalid redirect URL: {}", e)))?,
        );

        let jwt_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());

        Ok(Self {
            config: Arc::new(config),
            client: Arc::new(client),
            jwt_key,
        })
    }
}

impl<S, B> Transform<S, ServiceRequest> for OIDC
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = OIDCMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OIDCMiddleware {
            service,
            config: Arc::clone(&self.config),
            client: Arc::clone(&self.client),
            jwt_key: self.jwt_key.clone(),
        }))
    }
}

// The middleware service
pub struct OIDCMiddleware<S> {
    service: S,
    config: Arc<OIDCConfig>,
    client: Arc<CoreClient>,
    jwt_key: EncodingKey,
}

impl<S, B> Service<ServiceRequest> for OIDCMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = Arc::clone(&self.config);
        let client = Arc::clone(&self.client);
        let jwt_key = self.jwt_key.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Check if this is the OAuth callback
            if req.path() == "/auth/callback" {
                return Ok(handle_callback(req, client, config, jwt_key).await?.map_into_boxed_body());
            }

            // Check for existing session
            if let Some(session_cookie) = req.cookie(&config.cookie_name) {
                if let Ok(claims) = validate_session_token(session_cookie.value(), &jwt_key) {
                    // Add claims to request extensions for use in handlers
                    req.extensions_mut().insert(claims);
                    return service.call(req).await.map(|res| res.map_into_boxed_body());
                }
            }

            // Start OAuth flow
            let (auth_url, csrf_token, nonce) = client
                .authorize_url(
                    AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                )
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .url();

            // Store CSRF token and nonce in session
            // TODO: Implement secure session storage for CSRF/nonce

            Ok(req.into_response(
                HttpResponse::Found()
                    .append_header((header::LOCATION, auth_url.as_str()))
                    .finish()
                    .map_into_boxed_body(),
            ))
        })
    }
}

async fn handle_callback<B>(
    req: ServiceRequest,
    client: Arc<CoreClient>,
    config: Arc<OIDCConfig>,
    jwt_key: EncodingKey,
) -> Result<ServiceResponse<B>, Error> {
    let query =
        web::Query::<std::collections::HashMap<String, String>>::from_query(req.query_string())
            .map_err(|e| ErrorUnauthorized(format!("Invalid callback parameters: {}", e)))?;

    let code = query
        .get("code")
        .ok_or_else(|| ErrorUnauthorized("No code provided"))?;
    let state = query
        .get("state")
        .ok_or_else(|| ErrorUnauthorized("No state provided"))?;

    // TODO: Validate CSRF token from state

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(AWCHttpClient(
            awc::Client::builder()
                .connector(awc::Connector::new())
                .finish(),
        ))
        .await
        .map_err(|e| ErrorUnauthorized(format!("Token exchange failed: {}", e)))?;

    // Extract and validate ID token
    let id_token = token_response
        .id_token()
        .ok_or_else(|| ErrorUnauthorized("No ID token received"))?;

    let claims = id_token
        .claims(&client.id_token_verifier(), &nonce) // TODO: Get nonce from session
        .map_err(|e| ErrorUnauthorized(format!("Invalid ID token: {}", e)))?;

    // Create session JWT
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session_claims = SessionClaims {
        sub: claims.subject().to_string(),
        email: claims.email().map(|e| e.to_string()),
        name: claims.name().map(|n| n.to_string()),
        iat: now,
        exp: now + config.cookie_max_age as u64,
        iss: config.issuer_url.clone(),
    };

    let token = encode(&Header::default(), &session_claims, &jwt_key)
        .map_err(|e| ErrorUnauthorized(format!("Failed to create session token: {}", e)))?;

    let cookie = cookie::Cookie::build(&config.cookie_name, token)
        .secure(config.cookie_secure)
        .http_only(true)
        .max_age(time::Duration::seconds(config.cookie_max_age))
        .path("/")
        .finish();

    Ok(req.into_response(
        HttpResponse::Found()
            .cookie(cookie)
            .append_header((header::LOCATION, "/"))
            .map_into_boxed_body()
            .finish(),
    ))
}

fn validate_session_token(token: &str, key: &EncodingKey) -> Result<SessionClaims, Error> {
    let validation = jsonwebtoken::Validation::default();
    jsonwebtoken::decode::<SessionClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(key.as_bytes()),
        &validation,
    )
    .map(|token_data| token_data.claims)
    .map_err(|e| ErrorUnauthorized(format!("Invalid session token: {}", e)))
}
