import envoy
import flwr_oauth2
import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/option
import gleam/result
import gleam/uri.{type Uri}
import storail
import wisp

pub type Context {
  Context(
    session: Session,
    sessions: storail.Collection(Session),
    oidc_config: DiscoveryData,
    oidc_client: OidcClientConfig,
  )
}

pub type Session {
  NoSession
  Authenticating(state: String)
  Authenticated(user: User)
}

pub type User {
  User(id: String, name: String)
}

pub type DiscoveryData {
  DiscoveryData(authorization_endpoint: Uri, token_endpoint: Uri)
}

pub type OidcClientConfig {
  OidcClientConfig(redirect_uri: Uri, client_id: String, client_secret: String)
}

const oidc_discovery_endpoint = ".well-known/openid-configuration"

pub fn configure() {
  let config = storail.Config(storage_path: "tmp/storage")

  let sessions =
    storail.Collection(
      name: "sessions",
      to_json: session_to_json,
      decoder: session_decoder(),
      config:,
    )

  let assert Ok(server_url) =
    envoy.get("OIDC_SERVER_URL") |> result.try(uri.parse)
  let assert Ok(req) =
    uri.parse(oidc_discovery_endpoint)
    |> result.try(uri.merge(server_url, _))
    |> result.try(request.from_uri)

  let assert Ok(res) = httpc.send(req)
  let assert Ok(oidc_config) = json.parse(res.body, discovery_data_decoder())

  let assert Ok(app_base_url) =
    envoy.get("APP_BASE_URL") |> result.try(uri.parse)
  let assert Ok(redirect_uri) =
    uri.parse("/oauth/post-login")
    |> result.try(uri.merge(app_base_url, _))
  let assert Ok(client_id) = envoy.get("OIDC_CLIENT_ID")
  let assert Ok(client_secret) = envoy.get("OIDC_CLIENT_SECRET")
  let oidc_client = OidcClientConfig(redirect_uri:, client_id:, client_secret:)

  Context(NoSession, sessions:, oidc_config:, oidc_client:)
}

const session_cookie = "session_id"

pub fn middleware(
  req: wisp.Request,
  ctx: Context,
  next: fn(Context) -> wisp.Response,
) -> wisp.Response {
  let ctx =
    wisp.get_cookie(req, session_cookie, wisp.Signed)
    |> result.map(get_session(ctx, _))
    |> result.unwrap(ctx)

  case wisp.path_segments(req) {
    ["login"] -> login_handler(req, ctx)
    ["logout"] -> logout_handler(req, ctx)
    ["oauth", "post-login"] -> post_login_handler(req, ctx)
    _ -> next(ctx)
  }
}

fn login_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  let session_id = flwr_oauth2.random_state32().value
  let state = flwr_oauth2.random_state32()
  let _ctx = set_session(ctx, session_id, Authenticating(state.value))
  wisp.redirect(
    flwr_oauth2.make_redirect_uri(flwr_oauth2.AuthorizationCodeGrantRedirectUri(
      oauth_server: ctx.oidc_config.authorization_endpoint,
      response_type: flwr_oauth2.Code,
      redirect_uri: option.Some(ctx.oidc_client.redirect_uri),
      client_id: flwr_oauth2.ClientId(ctx.oidc_client.client_id),
      scope: ["openid"],
      state: option.Some(state),
    ))
    |> uri.to_string,
  )
  |> wisp.set_cookie(req, session_cookie, session_id, wisp.Signed, 60 * 60 * 24)
}

fn logout_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  todo
}

fn post_login_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  todo
}

fn get_session(ctx: Context, id: String) -> Context {
  let session =
    storail.read(storail.key(ctx.sessions, id))
    |> result.unwrap(NoSession)
  Context(..ctx, session:)
}

fn set_session(ctx: Context, id: String, session: Session) -> Context {
  // if we can't write to our session store, panic
  let assert Ok(_) = storail.write(storail.key(ctx.sessions, id), session)
  ctx
}

// --- JSON encoders and decoders ---

fn discovery_data_decoder() -> decode.Decoder(DiscoveryData) {
  use authorization_endpoint <- decode.field(
    "authorization_endpoint",
    uri_decoder(),
  )
  use token_endpoint <- decode.field("token_endpoint", uri_decoder())
  decode.success(DiscoveryData(authorization_endpoint:, token_endpoint:))
}

fn uri_decoder() -> decode.Decoder(Uri) {
  use str <- decode.then(decode.string)
  case uri.parse(str) {
    Ok(value) -> decode.success(value)
    Error(_) -> decode.failure(uri.empty, "Uri")
  }
}

fn user_to_json(user: User) -> json.Json {
  let User(id:, name:) = user
  json.object([
    #("id", json.string(id)),
    #("name", json.string(name)),
  ])
}

fn user_decoder() -> decode.Decoder(User) {
  use id <- decode.field("id", decode.string)
  use name <- decode.field("name", decode.string)
  decode.success(User(id:, name:))
}

fn session_to_json(session: Session) -> json.Json {
  case session {
    NoSession ->
      json.object([
        #("type", json.string("no_session")),
      ])
    Authenticating(state:) ->
      json.object([
        #("type", json.string("authenticating")),
        #("state", json.string(state)),
      ])
    Authenticated(user:) ->
      json.object([
        #("type", json.string("authenticated")),
        #("user", user_to_json(user)),
      ])
  }
}

fn session_decoder() -> decode.Decoder(Session) {
  use variant <- decode.field("type", decode.string)
  case variant {
    "no_session" -> decode.success(NoSession)
    "authenticating" -> {
      use state <- decode.field("state", decode.string)
      decode.success(Authenticating(state:))
    }
    "authenticated" -> {
      use user <- decode.field("user", user_decoder())
      decode.success(Authenticated(user:))
    }
    _ -> decode.failure(NoSession, "Session")
  }
}
