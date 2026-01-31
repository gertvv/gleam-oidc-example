import envoy
import flwr_oauth2
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/io
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/uri.{type Uri}
import storail
import wisp
import ywt

pub type Context {
  Context(
    session: #(String, Session),
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
  // set up the session store
  let config = storail.Config(storage_path: "tmp/storage")
  let sessions =
    storail.Collection(
      name: "sessions",
      to_json: session_to_json,
      decoder: session_decoder(),
      config:,
    )

  // get the OIDC discovery data
  let assert Ok(server_url) =
    envoy.get("OIDC_SERVER_URL") |> result.try(uri.parse)
  let assert Ok(req) =
    uri.parse(oidc_discovery_endpoint)
    |> result.try(uri.merge(server_url, _))
    |> result.try(request.from_uri)
  let assert Ok(res) = httpc.send(req)
  let assert Ok(oidc_config) = json.parse(res.body, discovery_data_decoder())

  // create our client configuration (redirect URI and credentials)
  let assert Ok(app_base_url) =
    envoy.get("APP_BASE_URL") |> result.try(uri.parse)
  let assert Ok(redirect_uri) =
    uri.parse("/oauth/post-login")
    |> result.try(uri.merge(app_base_url, _))
  let assert Ok(client_id) = envoy.get("OIDC_CLIENT_ID")
  let assert Ok(client_secret) = envoy.get("OIDC_CLIENT_SECRET")
  let oidc_client = OidcClientConfig(redirect_uri:, client_id:, client_secret:)

  Context(#("", NoSession), sessions:, oidc_config:, oidc_client:)
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

pub fn is_authenticated(ctx: Context) -> Bool {
  case ctx.session {
    #(_, Authenticated(..)) -> True
    _ -> False
  }
}

pub fn require_user(
  ctx: Context,
  next: fn(User) -> wisp.Response,
) -> wisp.Response {
  case ctx.session {
    #(_, Authenticated(user)) -> next(user)
    _ ->
      "
      <h1>Unauthorized</h1>
      <p>You must log in to access this page</p>
      "
      |> wisp.html_response(401)
  }
}

fn login_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Post)
  let session_id = flwr_oauth2.random_state32().value
  let state = flwr_oauth2.random_state32()
  let _ctx = set_session(ctx, session_id, Authenticating(state.value))
  wisp.redirect(
    flwr_oauth2.make_redirect_uri(flwr_oauth2.AuthorizationCodeGrantRedirectUri(
      oauth_server: ctx.oidc_config.authorization_endpoint,
      response_type: flwr_oauth2.Code,
      redirect_uri: option.Some(ctx.oidc_client.redirect_uri),
      client_id: flwr_oauth2.ClientId(ctx.oidc_client.client_id),
      scope: ["openid", "profile"],
      state: option.Some(state),
    ))
    |> uri.to_string,
  )
  |> wisp.set_cookie(req, session_cookie, session_id, wisp.Signed, 60 * 60 * 24)
}

fn post_login_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Get)
  use code <- require_param(req, "code")
  use state <- require_param(req, "state")
  use <- verify_state(ctx, state)

  use token_response <- perform_token_request(ctx, code)
  use user <- token_response_to_user(token_response)
  let #(session_id, _) = ctx.session
  let _ctx = set_session(ctx, session_id, Authenticated(user))
  wisp.redirect("/")
}

fn verify_state(
  ctx: Context,
  state_param: String,
  next: fn() -> wisp.Response,
) -> wisp.Response {
  case ctx.session {
    #(_, NoSession) | #(_, Authenticated(..)) ->
      auth_error("Session is not in login flow", 400)
    #(_, Authenticating(state:)) ->
      case state_param == state {
        True -> next()
        False -> auth_error("State parameter mismatched", 400)
      }
  }
}

fn perform_token_request(
  ctx: Context,
  code: String,
  next: fn(flwr_oauth2.AccessTokenResponse) -> wisp.Response,
) -> wisp.Response {
  let token_request =
    flwr_oauth2.AuthorizationCodeGrantTokenRequest(
      token_endpoint: ctx.oidc_config.token_endpoint,
      authentication: flwr_oauth2.ClientSecretBasic(
        client_id: flwr_oauth2.ClientId(ctx.oidc_client.client_id),
        client_secret: flwr_oauth2.Secret(ctx.oidc_client.client_secret),
      ),
      redirect_uri: option.Some(ctx.oidc_client.redirect_uri),
      code: code,
    )
  use token_request <- require_ok(
    flwr_oauth2.to_http_request(token_request),
    "Unable to generate token request",
  )
  use res <- require_ok(
    httpc.send(token_request),
    "Unable to perform token request",
  )
  case flwr_oauth2.parse_token_response(res) {
    Ok(res) -> next(res)
    Error(flwr_oauth2.ParseError(..)) ->
      auth_error("Unable to parse token response", 500)
    Error(flwr_oauth2.ErrorResponse(error:, error_description:, ..)) ->
      auth_error(
        error
          <> case error_description {
          option.Some(description) -> ": " <> description
          option.None -> ""
        },
        500,
      )
  }
}

fn token_response_to_user(
  res: flwr_oauth2.AccessTokenResponse,
  next: fn(User) -> wisp.Response,
) -> wisp.Response {
  let decoder = {
    use id <- decode.field("sub", decode.string)
    use name <- decode.field("name", decode.string)
    decode.success(User(id:, name:))
  }
  case ywt.decode_unsafely_without_validation(res.access_token, decoder) {
    Ok(user) -> next(user)
    Error(_) -> auth_error("Unable to decode JWT", 500)
  }
}

/// Render an authentication error page with the given `message` and `status`.
fn auth_error(message: String, status: Int) -> wisp.Response {
  wisp.html_response(
    "<h1>Authentication error</h1><p>" <> message <> "</p>",
    status,
  )
}

/// Calls `next` with the value of the named request parameter,
/// or renders an error page.
fn require_param(
  req: wisp.Request,
  name: String,
  next: fn(String) -> wisp.Response,
) -> wisp.Response {
  case wisp.get_query(req) |> list.key_find(name) {
    Ok(value) -> next(value)
    Error(_) -> auth_error("Missing parameter: " <> name, 400)
  }
}

/// Calls `next` with the `Ok` value of the given `Result`,
/// or logs the `Error` and renders an error page with the `message`.
fn require_ok(
  result: Result(a, b),
  message: String,
  next: fn(a) -> wisp.Response,
) -> wisp.Response {
  case result {
    Ok(value) -> next(value)
    Error(err) -> {
      io.println_error("[ERROR] " <> message)
      echo err
      auth_error(message, 500)
    }
  }
}

fn logout_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Post)
  case ctx.session {
    #(id, Authenticated(_)) | #(id, Authenticating(_)) -> {
      // if we can't write to our session store, panic
      let assert Ok(_) = storail.delete(storail.key(ctx.sessions, id))
      wisp.redirect("/")
      |> wisp.set_cookie(req, session_cookie, id, wisp.Signed, 0)
    }
    _ -> wisp.redirect("/")
  }
}

fn get_session(ctx: Context, id: String) -> Context {
  let session =
    storail.read(storail.key(ctx.sessions, id))
    |> result.unwrap(NoSession)
  Context(..ctx, session: #(id, session))
}

fn set_session(ctx: Context, id: String, session: Session) -> Context {
  // if we can't write to our session store, panic
  let assert Ok(_) = storail.write(storail.key(ctx.sessions, id), session)
  Context(..ctx, session: #(id, session))
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
