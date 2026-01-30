import envoy
import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/result
import gleam/uri.{type Uri}
import storail

pub type Context {
  Context(
    session: Session,
    sessions: storail.Collection(Session),
    oidc_config: DiscoveryData,
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

  echo oidc_config

  Context(NoSession, sessions:, oidc_config:)
}

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
