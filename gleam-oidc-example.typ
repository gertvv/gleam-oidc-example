= Backend OpenID Connect (OIDC) authentication in Gleam

In this post we'll implement a basic server-side OpenID Connect flow, the authorization code flow with client credentials. We'll use the Erlang (BEAM) back-end.

== Prerequisites

TODO:

 - An OIDC server
 - A configured client
 - ...

== Setting up the project

First, we make sure we have the Gleam and Erlang tooling installed. I like to use mise (LINK) for this.

```sh
mise use gleam@1.14 erlang@28 rebar@3
```

We can also use mise to set environment variables, so we can set those up as well. If you care about your secrets, you should use something like fnox (LINK) for those instead.

```sh
mise set APP_URL=http://localhost:8080/
mise set SECRET_KEY_BASE=<random string>
mise set OIDC_SERVER_URL=<e.g. https://example.com/realms/something/>
mise set OIDC_CLIENT_ID=<client ID>
mise set OIDC_CLIENT_SECRET=<client secret>
```

Next we create a new gleam project.

```sh
gleam new . --name oidc_example
```

And then we install Wisp, the web framework, and envoy, for environment variables. We'll also add some of Wisp's dependencies as direct dependencies since we'll need to import them.

```sh
gleam add wisp@2 envoy gleam_http gleam_erlang mist
```

== The example app

Our main app will be really simple, just enough to demonstrate the OAuth flow, under `src/oidc_example.gleam`. We'll add a homepage with login button and a profile page for logged in users.

```gleam
import envoy
import gleam/erlang/process
import gleam/http
import mist
import oidc_example/auth
import wisp
import wisp/wisp_mist

pub type Context {
  Context(auth: auth.Context)
}

pub fn main() {
  wisp.configure_logger()

  let assert Ok(secret_key_base) = envoy.get("SECRET_KEY_BASE")

  let context = Context(auth.configure())

  let assert Ok(_) =
    wisp_mist.handler(router(_, context), secret_key_base)
    |> mist.new
    |> mist.port(8080)
    |> mist.start

  process.sleep_forever()
}

pub fn router(req: wisp.Request, ctx: Context) -> wisp.Response {
  let req = wisp.method_override(req)
  use <- wisp.log_request(req)
  use <- wisp.rescue_crashes
  use req <- wisp.handle_head(req)
  use req <- wisp.csrf_known_header_protection(req)

  case wisp.path_segments(req) {
    [] -> home_handler(req, ctx)
    ["profile"] -> profile_handler(req, ctx)
    _ -> wisp.not_found()
  }
}

fn home_handler(req: wisp.Request, _ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Get)

  "
  <h1>🌟 Gleam OIDC Example 🌟</h1>
  <p>
    <a href='/profile'>View profile</a>
  </p>
  <form action='/login'>
    <input type='submit' value='Login'/>
  </form>
  "
  |> wisp.html_response(200)
}

fn profile_handler(req: wisp.Request, _ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Get)

  "
  <h1>Unauthorized</h1>
  <p>You must log in to access this page</p>
  "
  |> wisp.html_response(401)
}
```

We'll also set up some basic types in a dedicated module, `src/oidc_example/auth.gleam`, which we'll flesh out in more detail shortly.

```gleam
pub type Context {
  Context(session: Session)
}

pub type Session {
  NoSession
  Authenticating(state: String)
  Authenticated(user: User)
}

pub type User {
  User(id: String, name: String)
}

pub fn configure() {
  Context(NoSession)
}
```

Now we can run our app and visit some pages, which show up in the request log on the console.

```
✦ ❯ gleam run
   Compiled in 0.08s
    Running oidc_example.main
Listening on http://127.0.0.1:8080
INFO 200 GET /
INFO 404 GET /favicon.ico
INFO 404 GET /login
INFO 401 GET /profile
```

== The authorization code flow

We'll implement the authorization code flow as follows (LINK https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow):

 1. When the user clicks the login button, their browser does a POST request to the `/login` endpoint.
 2. On receiving this request, we generate a random state string, which we associate with user's session. We set a session cookie and perform a redirect to the *authorization endpoint* of the identity provider.
 3. The user goes through an authentication flow at the identity provider. When this is done, their browser is redirected to our application's redirect URI, which we'll implement under `/oauth/post-login`.
 4. In the post-login handler, we retrieve the user's session and check the state against the state returned to us by the identity provider. If that checks out, we perform a request to the identity provider's *token endpoint*, including the authorization code as well as our client credentials.
 5. If all goes well, the *token endpoint* returns identity and access tokens to us, which we can use for various purposes. We'll decode the identity token (JWT) to store the user's ID and name in their session.

Before we're ready to do that, though, we'll need to set up our session storage and get the endpoint details via the OIDC discovery endpoint (LINK).

== Setting up OIDC

Now we need to add storail for persistent storage, as well as the HTTP client and JSON libraries.

```sh
gleam add storail@3 gleam_httpc gleam_json
```

We'll modify our context to include the session storage and OIDC configuration. 

```gleam
pub type Context {
  Context(
    session: Session,
    sessions: storail.Collection(Session),
    oidc_config: DiscoveryData,
  )
}

pub type DiscoveryData {
  DiscoveryData(authorization_endpoint: Uri, token_endpoint: Uri)
}
```

Now we can flesh out our `configure` function (TODO: update to add OidcClientConfig):

```gleam
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
```

We need decoder and "to JSON" functions for the Session and User types, to be able to read and write these to our storage, as well as a decoder for the DiscoveryData type. These can mostly be generated using the automated code actions the Gleam LSP provides. To decode the discovery data we also need to decode URIs, which can be done as follows.

```gleam
fn uri_decoder() -> decode.Decoder(Uri) {
  use str <- decode.then(decode.string)
  case uri.parse(str) {
    Ok(value) -> decode.success(value)
    Error(_) -> decode.failure(uri.empty, "Uri")
  }
}
```

Because we added an echo statement, when we run our application we should be able to see that it correctly loaded the endpoint configuration.

== Initiating the OIDC flow

First, we define our middleware in the `auth` module, which will handle the routes we need for the user to initiate the login process, for the callback from the identity provider, and for the user to log out. It will also get the user's session from storage based on a signed cookie included in the request.

```gleam
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
  todo
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
```

And we modify the router to use the middleware:

```gleam
  use req <- wisp.csrf_known_header_protection(req)

  use auth_context <- auth.middleware(req, ctx.auth)
  let ctx = Context(auth: auth_context)

  case wisp.path_segments(req) {
```

Now, our application should still run, but the login route will return a 500 error rather than a 404. Progress?

We'll use `flwr_oauth2`, an OAuth2 library that doesn't assume anything - which means we'll have to do some of the work, but there is no magic. A great fit for Gleam's philosophy.

```sh
gleam add flwr_oauth2@1
```

Using this, we can set up our login handler, which will first generate a new session ID, and create a new session in Authenticating status with a randomly generated state. The OAuth library generates the redirect for us, and we set the session cookie on the same request.

```gleam
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
```

Now the login button will take us to the identity provider's login flow, and when that completes we end up at the post-login handler, which crashes with a 500 error because we didn't implement it yet.

== Obtaining the OIDC token

TODO...

== Decoding the OIDC token

TODO...

== Logging out

TODO...
