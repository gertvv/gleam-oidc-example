#set raw(syntaxes: "gleam.sublime-syntax")

#html.elem("h1")[
  Gert van Valkenhoef
]

= Backend OpenID Connect (OIDC) authentication in Gleam

_February 2026_

In this post we'll implement a basic server-side OpenID Connect flow, the authorization code flow with client credentials. We'll use the Erlang (BEAM) back-end. This post assumes you have a basic understanding of Gleam and know how to work with JSON in Gleam.

== Prerequisites

TODO:

 - An OIDC server
 - A configured client
 - ...

== Setting up the project

First, we make sure we have the Gleam and Erlang tooling installed. I like to use #link("https://mise.jdx.dev")[mise] for this.

```sh
mise use gleam@1.14 erlang@28 rebar@3
```

We can also use mise to set environment variables, so we can set those up as well. If you care about your secrets, you should use something like #link("https://fnox.jdx.dev/")[fnox] for those instead.

```sh
mise set APP_BASE_URL=http://localhost:8080/
mise set SECRET_KEY_BASE=<random string>
mise set OIDC_SERVER_URL=<e.g. https://example.com/realms/something/>
mise set OIDC_CLIENT_ID=<client ID>
mise set OIDC_CLIENT_SECRET=<client secret>
```

Next we create a new gleam project.

```sh
gleam new . --name oidc_example
```

And then we install #link("https://hexdocs.pm/wisp/")[wisp], the web framework, and #link("https://hexdocs.pm/envoy/")[envoy], for environment variables. We'll also add some of Wisp's dependencies as direct dependencies since we'll need to import them.

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
  <form action='/login' method='post'>
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
  Context(session: #(String, Session))
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

We'll implement the #link("https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow")[authorization code flow] as follows:

 1. When the user clicks the login button, their browser does a POST request to the `/login` endpoint.
 2. On receiving this request, we generate a random state string, which we associate with user's session. We set a session cookie and perform a redirect to the *authorization endpoint* of the identity provider.
 3. The user goes through an authentication flow at the identity provider. When this is done, their browser is redirected to our application's redirect URI, which we'll implement under `/oauth/post-login`.
 4. In the post-login handler, we retrieve the user's session and check the state against the state returned to us by the identity provider. If that checks out, we perform a request to the identity provider's *token endpoint*, including the authorization code as well as our client credentials.
 5. If all goes well, the *token endpoint* returns an access tokens to us, which we can use for various purposes. We'll decode the token (JWT) to store the user's ID and name in their session.

Before we're ready to do that, though, we'll need to set up our session storage and get the endpoint details via the #link("https://auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery")[OIDC discovery endpoint].

== Setting up OIDC

Now we'll add #link("https://hexdocs.pm/storail/")[storail] for persistent storage, as well as the HTTP client and JSON libraries.

```sh
gleam add storail@3 gleam_httpc gleam_json
```

We'll modify our context to include the session storage and OIDC configuration. 

```gleam
pub type Context {
  Context(
    session: #(String, Session),
    sessions: storail.Collection(Session),
    oidc_config: DiscoveryData,
  )
}

pub type DiscoveryData {
  DiscoveryData(authorization_endpoint: Uri, token_endpoint: Uri)
}
```

Now we can flesh out our `configure` function:

```gleam
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

  echo oidc_config

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
```

We need decoder and "to JSON" functions for the Session and User types, to be able to read and write these to our storage, as well as a decoder for the `DiscoveryData` type. These can mostly be generated using the automated code actions the Gleam LSP provides. To decode the discovery data we also need to decode URIs, which can be done as follows.

```gleam
fn uri_decoder() -> decode.Decoder(Uri) {
  use str <- decode.then(decode.string)
  case uri.parse(str) {
    Ok(value) -> decode.success(value)
    Error(_) -> decode.failure(uri.empty, "Uri")
  }
}
```

Because we added an echo statement, when we run our application we should be able to see that it correctly loaded the endpoint configuration. If so, we can remove it.

== Defining authentication middleware

Next, we define our top-level middleware in the `auth` module, which will handle the routes we need for the user to initiate the login process, for the callback from the identity provider, and for the user to log out. It will also get the user's session from storage based on a signed cookie included in the request.

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

Before we implement the login flow, we'll define some authentication middleware to use in our handlers.

```gleam
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
```

And update our handlers to use said middleware, so we'll be able to see when our login has worked.

```gleam
fn home_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Get)

  { "
    <h1>🌟 Gleam OIDC Example 🌟</h1>
    <p>
      <a href='/profile'>View profile</a>
    </p>
    " <> case auth.is_authenticated(ctx.auth) {
      False ->
        "<form action='/login' method='post'><input type='submit' value='Login'/></form>"
      True ->
        "<form action='/logout' method='post'><input type='submit' value='Logout'></form>"
    } }
  |> wisp.html_response(200)
}

fn profile_handler(req: wisp.Request, ctx: Context) -> wisp.Response {
  use <- wisp.require_method(req, http.Get)
  use user <- auth.require_user(ctx.auth)

  [
    "<h1>Profile</h1>",
    "<ul><li>ID: ",
    user.id,
    "</li><li>Name: ",
    user.name,
    "</li></ul><p><a href='/'>Home</a></p>",
  ]
  |> string.join("")
  |> wisp.html_response(200)
}
```

Even at this scale concatenating strings to generate our HTML is starting to get annoying. I personally like using #link("https://hexdocs.pm/lustre/")[Lustre] on the back-end for a nice developer experience.

== Initiating the login flow

We'll use #link("https://hexdocs.pm/flwr_oauth2/")[flwr_oauth2], an OAuth2 library that doesn't assume anything - which means we'll have to do some of the work, but there is no magic. A great fit for Gleam's philosophy.

```sh
gleam add flwr_oauth2@1
```

Using this, we can set up our login handler, which will first generate a new session ID, and create a new session in Authenticating status with a randomly generated state. The state is important to protect against "man in the middle" attacks. The OAuth library generates the redirect for us, and we set the session cookie on the same request.

```gleam
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

fn set_session(ctx: Context, id: String, session: Session) -> Context {
  // if we can't write to our session store, panic
  let assert Ok(_) = storail.write(storail.key(ctx.sessions, id), session)
  Context(..ctx, session: #(id, session))
}
```

Now the login button will take us to the identity provider's login flow, and when that completes we end up at the post-login handler, which crashes with a 500 error because we didn't implement it yet.

== Obtaining the OIDC token

All sorts of things can go wrong when we handle the callback from the identity provider, so we need some helper methods. First, a convenient method for rendering an authentication error page.

```gleam
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
```

OK, now we can write the top-level callback handler, with some of the steps to be filled in later. We'll get the code and state parameters, verify the state matches what we have in our session, perform the token request, and then convert the token response to a user object, which we'll store in the session. At the end, we send the user back to the homepage.

```gleam
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
```

To verify the state, we simply look for the expected state string in an "Authenticating" session object and then compare it to the provided state string.

```gleam
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
```

To perform the token request, once again the library does the heavy lifting for us, and we just need to run the HTTP request and handle errors. We render any authentication errors returned by the identity provider nicely for the user.

```gleam
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
```

To prove the flow works, let's stub the decoding of the token.

```gleam
fn token_response_to_user(
  _res: flwr_oauth2.AccessTokenResponse,
  next: fn(User) -> wisp.Response,
) -> wisp.Response {
  next(User(id: "123", name: "Joe"))
}
```

Now, we should be able to go through the entire login flow, and we should see Joe's details on the profile page.

== Logging out

But we're not Joe (or certainly, I'm not). We'll implement the logout handler now so we can test the login flow as many times as we like. 

```gleam
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
```

It is pretty simple - if there is a non-trivial session, we delete it from storage and then set the cookie lifetime to zero. Either way, we redirect the user to the homepage. We don't log the user out of the identity provider.

== Decoding the OIDC token

To decode the JWT, we'll use #link("https://hexdocs.pm/ywt_erlang/")[ywt]. Decoding it is easy enough but verifying can get complicated, so a library is well worth it.

```sh
gleam add ywt_core@1 ywt_erlang@1
```

Let's update that function to put together our user record. I should note that while "sub" (subject) is guaranteed to be present, "name" is not. Different identity providers will put different claims in their access tokens, and you may need to request a specific scope, or you may need to call the userinfo endpoint to get this information.

```gleam
fn token_response_to_user(
  res: flwr_oauth2.AccessTokenResponse,
  next: fn(User) -> wisp.Response,
) -> wisp.Response {
  let decoder = {
    use id <- decode.field("sub", decode.string)
    use name <- decode.field("firstName", decode.string)
    decode.success(User(id:, name:))
  }
  case ywt.decode_unsafely_without_validation(res.access_token, decoder) {
    Ok(user) -> next(user)
    Error(_) -> auth_error("Unable to decode JWT", 500)
  }
}
```

Now, you'll probably notice some stern warnings in the documentation of that unsafe function we're using. In this case, we're getting the token straight from the identity provider itself, so we can trust it. But if instead we were decoding a token received from another app, we'd really need to verify it.

#html.elem("link", attrs: (rel: "stylesheet", href: "/css/gert.css?v2", type: "text/css"))
#html.elem("link", attrs: (rel: "stylesheet", href: "https://fonts.googleapis.com/css?family=Raleway", type: "text/css"))
