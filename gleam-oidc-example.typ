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
mise set SECRET_KEY_BASE=<random string>
mise set OIDC_SERVER_URL=<e.g. https://example.com/realms/something/>
mise set OIDC_CLIENT_ID=<client ID>
mise set OIDC_CLIENT_SECRET=<client secret>
```

Next we create a new gleam project.

```sh
gleam new . --name oidc_example
```

And then we install Wisp, the web framework, and storail, for simple persistent storage. We're also going to import envoy (environment variables), and some other transitive dependencies, so we'll add those now too.

```sh
gleam add wisp@2 storail@3 envoy gleam_http gleam_json mist gleam_erlang
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
