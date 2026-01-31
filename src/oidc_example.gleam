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

  use auth_context <- auth.middleware(req, ctx.auth)
  let ctx = Context(auth: auth_context)

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
