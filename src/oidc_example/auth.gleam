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
