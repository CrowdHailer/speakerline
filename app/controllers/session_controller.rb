
class SessionController < ApplicationController

  def authenticate
    config = OpenIDConnect::Discovery::Provider::Config.discover! "https://did.app"

    client = OpenIDConnect::Client.new({
      identifier: ENV["CLIENT_ID"],
      secret: ENV["CLIENT_SECRET"],
      redirect_uri: "http://localhost:3000/session/callback",
      issuer: config.issuer,
      authorization_endpoint: config.authorization_endpoint,
      jwks_uri: config.jwks_uri,
      token_endpoint: config.token_endpoint,
    })
    redirect_to client.authorization_uri()
  end

  def callback
    config = OpenIDConnect::Discovery::Provider::Config.discover! "https://did.app"

    client = OpenIDConnect::Client.new({
      identifier: ENV["CLIENT_ID"],
      secret: ENV["CLIENT_SECRET"],
      redirect_uri: "http://localhost:3000/session/callback",
      issuer: config.issuer,
      authorization_endpoint: config.authorization_endpoint,
      jwks_uri: config.jwks_uri,
      token_endpoint: config.token_endpoint,
    })
    code = params["code"]
    client.authorization_code = code
    tokens = client.access_token!

    id_token = OpenIDConnect::ResponseObject::IdToken.decode tokens.id_token, config.jwks
    id_token.verify!(issuer: config.issuer, client_id: client.identifier)
    session[:current_user_id] = id_token.subject
    redirect_to root_path
  end
  def terminate
    session[:current_user_id] = nil
    redirect_to root_path
  end

end
