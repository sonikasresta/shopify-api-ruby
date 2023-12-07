# typed: strict
# frozen_string_literal: true

module ShopifyAPI
  module Auth
    module Oauth
      extend T::Sig

      NONCE_LENGTH = 15

      TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
      ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"

      class RequestedTokenType < T::Enum
        enums do
          ONLINE_ACCESS_TOKEN = new("urn:shopify:params:oauth:token-type:online-access-token")
          OFFLINE_ACCESS_TOKEN = new("urn:shopify:params:oauth:token-type:offline-access-token")
        end
      end

      class << self
        extend T::Sig

        sig do
          params(
            shop: String,
            redirect_path: String,
            is_online: T.nilable(T::Boolean),
            scope_override: T.nilable(T.any(ShopifyAPI::Auth::AuthScopes, T::Array[String], String)),
          ).returns(T::Hash[Symbol, T.any(String, SessionCookie)])
        end
        def begin_auth(shop:, redirect_path:, is_online: true, scope_override: nil)
          scope = if scope_override.nil?
            ShopifyAPI::Context.scope
          elsif scope_override.is_a?(ShopifyAPI::Auth::AuthScopes)
            scope_override
          else
            ShopifyAPI::Auth::AuthScopes.new(scope_override)
          end

          unless Context.setup?
            raise Errors::ContextNotSetupError, "ShopifyAPI::Context not setup, please call ShopifyAPI::Context.setup"
          end
          raise Errors::UnsupportedOauthError, "Cannot perform OAuth for private apps." if Context.private?

          state = SecureRandom.alphanumeric(NONCE_LENGTH)

          cookie = SessionCookie.new(value: state, expires: Time.now + 60)

          query = {
            client_id: ShopifyAPI::Context.api_key,
            scope: scope.to_s,
            redirect_uri: "#{ShopifyAPI::Context.host}#{redirect_path}",
            state: state,
            "grant_options[]": is_online ? "per-user" : "",
          }

          query_string = URI.encode_www_form(query)

          auth_route = "https://#{shop}/admin/oauth/authorize?#{query_string}"
          { auth_route: auth_route, cookie: cookie }
        end

        sig do
          params(
            cookies: T::Hash[String, String],
            auth_query: AuthQuery,
          ).returns(T::Hash[Symbol, T.any(Session, SessionCookie)])
        end
        def validate_auth_callback(cookies:, auth_query:)
          unless Context.setup?
            raise Errors::ContextNotSetupError, "ShopifyAPI::Context not setup, please call ShopifyAPI::Context.setup"
          end
          raise Errors::InvalidOauthError, "Invalid OAuth callback." unless Utils::HmacValidator.validate(auth_query)
          raise Errors::UnsupportedOauthError, "Cannot perform OAuth for private apps." if Context.private?

          state = cookies[SessionCookie::SESSION_COOKIE_NAME]
          raise Errors::NoSessionCookieError unless state

          raise Errors::InvalidOauthError,
            "Invalid state in OAuth callback." unless state == auth_query.state

          body = { client_id: Context.api_key, client_secret: Context.api_secret_key, code: auth_query.code }

          response = begin
            access_token_request(auth_query.shop, body)
          rescue ShopifyAPI::Errors::HttpResponseError => e
            raise Errors::RequestAccessTokenError,
              "Cannot complete OAuth process. Received a #{e.code} error while requesting access token."
          end

          session_params = T.cast(response.body, T::Hash[String, T.untyped]).to_h
          session = create_new_session(session_params, auth_query.shop)

          cookie = if Context.embedded?
            SessionCookie.new(
              value: "",
              expires: Time.now,
            )
          else
            SessionCookie.new(
              value: session.id,
              expires: session.online? ? session.expires : nil,
            )
          end

          { session: session, cookie: cookie }
        end

        sig do
          params(
            shop: String,
            session_token: String,
            requested_token_type: RequestedTokenType,
          ).returns(ShopifyAPI::Auth::Session)
        end
        def token_exchange(shop:, session_token:, requested_token_type:)
          unless ShopifyAPI::Context.setup?
            raise ShopifyAPI::Errors::ContextNotSetupError,
              "ShopifyAPI::Context not setup, please call ShopifyAPI::Context.setup"
          end
          raise ShopifyAPI::Errors::UnsupportedOauthError,
            "Cannot perform OAuth Token Exchange for private apps." if ShopifyAPI::Context.private?
          raise ShopifyAPI::Errors::UnsupportedOauthError,
            "Cannot perform OAuth Token Exchange for non embedded apps." unless ShopifyAPI::Context.embedded?

          # Validate the session token content
          ShopifyAPI::Auth::JwtPayload.new(session_token)

          body = {
            client_id: ShopifyAPI::Context.api_key,
            client_secret: ShopifyAPI::Context.api_secret_key,
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
            subject_token: session_token,
            subject_token_type: ID_TOKEN_TYPE,
            requested_token_type: requested_token_type.serialize,
          }

          response = begin
            access_token_request(shop, body)
          rescue ShopifyAPI::Errors::HttpResponseError => error
            if error.code == 400 && error.response.body["error"] == "invalid_subject_token"
              raise ShopifyAPI::Errors::InvalidJwtTokenError, "Session token was rejected by token exchange"
            end

            raise error
          end

          session_params = T.cast(response.body, T::Hash[String, T.untyped]).to_h
          session = create_new_session(session_params, shop)

          session
        end

        private

        sig do
          params(shop: String,
            body: T.nilable(T.any(T::Hash[T.any(Symbol, String), T.untyped],
              String))).returns(ShopifyAPI::Clients::HttpResponse)
        end
        def access_token_request(shop, body)
          null_session = ShopifyAPI::Auth::Session.new(shop: shop)
          client = ShopifyAPI::Clients::HttpClient.new(session: null_session, base_path: "/admin/oauth")
          client.request(
              ShopifyAPI::Clients::HttpRequest.new(
                http_method: :post,
                path: "access_token",
                body: body,
                body_type: "application/json",
              ),
            )
        end

        sig { params(session_params: T::Hash[String, T.untyped], shop: String).returns(Session) }
        def create_new_session(session_params, shop)
          session_params = session_params.to_h { |k, v| [k.to_sym, v] }

          scope = session_params[:scope]

          is_online = !session_params[:associated_user].nil?

          if is_online
            associated_user = AssociatedUser.new(session_params[:associated_user].to_h { |k, v| [k.to_sym, v] })
            expires = Time.now + session_params[:expires_in].to_i
            associated_user_scope = session_params[:associated_user_scope]
            id = "#{shop}_#{associated_user.id}"
          else
            id = "offline_#{shop}"
          end

          Session.new(
            id: id,
            shop: shop,
            access_token: session_params[:access_token],
            scope: scope,
            is_online: is_online,
            associated_user_scope: associated_user_scope,
            associated_user: associated_user,
            expires: expires,
            shopify_session_id: session_params[:session],
          )
        end
      end
    end
  end
end
