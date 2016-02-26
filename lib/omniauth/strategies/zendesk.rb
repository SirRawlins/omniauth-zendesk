require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Zendesk < OmniAuth::Strategies::OAuth2
      # Custom error class for missing Account argument.
      # TODO: Refactor errors out into their own class?
      class AccountError < ArgumentError; end

      # Give your strategy a name.
      option :name, "zendesk"

      # Set full access scopes.
      option :scope, 'read write'

      # Additional token params required by Zendesk
      # to determine what type of token you want.
      option :token_params, { :grant_type => 'authorization_code' }

      # A more friendly breakdown of the
      # authenticated user data from Zendesk.
      info do; raw_info[:user]; end

      # Basic raw user data returned
      # from the Zendesk API when authenticated.
      extra do; {'raw_info' => raw_info}; end

      # Modify some settings before the request
      # phase to account for the tenanted subdomain
      # endpoints which Zendesk uses.
      def request_phase
        # Stash the account into the session so that we
        # can trieve it during the callback.
        session['omniauth.zendesk.account'] = fetch_zendesk_account

        # Prep the urls using the account ID.
        # TODO: Could we use the :setup option and a Proc
        #       to handle this rather than call here?
        set_omniauth_zendesk_urls

        # Continue the request as usual.
        super
      end

      # Modify some settings before the request
      # phase to account for the tenanted subdomain
      # endpoints which Zendesk uses.
      def callback_phase
        # Prep the urls using the account ID.
        # TODO: Could we use the :setup option and a Proc
        #       to handle this rather than call here? 
        set_omniauth_zendesk_urls

        # Continue the request as usual.
        super
      end

      def token_params
        # Merge the scope for the provider into
        # the token params request to pass to Zendesk.
        options.token_params[:scope] = options[:scope]

        # Continue the request as usual.
        super
      end

      def raw_info
        # Get the authenticated user data.
        @raw_info ||= deep_symbolize(access_token.get('/api/v2/users/me.json').parsed)
      end

      private

        # When making requests to the Zendesk oAuth we do
        # so through a tenanted URL which uses a unique subdomain.
        #
        # We pull this subdomain from the URL params.
        def fetch_zendesk_account
          # Pull the subdomain from the ?account query param.
          env["rack.request.query_hash"].fetch("account") do
            # No param 'account' was found, throw an error.
            raise AccountError.new "account key needed in query string"
          end
        end

        # The site and urls for the provider are dynamic
        # as Zendesk uses a tenanted endpoint with a per-customer
        # subdomain rather than a consistant single endppint.
        def set_omniauth_zendesk_urls
          # Pull the account from the session.
          # We cached it here at the begining of the 
          # authentication flow.
          account = session['omniauth.zendesk.account']

          # Update the client options with the dynamic endppints
          # based on the account subdomain given to us.
          options["client_options"] = {
            :site => "https://#{account}.zendesk.com",
            # TODO: Do we need to set these as absolute paths?
            :authorize_url => "https://#{account}.zendesk.com/oauth/authorizations/new",
            :token_url => "https://#{account}.zendesk.com/oauth/tokens"
          }
        end
    end
  end
end
