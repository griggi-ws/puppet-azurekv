# frozen_string_literal: true

# Taking out of puppet's Vault book
require 'puppet'
require 'net/http'
require 'json'
require 'securerandom'

module PuppetX
  module GRiggi
    module AZUREKV
      # First module for AZUREKV, to lookup a given key (and optionally version)
      class Lookup
        def self.lookup(cache:, id:, vault:, version: nil, api: 'vault.azure.net', api_version: '7.5', cache_stale: 30, ignore_cache: false, create_options: {})
          Puppet.debug '[AZUREKV]: Lookup function started'
          id = normalize_name(id: id)
          cache_key = [id, version, vault]
          cache_hash = cache.retrieve(self)
          cached_result = cache_hash[cache_key] unless ignore_cache
          cache_use = false
          if cached_result
            # ! Not currently working as expected, cache behavior is not documented and the only usage I found is in Puppet's Hashicorp Vault module
            # https://github.com/voxpupuli/puppet-vault_lookup/pull/65
            # https://tickets.puppetlabs.com/browse/PUP-8676
            if (cached_result['date'] <=> Time.now - (cache_stale * 60)) == 1
              Puppet.debug '[AZUREKV]: Returning cached value that is still fresh'
              cache_use = true
              return cached_result['data']
            end
            Puppet.debug '[AZUREKV]: Cached value is stale, fetching new one'
          end
          result = get_secret(id: id,
                              version: version,
                              vault: vault,
                              api: api,
                              api_version: api_version,
                              create_options: create_options)
          Puppet.debug '[AZUREKV]: Sensitive secret returned.'
          to_cache = {
            data: result,
            date: Time.now
          }
          if cache_use
            cache_hash[cache_key] = to_cache
            Puppet.debug '[AZUREKV]: New value stored in cache'
          end
          Puppet.info "[AZUREKV]: Successfully looked up value of #{id} in vault #{vault} (cache hit: #{cache_use})"
          result
        end

        def self.get_token_msi(api:, api_version: '2018-02-01')
          uri = URI("http://169.254.169.254/metadata/identity/oauth2/token?api-version=#{api_version}&resource=https://#{api}")
          request = Net::HTTP::Get.new(uri.request_uri)
          request['Metadata'] = 'true'
          response = Net::HTTP.start(uri.hostname, uri.port) do |http|
            http.request(request)
          end
          raise response.body unless response.is_a?(Net::HTTPSuccess)

          JSON.parse(response.body)['access_token']
        end

        def self.normalize_name(id:, sub: '-')
          Puppet.debug '[AZUREKV]: normalize_name function started'
          id.gsub('/', sub + sub).gsub(/[^a-zA-Z0-9-]/, sub)
        end

        def self.get_random_password(password_length: 32, exclude_characters: '\'";\\{}@', exclude_numbers: false, exclude_punctuation: false, exclude_uppercase: false, exclude_lowercase: false, include_space: false, require_each_included_type: true)
          Puppet.debug '[AZUREKV]: get_random_password function started'
          symbols = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
          inclusions = [*'A'..'Z', *'a'..'z', *'0'..'9', *symbols.chars]
          exclusions = [exclude_characters.chars]
          exclusions.push(*'0'..'9') if exclude_numbers
          exclusions.push(symbols.chars) if exclude_punctuation
          exclusions.push(*'A'..'Z') if exclude_uppercase
          exclusions.push(*'a'..'z') if exclude_lowercase
          SecureRandom.send(:choose, inclusions - exclusions,
                            password_length)
        end

        def self.create_secret(id:, vault:, api:, api_version:, options: {})
          Puppet.debug '[AZUREKV]: create_secret function started'
          uri = URI("https://#{vault}.#{api}/secrets/#{id}?api-version=#{api_version}")
          request = Net::HTTP::Put.new(uri.request_uri)
          request['Authorization'] = "Bearer #{get_token_msi(api: api)}"
          request['Content-Type'] = 'application/json'
          secret = get_random_password({
                                         password_length: options['password_length'] || 32,
                                         exclude_characters: options['exclude_characters'] || '\'";\\{}@',
                                         exclude_numbers: options['exclude_numbers'] || false,
                                         exclude_punctuation: options['exclude_punctuation'] || false,
                                         exclude_uppercase: options['exclude_uppercase'] || false,
                                         exclude_lowercase: options['exclude_lowercase'] || false,
                                         include_space: options['include_space'] || false,
                                         require_each_included_type: options['require_each_included_type'] || true
                                       })
          data = {
            'value': secret,
            'tags': {
              'description': options['description'] || 'Created by Puppet'
            }
          }
          request.body = data.to_json
          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
            http.request(request)
          end
          unless response.is_a?(Net::HTTPSuccess)
            raise Puppet::Error, "[AZUREKV]: Error when creating #{id}: #{response.body}"
          end

          Puppet::Pops::Types::PSensitiveType::Sensitive.new(secret)
        end

        def self.get_secret(id:, version:, create_options:, vault:, api:, api_version:)
          Puppet.debug '[AZUREKV]: get_secret function started'
          Puppet.debug "Called with: id: #{id} version: #{version} vault: #{vault} api: #{vault} create_options: #{create_options}"
          response = nil
          uri = URI("https://#{vault}.#{api}/secrets/#{id}/#{version}?api-version=#{api_version}")
          request = Net::HTTP::Get.new(uri.request_uri)
          request['Authorization'] = "Bearer #{get_token_msi(api: api)}"
          begin
            response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
              http.request(request)
            end
          rescue Net::HTTPNotFound
            unless create_options['create_missing']
              raise Puppet::Error,
                    "[AZUREKV]: No matching key #{id} + version #{version} found, and creating a missing secret is not enabled."
            end
            # this can be changed to omit keyword argument repetition with ruby 3.1, so dropping puppet <=7 support.
            return create_secret(id: id, options: create_options, vault: vault, api: api, api_version: api_version)
          end
          unless response.is_a?(Net::HTTPSuccess)
            raise Puppet::Error, "[AZUREKV]: Non-specific error when looking up #{id}: #{response.body}"
          end

          Puppet.debug '[AZUREKV]: Response received.'
          secret = JSON.parse(response.body['value'])
          Puppet.debug '[AZUREKV]: Returning secret as sensitive.'
          Puppet::Pops::Types::PSensitiveType::Sensitive.new(secret)
        end
      end
    end
  end
end
