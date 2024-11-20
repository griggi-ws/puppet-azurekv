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
        def self.lookup(cache:, id:, region: 'us-east-2', version: nil, cache_stale: 30, ignore_cache: false, create_options: {})
          Puppet.debug '[AZUREKV]: Lookup function started'
          cache_key = [id, version, region]
          cache_hash = cache.retrieve(self)
          cached_result = cache_hash[cache_key] unless ignore_cache
          cache_use = false
          if cached_result
            # ! Not currently working as expected
            if (cached_result['date'] <=> Time.now - (cache_stale * 60)) == 1
              Puppet.debug '[AZUREKV]: Returning cached value that is still fresh'
              cache_use = true
              return cached_result['data']
            end
            Puppet.debug '[AZUREKV]: Cached value is stale, fetching new one'
          end
          result = get_secret(id:,
                              version:,
                              region:,
                              create_options:)
          Puppet.debug '[AZUREKV]: Sensitive secret returned.'
          to_cache = {
            data: result,
            date: Time.now
          }
          if cache_use
            cache_hash[cache_key] = to_cache
            Puppet.debug '[AZUREKV]: New value stored in cache'
          end
          Puppet.info "[AZUREKV]: Successfully looked up value of #{id} in region #{region} (cache hit: #{cache_use})"
          result
        end

        def self.get_token_msi(resource: 'https://vault.usgovcloudapi.net', api_version: '2018-02-01')
          uri = URI("http://169.254.169.254/metadata/identity/oauth2/token?api-version=#{api_version}&resource=#{resource}")
          req = Net::HTTP::Get.new(uri.request_uri)
          req['Metadata'] = 'true'
          response = Net::HTTP.start(uri.hostname, uri.port) do |http|
            http.request(req)
          end
          raise res.body unless res.is_a?(Net::HTTPSuccess)

          JSON.parse(response.body)['access_token']
        end

        def self.get_random_password(password_length: 32, exclude_characters: '\'";\\{}@', exclude_numbers: false, exclude_punctuation: false, exclude_uppercase: false, exclude_lowercase: false, include_space: false, require_each_included_type: true)
          Puppet.debug '[AZUREKV]: get_random_password function started'
          SecureRandom.send(:choose, [] - [], password_length)
        end

        def self.create_secret(id:, region:, options: {}, vault:, api:, api_version:)
          Puppet.debug '[AZUREKV]: create_secret function started'
          uri = URI("https://#{vault}.#{api}/secrets/#{id}?api-version=#{api_version}")
          request = Net::HTTP::Put.new(uri.request_uri)
          request['Authorization'] = "Bearer #{get_token_msi}"
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
            raise Puppet::Error, "[AZUREKV]: Non-specific error when looking up #{id}: #{response.body}"
          end

          Puppet::Pops::Types::PSensitiveType::Sensitive.new(secret)
        end

        def self.get_secret(id:, version:, region:, create_options:, vault:, api:, api_version:)
          Puppet.debug '[AZUREKV]: get_secret function started'
          Puppet.debug "Called with: id: #{id} version: #{version} region: #{region} create_options: #{create_options}"
          secret = nil
          response = nil
          uri = URI("https://#{vault}.#{api}/secrets/#{id}/#{version}?api-version=#{api_version}")
          req = Net::HTTP::Get.new(uri.request_uri)
          req['Authorization'] = "Bearer #{get_token_msi}"
          begin
            response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
              http.request(req)
            end
          rescue Net::HTTPNotFound
            unless create_options['create_missing']
              raise Puppet::Error,
                    "[AZUREKV]: No matching key #{id} + version #{version} found, and creating a missing secret is not enabled."
            end

            return create_secret(id:, region:, options: create_options, vault:, api:, api_version:)
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
