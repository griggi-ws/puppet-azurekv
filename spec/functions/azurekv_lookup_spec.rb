# frozen_string_literal: true

require 'spec_helper'
require 'net/http'
require 'puppet_x/griggi/azurekv/lookup'

describe PuppetX::GRiggi::AZUREKV::Lookup do
  let(:cache) { double('cache') }
  let(:cache_hash) { {} }
  let(:http_response) { double('http_response') }
  let(:secret_value) { 'super-secret-value' }
  let(:secret_id) { 'test-secret-key' }
  let(:vault) { 'test-vault' }
  let(:api) { 'vault.azure.net' }
  let(:api_version) { '7.5' }
  let(:access_token) { 'mock-access-token' }

  before(:each) do
    allow(cache).to receive(:retrieve).with(described_class).and_return(cache_hash)

    # Mock MSI token retrieval
    token_response = double('token_response', body: { 'access_token' => access_token }.to_json)
    allow(token_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)

    msi_http = double('msi_http')
    allow(msi_http).to receive(:request).and_return(token_response)
    allow(Net::HTTP).to receive(:start).with('169.254.169.254', 80).and_yield(msi_http)
  end

  describe '.lookup' do
    context 'when secret is not cached' do
      it 'fetches secret from Azure and returns sensitive value' do
        response_body = { 'value' => secret_value }.to_json
        allow(http_response).to receive(:body).and_return(response_body)
        allow(http_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(http_response).to receive(:value).and_return(nil)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(http_response)
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        result = described_class.lookup(
          cache: cache,
          id: secret_id,
          vault: vault,
          api: api,
          api_version: api_version
        )

        expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
        expect(result.unwrap).to eq(secret_value)
      end

      it 'stores the fetched secret in cache for future lookups' do
        response_body = { 'value' => secret_value }.to_json
        allow(http_response).to receive(:body).and_return(response_body)
        allow(http_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(http_response).to receive(:value).and_return(nil)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(http_response)
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        described_class.lookup(
          cache: cache,
          id: secret_id,
          vault: vault,
          api: api,
          api_version: api_version
        )

        # Verify the secret was stored in cache
        cache_key = [secret_id, nil, vault]
        expect(cache_hash[cache_key]).not_to be_nil
        expect(cache_hash[cache_key].unwrap).to eq(secret_value)
      end

      it 'normalizes the secret name' do
        unnormalized_id = 'test/secret/key'
        normalized_id = 'test--secret--key'
        response_body = { 'value' => secret_value }.to_json
        allow(http_response).to receive(:body).and_return(response_body)
        allow(http_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(http_response).to receive(:value).and_return(nil)

        # Expect the normalized ID in the URL
        vault_http = double('vault_http')
        expect(vault_http).to receive(:request) do |request|
          expect(request.path).to match(%r{/secrets/#{normalized_id}/})
          http_response
        end
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        described_class.lookup(
          cache: cache,
          id: unnormalized_id,
          vault: vault,
          api: api,
          api_version: api_version
        )
      end

      it 'requests specific version when provided' do
        version_id = 'version-123'
        response_body = { 'value' => secret_value }.to_json
        allow(http_response).to receive(:body).and_return(response_body)
        allow(http_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(http_response).to receive(:value).and_return(nil)

        vault_http = double('vault_http')
        expect(vault_http).to receive(:request) do |request|
          expect(request.path).to match(%r{/secrets/#{secret_id}/#{version_id}})
          http_response
        end
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        described_class.lookup(
          cache: cache,
          id: secret_id,
          vault: vault,
          version: version_id,
          api: api,
          api_version: api_version
        )
      end
    end

    context 'when secret is cached' do
      let(:cached_data) { Puppet::Pops::Types::PSensitiveType::Sensitive.new(secret_value) }

      before(:each) do
        cache_hash[[secret_id, nil, vault]] = cached_data
      end

      it 'returns cached value without calling Azure' do
        expect(Net::HTTP).not_to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true)

        result = described_class.lookup(
          cache: cache,
          id: secret_id,
          vault: vault,
          api: api,
          api_version: api_version
        )

        expect(result.unwrap).to eq(secret_value)
      end
    end

    context 'when ignore_cache is true' do
      let(:cached_data) { Puppet::Pops::Types::PSensitiveType::Sensitive.new('cached-value') }

      before(:each) do
        cache_hash[[secret_id, nil, vault]] = cached_data
      end

      it 'fetches value from Azure even when cache exists' do
        response_body = { 'value' => secret_value }.to_json
        allow(http_response).to receive(:body).and_return(response_body)
        allow(http_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(http_response).to receive(:value).and_return(nil)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(http_response)
        expect(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        result = described_class.lookup(
          cache: cache,
          id: secret_id,
          vault: vault,
          api: api,
          api_version: api_version,
          ignore_cache: true
        )

        expect(result.unwrap).to eq(secret_value)
      end
    end
  end

  describe '.get_secret' do
    context 'when secret exists' do
      it 'returns the secret as a Sensitive value' do
        response_body = { 'value' => secret_value }.to_json
        allow(http_response).to receive(:body).and_return(response_body)
        allow(http_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(http_response).to receive(:value).and_return(nil)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(http_response)
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        result = described_class.get_secret(
          id: secret_id,
          version: nil,
          vault: vault,
          api: api,
          api_version: api_version,
          create_options: {}
        )

        expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
        expect(result.unwrap).to eq(secret_value)
      end
    end

    context 'when secret does not exist' do
      let(:not_found_response) { double('not_found_response', body: 'Not Found') }

      before(:each) do
        allow(not_found_response).to receive(:is_a?).with(Net::HTTPNotFound).and_return(true)
        allow(not_found_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(false)
        allow(not_found_response).to receive(:value).and_raise(Net::HTTPServerException.new('404', not_found_response))
      end

      context 'and create_missing is not enabled' do
        it 'raises a Puppet::Error' do
          vault_http = double('vault_http')
          allow(vault_http).to receive(:request).and_return(not_found_response)
          allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

          expect do
            described_class.get_secret(
              id: secret_id,
              version: nil,
              vault: vault,
              api: api,
              api_version: api_version,
              create_options: {}
            )
          end.to raise_error(Puppet::Error, /No matching key.*and creating a missing secret is not enabled/)
        end
      end

      context 'and create_missing is enabled' do
        let(:create_options) do
          {
            'create_missing' => true,
            'password_length' => 16
          }
        end

        it 'creates a new secret' do
          # Mock get_random_password to avoid issues with SecureRandom
          generated_password = 'generated-password-16'
          allow(described_class).to receive(:get_random_password).and_return(generated_password)

          # Mock the GET request that returns 404
          get_http = double('get_http')
          allow(get_http).to receive(:request).and_return(not_found_response)

          # Mock the PUT request for creating the secret
          create_response_body = { 'value' => generated_password }.to_json
          create_response = double('create_response', body: create_response_body)
          allow(create_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)

          put_http = double('put_http')
          allow(put_http).to receive(:request).and_return(create_response)

          # Mock both HTTP.start calls - first for GET (returns 404), second for PUT (creates secret)
          call_count = 0
          allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true) do |&block|
            call_count += 1
            if call_count == 1
              block.call(get_http)
            else
              block.call(put_http)
            end
          end

          result = described_class.get_secret(
            id: secret_id,
            version: nil,
            vault: vault,
            api: api,
            api_version: api_version,
            create_options: create_options
          )

          expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
          expect(result.unwrap).to eq(generated_password)
        end
      end
    end

    context 'when Azure encounters a server error' do
      it 'raises a Puppet::Error with error details' do
        error_response = double('error_response', body: 'Service unavailable')
        allow(error_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(false)
        allow(error_response).to receive(:is_a?).with(Net::HTTPNotFound).and_return(false)
        allow(error_response).to receive(:value).and_raise(Net::HTTPServerException.new('500', error_response))

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(error_response)
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        expect do
          described_class.get_secret(
            id: secret_id,
            version: nil,
            vault: vault,
            api: api,
            api_version: api_version,
            create_options: {}
          )
        end.to raise_error(Puppet::Error, /Non-specific error when looking up/)
      end
    end
  end

  describe '.create_secret' do
    let(:random_password) { 'randomly-generated-password' }
    let(:create_response) do
      double('create_response', body: { 'value' => random_password }.to_json)
    end

    before(:each) do
      allow(create_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
      allow(described_class).to receive(:get_random_password).and_return(random_password)
    end

    context 'with default options' do
      it 'creates a secret with default parameters' do
        expect(described_class).to receive(:get_random_password).with(hash_including({
                                                                                       password_length: 32,
                                                                                       exclude_characters: '\'";\\{}@',
                                                                                       exclude_numbers: false,
                                                                                       exclude_punctuation: false,
                                                                                       exclude_uppercase: false,
                                                                                       exclude_lowercase: false,
                                                                                       include_space: false,
                                                                                       require_each_included_type: true
                                                                                     })).and_return(random_password)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(create_response)
        expect(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        result = described_class.create_secret(
          id: secret_id,
          vault: vault,
          api: api,
          api_version: api_version
        )

        expect(result).to be_a(Puppet::Pops::Types::PSensitiveType::Sensitive)
        expect(result.unwrap).to eq(random_password)
      end
    end

    context 'with custom options' do
      let(:options) do
        {
          'password_length' => 16,
          'exclude_characters' => '!@#',
          'exclude_numbers' => true,
          'description' => 'Custom description'
        }
      end

      it 'creates a secret with custom parameters' do
        expect(described_class).to receive(:get_random_password).with(hash_including({
                                                                                       password_length: 16,
                                                                                       exclude_characters: '!@#',
                                                                                       exclude_numbers: true
                                                                                     })).and_return(random_password)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(create_response)
        expect(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        result = described_class.create_secret(
          id: secret_id,
          vault: vault,
          api: api,
          api_version: api_version,
          options: options
        )

        expect(result.unwrap).to eq(random_password)
      end
    end

    context 'when secret creation fails' do
      it 'raises a Puppet::Error on server error' do
        error_response = double('error_response', body: 'Error creating secret')
        allow(error_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(false)

        vault_http = double('vault_http')
        allow(vault_http).to receive(:request).and_return(error_response)
        allow(Net::HTTP).to receive(:start).with("#{vault}.#{api}", 443, use_ssl: true).and_yield(vault_http)

        expect do
          described_class.create_secret(
            id: secret_id,
            vault: vault,
            api: api,
            api_version: api_version
          )
        end.to raise_error(Puppet::Error, /Error when creating/)
      end
    end
  end

  describe '.normalize_name' do
    it 'replaces forward slashes with double dashes' do
      expect(described_class.normalize_name(id: 'test/secret/key')).to eq('test--secret--key')
    end

    it 'replaces special characters with dashes' do
      expect(described_class.normalize_name(id: 'test@secret$key')).to eq('test-secret-key')
    end

    it 'keeps alphanumeric characters and dashes' do
      expect(described_class.normalize_name(id: 'test-secret-123')).to eq('test-secret-123')
    end

    it 'can use custom substitution character' do
      expect(described_class.normalize_name(id: 'test/key', sub: '_')).to eq('test__key')
    end
  end

  describe '.get_random_password' do
    it 'generates password of specified length' do
      password = described_class.get_random_password(password_length: 16)
      expect(password.length).to eq(16)
    end

    it 'excludes specified characters' do
      password = described_class.get_random_password(
        password_length: 100,
        exclude_characters: 'abc'
      )
      expect(password).not_to include('a', 'b', 'c')
    end

    it 'excludes numbers when requested' do
      password = described_class.get_random_password(
        password_length: 100,
        exclude_numbers: true
      )
      expect(password).not_to match(/\d/)
    end

    it 'excludes punctuation when requested' do
      password = described_class.get_random_password(
        password_length: 100,
        exclude_punctuation: true
      )
      expect(password).not_to match(%r{[!"#$%&'()*+,\-./\\:;<=>?@\[\]^_`{|}~]})
    end

    it 'excludes uppercase when requested' do
      password = described_class.get_random_password(
        password_length: 100,
        exclude_uppercase: true
      )
      expect(password).not_to match(/[A-Z]/)
    end

    it 'excludes lowercase when requested' do
      password = described_class.get_random_password(
        password_length: 100,
        exclude_lowercase: true
      )
      expect(password).not_to match(/[a-z]/)
    end
  end

  describe '.get_token_msi' do
    it 'retrieves an access token from the MSI endpoint' do
      token_response_body = { 'access_token' => access_token }.to_json
      token_response = double('token_response', body: token_response_body)
      allow(token_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)

      msi_http = double('msi_http')
      allow(msi_http).to receive(:request).and_return(token_response)
      expect(Net::HTTP).to receive(:start).with('169.254.169.254', 80).and_yield(msi_http)

      result = described_class.get_token_msi(api: api)
      expect(result).to eq(access_token)
    end

    it 'raises an error when token retrieval fails' do
      error_response = double('error_response', body: 'Unauthorized')
      allow(error_response).to receive(:is_a?).with(Net::HTTPSuccess).and_return(false)
      msi_http = double('msi_http')
      allow(msi_http).to receive(:request).and_return(error_response)
      allow(Net::HTTP).to receive(:start).with('169.254.169.254', 80).and_yield(msi_http)

      expect do
        described_class.get_token_msi(api: api)
      end.to raise_error(RuntimeError, 'Unauthorized')
    end
  end
end
