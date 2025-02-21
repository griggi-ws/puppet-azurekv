# frozen_string_literal: true

require_relative '../../../puppet_x/griggi/azurekv/lookup'

Puppet::Functions.create_function(:'azurekv::lookup', Puppet::Functions::InternalFunction) do
  dispatch :lookup do
    cache_param # Completely undocumented feature that I can only find implemented in a single official Puppet module? Sure why not let's try it
    param 'String', :id
    optional_param 'Optional[String]', :vault
    optional_param 'Optional[String]', :version
    optional_param 'Optional[String]', :api
    optional_param 'Optional[String]', :api_version
    optional_param 'Optional[Number]', :cache_stale
    optional_param 'Optional[Boolean]', :ignore_cache
    optional_param 'Optional[Hash]', :create_options
    return_type 'Sensitive'
  end

  # Allows for passing a hash of options to the vault_lookup::lookup() function.
  #
  # @example
  #  $foo = azurekv::lookup('secret/some/path/foo',
  #    { 'version' => 'AWSPREVIOUS', 'region' => 'us-east-1' }
  #  )
  #
  dispatch :lookup_opts_hash do
    cache_param
    param 'String[1]', :id
    param 'Hash[String[1], Data]', :options
    return_type 'Sensitive'
  end

  # Lookup with a path and an options hash. The use of undef/nil in positional parameters with a deferred call appears to not work, so we need this.
  # Be sure to also update the default values in the azurekv::lookup function, as those will be used in the case that an options hash is passed without
  # all values defined.
  def lookup_opts_hash(cache, id, options = { 'vault' => nil,
                                              'api' => nil,
                                              'version' => nil,
                                              'cache_stale' => 30,
                                              'ignore_cache' => false,
                                              'create_options' => {
                                                'create_missing' => true,
                                                'password_length' => 32,
                                                'exclude_characters' => '\'";\\{}@',
                                                'exclude_numbers' => false,
                                                'exclude_punctuation' => false,
                                                'exclude_uppercase' => false,
                                                'exclude_lowercase' => false,
                                                'include_space' => false,
                                                'require_each_included_type' => true
                                              } })

    Puppet.debug '[AZUREKV]: Looking up vault to use'
    vault_lookup = [closure_scope['facts']&.fetch('azurekv_vault', nil)]
    begin
      hiera = call_function('lookup', 'azurekv_vault', nil, nil, 'default')
      vault_lookup.push(hiera)
    rescue StandardError => e
      Puppet.debug "[AZUREKV]: Puppet `lookup` function inaccessible, error #{e}"
    end

    Puppet.debug "[AZUREKV]: vault_lookup value is #{vault_lookup}"

    Puppet.debug '[AZUREKV]: Looking up API to use'
    api_lookup = [closure_scope['facts']&.fetch('azurekv_api', nil)]
    begin
      hiera = call_function('lookup', 'azurekv_api', nil, nil, 'vault.microsoft.net')
      api_lookup.push(hiera)
    rescue StandardError => e
      Puppet.debug "[AZUREKV]: Puppet `lookup` function inaccessible, error #{e}"
    end

    Puppet.debug "[AZUREKV]: api_lookup value is #{api_lookup}"

    # Things we don't want to be `nil` if not passed in the initial call
    options['vault'] ||= vault_lookup.compact.first
    options['api'] ||= api_lookup.compact.first
    options['api_version'] ||= '7.5'
    options['cache_stale'] ||= 30
    options['ignore_cache'] ||= false
    # NOTE: The order of these options MUST be the same as the lookup()
    # function's signature. If new parameters are added to lookup(), or if the
    # order of existing parameters change, those changes must also be made
    # here.

    Puppet.debug "[AZUREKV]: Calling lookup function in vault #{options['vault']} using api #{options['api']}"
    PuppetX::GRiggi::AZUREKV::Lookup.lookup(cache: cache,
                                            id: id,
                                            vault: options['vault'],
                                            version: options['version'],
                                            api: options['api'],
                                            api_version: options['api_version'],
                                            cache_stale: options['cache_stale'],
                                            ignore_cache: options['ignore_cache'],
                                            create_options: options['create_options'])
  end

  # Lookup with a path and positional arguments.
  # NOTE: If new parameters are added, or if the order of existing parameters
  # change, those changes must also be made to the lookup() call in
  # lookup_opts_hash().
  def lookup(cache,
             id,
             vault = nil,
             version = nil,
             api = nil,
             api_version = '7.5',
             cache_stale = 30,
             ignore_cache = false,
             create_options = {
               'create_missing' => true,
               'password_length' => 32,
               'exclude_characters' => '\'";\\{}@',
               'exclude_numbers' => false,
               'exclude_punctuation' => false,
               'exclude_uppercase' => false,
               'exclude_lowercase' => false,
               'include_space' => false,
               'require_each_included_type' => true
             })
    Puppet.debug '[AZUREKV]: Looking up vault to use'
    vault_lookup = [closure_scope['facts']&.fetch('azurekv_vault', nil)]
    begin
      hiera = call_function('lookup', 'azurekv_vault', nil, nil, 'default')
      vault_lookup.push(hiera)
    rescue StandardError => e
      Puppet.debug "[AZUREKV]: Puppet `lookup` function inaccessible, error #{e}"
    end
    Puppet.debug "[AZUREKV]: vault_lookup value is #{vault_lookup}"

    Puppet.debug '[AZUREKV]: Looking up API to use'
    api_lookup = [closure_scope['facts']&.fetch('azurekv_api', nil)]
    begin
      hiera = call_function('lookup', 'azurekv_api', nil, nil, 'vault.microsoft.net')
      api_lookup.push(hiera)
    rescue StandardError => e
      Puppet.debug "[AZUREKV]: Puppet `lookup` function inaccessible, error #{e}"
    end

    Puppet.debug "[AZUREKV]: api_lookup value is #{api_lookup}"

    vault ||= vault_lookup.compact.first
    api ||= api_lookup.compact.first
    Puppet.debug "[AZUREKV]: Calling lookup function in vault #{vault} using api #{api}"

    PuppetX::GRiggi::AZUREKV::Lookup.lookup(cache: cache,
                                            id: id,
                                            vault: vault,
                                            version: version,
                                            api: api,
                                            api_version: api_version,
                                            cache_stale: cache_stale,
                                            ignore_cache: ignore_cache,
                                            create_options: create_options)
  end
end
