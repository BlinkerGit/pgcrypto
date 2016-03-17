require 'active_record'
require 'active_record/relation'
require 'active_record/relation/query_methods'
require 'active_record/connection_adapters/postgresql_adapter'
require 'pgcrypto/has_encrypted_column'
require 'pgcrypto/key'
require 'pgcrypto/key_manager'
require 'pgcrypto/table_manager'

module PGCrypto
  def self.[](key)
    (@table_manager ||= TableManager.new)[key]
  end

  def self.base_adapter
    @base_adapter ||= ActiveRecord::ConnectionAdapters::PostgreSQLAdapter
  end

  def self.base_adapter=(base_adapter)
    @base_adapter = base_adapter
    rebuild_adapter! if respond_to?(:rebuild_adapter!)
  end

  def self.keys
    @keys ||= KeyManager.new
  end

  def self.mode
    @mode ||= :asymmetric
  end

  def self.mode=(mode)
    %i(symmetric asymmetric).include?(mode.to_sym) or raise ArgumentError.new( "Invalid value for PGCrypto mode: '#{mode}'" )
    @mode = mode.to_sym
  end
end

require 'pgcrypto/manipulation'
require 'pgcrypto/crypt'

PGCrypto.keys[:public] = {:path => '.pgcrypto'} if File.file?('.pgcrypto')

require 'pgcrypto/railtie' if defined? Rails::Railtie

# Register the built-in postgres task class for use when running rake tasks.
ActiveRecord::Tasks::DatabaseTasks.register_task( /pgcrypto/, ActiveRecord::Tasks::PostgreSQLDatabaseTasks )

# Require our ActiveRecord extensions.
require 'pgcrypto/extensions'
