module PGCrypto
  module Crypt # Encapsulate these methods so they may be called from various locations.
    class << self
      def decrypt_column(table_name, column_name, key)
        column = Arel::Attribute.new(Arel::Table.new(table_name), column_name)
        case PGCrypto.mode
        when :asymmetric
          key_literal = Arel::Nodes::SqlLiteral.new("#{key.dearmored}#{key.password?}")
          Arel::Nodes::NamedFunction.new('pgp_pub_decrypt', [column, key_literal])
        when :symmetric
          key_literal = Arel::Nodes::SqlLiteral.new("'#{key}'")
          Arel::Nodes::NamedFunction.new('pgp_sym_decrypt', [column, key_literal])
        end
      end

      def encrypt_string(string, key, quoter = nil)
        quoter ||= ActiveRecord::Base.connection
        encryption_instruction = case PGCrypto.mode
        when :asymmetric
          %[pgp_pub_encrypt(#{quoter.quote(string)}, #{key.dearmored})]
        when :symmetric
          %[pgp_sym_encrypt(#{quoter.quote(string)}, '#{key}')]
        end
        Arel::Nodes::SqlLiteral.new(encryption_instruction)
      end

    end
  end
end
