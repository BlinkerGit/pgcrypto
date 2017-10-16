module PGCrypto::Extensions
  module Base

    def self.included( base )
      base.instance_eval do

        # We redefine this method to correctly prepare values for encrypted columns. Original source found at
        # https://github.com/rails/rails/blob/5-1-stable/activerecord/lib/active_record/sanitization.rb#L106

        # c = connection
        # attrs.map do |attr, value|
        #   value = type_for_attribute(attr.to_s).serialize(value)
        #   "#{c.quote_table_name_for_assignment(table, attr)} = #{c.quote(value)}"
        # end.join(", ")

        def sanitize_sql_hash_for_assignment(attrs, table)
          c, pgc_table = connection, PGCrypto[table]
          attrs.map do |attr, value|
            value = type_for_attribute(attr.to_s).serialize(value)

            if pgc_table.keys.include?(attr.to_sym) && ( key = PGCrypto.keys.public_key(pgc_table[attr.to_sym]) )
              right_side = PGCrypto::Crypt.encrypt_string( value, key, c ).to_s
            else
              right_side = c.quote(value)
            end
            "#{c.quote_table_name_for_assignment(table, attr)} = #{right_side}"
          end.join(', ')
        end

      end
    end

  end
end

# Load immediately. Or load later. It's all good with us.
if defined? ActiveRecord::Base
  ActiveRecord::Base.send( :include, PGCrypto::Extensions::Base )
else
  ActiveSupport.on_load(:active_record) do
    ActiveRecord::Base.send( :include, PGCrypto::Extensions::Base )
  end
end
