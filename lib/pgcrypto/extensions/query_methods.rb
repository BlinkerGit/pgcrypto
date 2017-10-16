module PGCrypto::Extensions
  module QueryMethods
    def self.included( base )
      base.module_eval do

        # We override this method to allow ordering by an encrypted column.
        # Original source can be found at
        # https://github.com/rails/rails/blob/5-1-stable/activerecord/lib/active_record/relation/query_methods.rb#L1115
        def preprocess_order_args(order_args)
          order_args.map! do |arg|
            klass.send(:sanitize_sql_for_order, arg)
          end
          order_args.flatten!
          validate_order_args(order_args)

          pgc_table = PGCrypto[table_name]

          references = order_args.grep(String)
          references.map! { |arg| arg =~ /^([a-zA-Z]\w*)\.(\w+)/ && $1 }.compact!
          references!(references) if references.any?

          order_args.map! do |arg|
            case arg
            when Symbol
              arg = klass.attribute_alias(arg) if klass.attribute_alias?(arg)
              if pgc_table.keys.include?( arg ) && ( key = PGCrypto.keys.private_key( pgc_table[arg] ) )
                decrypt_sql = PGCrypto::Crypt.decrypt_column( table_name, arg.to_s, key ).to_sql
                Arel::Nodes::SqlLiteral.new( "#{decrypt_sql} ASC" )
              else
                table[arg].asc
              end
            when Hash
              arg.map do |field, dir|
                field = klass.attribute_alias(field) if klass.attribute_alias?(field)
                if pgc_table.keys.include?( field.to_sym ) && ( key = PGCrypto.keys.private_key( pgc_table[field.to_sym] ) )
                  decrypt_sql = PGCrypto::Crypt.decrypt_column( table_name, field.to_s, key ).to_sql
                  Arel::Nodes::SqlLiteral.new( "#{decrypt_sql} #{dir.upcase}" )
                else
                  table[field].send(dir.downcase)
                end
              end
            when String
              arg.split(',').map do |a|
                output = a.dup
                pgc_table.keys.each do |col_name|
                  next unless key = PGCrypto.keys.private_key( pgc_table[col_name] )
                  pattern = Regexp.new "(?<![a-zA-Z0-9_\\.])(#{table_name}\\.)?#{col_name}(?![a-zA-Z0-9_])"
                  output.gsub!( pattern, PGCrypto::Crypt.decrypt_column( table_name, col_name, key ).to_sql )
                end
                (references - [table_name]).uniq.each do |ref_table|
                  # If we are referencing a different table from this string, check to see if that table also has an encrypted column.
                  next unless (pgc_ref_table = PGCrypto[ref_table]).present?
                  pgc_ref_table.keys.each do |ref_col|
                    next unless ref_key = PGCrypto.keys.private_key( pgc_ref_table[ref_col] )
                    pattern = Regexp.new "(?<![a-zA-Z0-9_\\.])#{table_name}\\.#{col_name}(?![a-zA-Z0-9_])" # slightly different to match ONLY qualified references
                    output.gsub!( pattern, PGCrypto::Crypt.decrypt_column( ref_table, ref_col, ref_key ).to_sql )
                  end
                end
                output
              end.join(',')
            when Arel::Nodes::Ascending, Arel::Nodes::Descending
              rel_table, rel_column = arg.expr.relation.name, arg.expr.name.to_sym
              # There may be nodes here for tables other than the one indicated by the current table_name.
              pgc_rel_table = PGCrypto[rel_table]
              if pgc_rel_table && pgc_rel_table.keys.include?( rel_column ) && ( rel_key = PGCrypto.keys.private_key( pgc_rel_table[rel_column] ) )
                dir = ( Arel::Nodes::Descending === arg ? 'DESC' : 'ASC' )
                decrypt_sql = PGCrypto::Crypt.decrypt_column( rel_table, rel_column.to_s, key ).to_sql
                Arel::Nodes::SqlLiteral.new( "#{decrypt_sql} #{dir}" )
              else
                arg
              end
            when nil
              nil
            else
              arg
              # raise "Unexpected class passed to preprocess_order_args: #{arg.class.to_s}!"
            end
          end.flatten!
        end

        # We override this method to preprocess any SQL fragment that was
        # passed. Original source found at
        # https://github.com/rails/rails/blob/5-1-stable/activerecord/lib/active_record/relation/query_methods.rb#L609
        def where!(opts, *rest)
          opts = sanitize_forbidden_attributes(opts)
          case opts
          when Hash
            references!(ActiveRecord::PredicateBuilder.references(opts))
          when String
            pgc_table = PGCrypto[table_name]
            if pgc_table && (columns = pgc_table.keys).present?
              opts = opts.dup.tap do |output|
                columns.each do |col_name|
                  next unless key = PGCrypto.keys.private_key(pgc_table[col_name])
                  pattern = Regexp.new "(?<![a-zA-Z0-9_\\.])(#{table_name}\\.)?#{col_name}(?![a-zA-Z0-9_])"
                  output.gsub!(pattern, PGCrypto::Crypt.decrypt_column(table_name, col_name, key).to_sql)
                end
              end
            end
          end

          self.where_clause += where_clause_factory.build(opts, rest)
          self
        end
      end
    end
  end
end

if defined? ActiveRecord::QueryMethods
  ActiveRecord::QueryMethods.include(PGCrypto::Extensions::QueryMethods)
else
  ActiveSupport.on_load(:active_record) do
    ActiveRecord::QueryMethods.include(PGCrypto::Extensions::QueryMethods)
  end
end
