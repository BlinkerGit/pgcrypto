require 'pgcrypto/crypt'

module PGCrypto::Manipulation # Encapsulate the logic that manipulates AREL trees so that it may be called from anywhere.
  class << self

    def process_arel(arel, binds = [])
      case arel
      when Arel::InsertManager
        process_insert(arel, binds)
      when Arel::SelectManager
        process_select(arel, binds)
      when Arel::UpdateManager
        process_update(arel, binds)
      when ActiveRecord::Relation
        process_select(arel, binds)
      end

      return arel, binds
    end

    # For use where AR builds a relation without a surrounding statement.
    def process_raw_relation(relation)
      # r = translate_where(relation.where_clause.ast)
      # r.is_a?(Array) ? r.inject { |x, y| x.and y } : r
      # relation.where_clause = ActiveRecord::Relation::WhereClause.new(testr)
      relation
    end

    private

    def process_insert(arel, binds = [])
      if table = PGCrypto[arel.ast.relation.name.to_s]
        arel.ast.columns.each_with_index do |column, i|
          if options = table[column.name.to_sym]
            next unless (key = PGCrypto.keys.public_key(options))
            expr = arel.ast.values.expressions[i]
            case expr
            when nil
              expr = null_literal
            when Arel::Nodes::BindParam
              if chosen_bind = binds.detect{ |b| b.name == column.name }
                expr = chosen_bind.nil? ? null_literal : PGCrypto::Crypt.encrypt_string(chosen_bind.value, key)
                binds.delete(chosen_bind)
              else
                raise "Could not find binding for column #{column.name}!"
              end
            when String
              expr = PGCrypto::Crypt.encrypt_string(expr, key)
            else
              raise "Unknown node class presented to pgcrypto_insert: #{expr.class.to_s}!"
            end
            arel.ast.values.expressions[i] = expr
          end
        end
      end
    end

    def process_select(arel, binds = [])
      # We start by looping through each "core," which is just a
      # SelectStatement and correcting plain-text queries against an encrypted
      # column...
      arel.ast.cores.each do |core|
        next unless core.is_a?(Arel::Nodes::SelectCore)

        translate_selects(core, core.projections) if core.projections
        translate_selects(core, core.havings) if core.havings

        # Loop through each WHERE to determine whether or not we need to refer
        # to its decrypted counterpart
        core.wheres.each do |where|
          translate_where(where)
        end
      end
    end

    def process_update(arel, binds = [])
      table_name = arel.ast.relation.name.to_s
      if columns = PGCrypto[table_name]
        # Find all columns with encryption instructions and encrypt them
        arel.ast.values.each do |value|
          if value.respond_to?(:left) && options = columns[column_name = value.left.name]
            next unless (key = PGCrypto.keys.public_key(options))
            case value.right
            when nil
              value.right = null_literal
            when Arel::Nodes::BindParam
              if chosen_bind = binds.detect { |b| b.name == column_name }
                value.right = chosen_bind.nil? ? null_literal : PGCrypto::Crypt.encrypt_string(chosen_bind.value, key)
                binds.delete(chosen_bind)
              else
                raise "Could not find binding for column #{column_name}!"
              end
            when String
              value.right = PGCrypto::Crypt.encrypt_string(value.right, key)
            else
              raise "Unknown node class presented to pgcrypto_update: #{value.class.to_s}!"
            end

          end
        end
        # Find any where clauses that refer to encrypted columns and correct them
        arel.ast.wheres.each do |where|
          translate_where(where)
        end
      end
    end

    def translate_selects(core, selects)
      table_name = core.source.left.name
      columns = PGCrypto[table_name]
      return if columns.empty?

      untouched_columns = columns.keys.map(&:to_s)

      selects.each_with_index do |select, i|
        next unless select.respond_to?(:name)

        select_name = select.name.to_s
        if untouched_columns.include?(select_name)
          next unless (key = PGCrypto.keys.private_key(columns[select_name.to_sym]))
          decrypt = PGCrypto::Crypt.decrypt_column(table_name, select_name, key)
          selects[i] = decrypt.as(select_name)
          untouched_columns.delete(select_name)
        end
      end

      splat_projection = selects.find { |s| s.respond_to?(:name) && s.name == '*' }
      if untouched_columns.any? && splat_projection
        untouched_columns.each do |column|
          next unless (key = PGCrypto.keys.private_key(columns[column.to_sym]))
          decrypt = PGCrypto::Crypt.decrypt_column(table_name, column, key)
          core.projections.push(decrypt.as(column))
        end
      end
    end

    def translate_where(where)
      if where.respond_to?(:children)
        where.children.each do |child|
          translate_where(child) # Recursively iterate through the children to find comparison nodes.
        end
      elsif where.respond_to?(:right) && where.respond_to?(:left)
        translate_child(where)
      end
    end

    def translate_child(child)
      return child unless child.respond_to?(:left)
      return child unless child.left.respond_to?(:relation)
      table_name = child.left.relation.name
      columns    = PGCrypto[table_name]
      return child unless columns.present?
      return child unless options = columns[child.left.name.to_s]
      key        = PGCrypto.keys.private_key(options)
      child.left = PGCrypto::Crypt.decrypt_column(table_name, child.left.name, key)

      # Prevent ActiveRecord from re-casting the value to binary
      case child.right
      when String
        child.right = quoted_literal(child.right)
      when Arel::Nodes::Casted
        if child.right.val.is_a(Hash)
          if child.right.val.key?(:value)
            child.right = quoted_literal(child.right.val[:value])
          else
            raise "Unknown value format presented to block in translate_child: #{child.right.val.inspect}!"
          end
        else
          child.right = quoted_literal(child.right.val)
        end
      when Array
        child.right = child.right.map do |item|
          case item
          when Arel::Nodes::Casted
            quoted_literal(item.val)
          else
            raise "Unknown node class presented to block in translate_child: #{item.class.to_s}!"
          end
        end
      when Arel::Nodes::BindParam
        # Do nothing -- ActiveRecord will pass the correct binding and cast it
        # appropriately.
      else
        raise "Unknown node class presented to translate_child: #{child.right.class.to_s}!"
      end
    end

    def null_literal
      Arel::Nodes::SqlLiteral.new('NULL')
    end

    def quoted_literal(str, quoter = nil)
      return null_literal if str.nil?
      quoter ||= ActiveRecord::Base.connection
      Arel::Nodes::SqlLiteral.new("'#{quoter.quote_string(str)}'")
    end
  end
end
