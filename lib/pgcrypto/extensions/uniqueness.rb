module PGCrypto::Extensions
  module Uniqueness
    def self.included(base)
      base.class_eval do
        # We redefine this method to correctly process the raw relations built
        # by this validator. Original source found at
        # https://github.com/rails/rails/blob/5-1-stable/activerecord/lib/active_record/validations/uniqueness.rb#L56
        def scope_relation(record, relation)
          Array(options[:scope]).each do |scope_item|
            scope_value = if record.class._reflect_on_association(scope_item)
              record.association(scope_item).reader
            else
              record._read_attribute(scope_item)
            end
            relation = relation.where(scope_item => scope_value)
          end

          relation
        end
      end
    end
  end
end

# Load immediately. Or load later. It's all good with us.
if defined? ActiveRecord::Validations::UniquenessValidator
  ActiveRecord::Validations::UniquenessValidator.send(
    :include, PGCrypto::Extensions::Uniqueness
  )
else
  ActiveSupport.on_load(:active_record) do
    ActiveRecord::Validations::UniquenessValidator.send(
      :include, PGCrypto::Extensions::Uniqueness
    )
  end
end
