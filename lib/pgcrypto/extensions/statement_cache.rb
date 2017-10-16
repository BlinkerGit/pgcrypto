module PGCrypto::Extensions
  module StatementCache
    def self.included(base)
      base.instance_eval do
        # We override this method so that AREL nodes being compiled into cached
        # queries are subjected to the same manipulation that they would be if
        # they were actually being passed to the database. Original source at
        # https://github.com/rails/rails/blob/5-1-stable/activerecord/lib/active_record/statement_cache.rb#L90
        def create(connection, block = Proc.new)
          relation = block.call ActiveRecord::StatementCache::Params.new
          bind_map = ActiveRecord::StatementCache::BindMap.new relation.bound_attributes
          correct_arel = PGCrypto::Manipulation.process_arel(relation.arel).first
          query_builder = connection.cacheable_query(self, correct_arel)

          new query_builder, bind_map
        end
      end
    end
  end
end

if defined? ActiveRecord::StatementCache
  ActiveRecord::StatementCache.include(PGCrypto::Extensions::StatementCache)
else
  ActiveSupport.on_load(:active_record) do
    ActiveRecord::StatementCache.include(PGCrypto::Extensions::StatementCache)
  end
end
