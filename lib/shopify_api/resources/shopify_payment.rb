module ShopifyAPI
  class ShopifyPayout < Base
    self.resource_prefix = 'shopify_payments/payouts/'

    def self.find_search(date_min=Time.zone.now.beginning_of_month.to_date.to_s, date_max=Time.zone.now.end_of_month.to_date.to_s)
      self.find(:all, 
                from: api_version.construct_api_path(
                    "shopify_payments/payouts.json?date_min=#{date_min}&date_max=#{date_max}"
                  )
                )
    end
  end
end
