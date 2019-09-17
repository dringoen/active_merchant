require File.join(File.dirname(__FILE__), '..', 'check.rb')
module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class InspireGateway < Gateway
      self.live_url = self.test_url = 'https://secure.inspiregateway.net/api/transact.php'

      QUERY_URL = 'https://secure.inspiregateway.net/api/query.php'
      
      self.supported_countries = ['US']
      self.supported_cardtypes = [:visa, :master, :american_express]
      self.homepage_url = 'http://www.inspiregateway.com'
      self.display_name = 'Inspire Commerce'

      # Creates a new InspireGateway
      #
      # The gateway requires that a valid login and password be passed
      # in the +options+ hash.
      #
      # ==== Options
      #
      # * <tt>:login</tt> -- The Inspire Username.
      # * <tt>:password</tt> -- The Inspire Password.
      # See the Inspire Integration Guide for details. (default: +false+)
      def initialize(options = {})
        requires!(options, :login, :password)
        @options = options
        super
      end  
      
      # Pass :store => true in the options to store the 
      # payment info at Inspire Gateway and get a generated 
      # customer_vault_id in the response.  
      # Pass :store => some_number_or_string to specify the
      # customer_vault_id InspireGateway should use (make sure it's
      # unique).
      
      # How to set the merchant account? (DRR: Information from Inspire)
      # There are a few ways you could do this. You can pass the 'processorid' field as part of the transaction data, 
      # assigning it the value of the processor you want the transaction routed to. 
      # Alternately, you can assign a username to only have privileges to one processor - 
      # every transaction submitted by that username would route to the processor they had been assigned. 
      # Lastly, you can use advanced load balancing to route transactions based on the value of a merchant defined field.
      def authorize(money, creditcard, options = {})
        post = {}
        add_invoice(post, options)
        add_payment_source(post, creditcard, options)
        add_address(post, creditcard, options)
        add_customer_data(post, options)
        add_descriptor(post, options)
        add_order_info(post, options)
        
        commit(options[:no_authorize] ? nil : 'auth', money, post)
      end

      def purchase(money, payment_source, options = {})
        post = {}
        add_invoice(post, options)
        add_payment_source(post, payment_source, options)
        add_address(post, payment_source, options)
        add_customer_data(post, options)
        add_descriptor(post, options)
        add_order_info(post, options)
        Rails.logger.error "Inspire Purchase post descriptor #{post.to_json}"
             
        commit('sale', money, post)
      end

      def capture(money, authorization, options = {})
        post ={}
        post[:transactionid] = authorization
        commit('capture', money, post)
      end

      def void(authorization, options = {})
        post ={}
        post[:transactionid] = authorization
        commit('void', nil, post)
      end

      def refund(money, authorization, options = {})
        post = {}
        post[:transactionid] = authorization
        commit('refund', money, post)
      end

      # Update the values (such as CC expiration) stored at
      # InspireGateway.  The CC number must be supplied in the
      # CreditCard object.
      def update(vault_id, creditcard, options = {})
        post = {}
        post[:customer_vault] = 'update_customer'
        add_customer_vault_id(post, vault_id)
        add_creditcard(post, creditcard, options)
        add_address(post, creditcard, options)
        add_customer_data(post, options)
             
        commit(nil, nil, post)
      end

      def delete(vault_id)
        post = {}
        post[:customer_vault] = 'delete_customer'
        add_customer_vault_id(post, vault_id)
        commit(nil, nil, post)
      end

      # To match the other stored-value gateways, like TrustCommerce,
      # store and unstore need to be defined
      def store(creditcard, options = {})
        billing_id = options.delete(:billing_id).to_s || true
        authorize((options[:no_authorize] ? nil : 100), creditcard, options.merge(:store => billing_id))
      end

      alias_method :unstore, :delete

      def get_vault_record(vault_id)
        post = {
          :report_type       => 'customer_vault',
          :customer_vault_id => vault_id,
        }
        query('customer', post)
      end

    private                             
      def add_customer_data(post, options)
        if options.has_key? :email
          post[:email] = options[:email]
        end

        if options.has_key? :ip
          post[:ipaddress] = options[:ip]
        end
      end

      def add_address(post, creditcard, options)
        if address = options[:billing_address] || options[:address]
          post[:address1]    = address[:address1].to_s
          post[:address2]    = address[:address2].to_s unless address[:address2].blank?
          post[:company]    = address[:company].to_s
          post[:phone]      = address[:phone].to_s
          post[:zip]        = address[:zip].to_s
          post[:city]       = address[:city].to_s
          post[:country]    = address[:country].to_s
          post[:state]      = address[:state].blank?  ? 'n/a' : address[:state]
        end
      end

      def add_invoice(post, options)
        post[:orderid] = options[:order_id].to_s.gsub(/[^\w.]/, '')
        post[:orderdescription] = options[:description]
      end

      def add_payment_source(params, source, options={})
        case determine_funding_source(source)
        when :vault       then add_customer_vault_id(params, source, options)
        when :credit_card then add_creditcard(params, source, options)
        when :check       then add_check(params, source)
        end
      end

      def add_customer_vault_id(params,vault_id,options={})
        params[:customer_vault_id] = vault_id
        params[:cvv] = options[:verification_value] if options[:verification_value]
      end

      def add_creditcard(post, creditcard, options)
        if options[:store]
          post[:customer_vault] = 'add_customer'
          post[:customer_vault_id] = options[:store] unless options[:store] == true
        end
        post[:ccnumber]  = creditcard.number
        post[:cvv] = creditcard.verification_value if creditcard.verification_value?
        post[:ccexp]  = expdate(creditcard)
        post[:firstname] = creditcard.first_name
        post[:lastname]  = creditcard.last_name
      end

      def add_check(post, check)
        post[:payment] = 'check' # Set transaction to ACH
        post[:checkname] = check.name # The name on the customer's Checking Account
        post[:checkaba] = check.routing_number # The customer's bank routing number
        post[:checkaccount] = check.account_number # The customer's account number
        post[:account_holder_type] = check.account_holder_type # The customer's type of ACH account
        post[:account_type] = check.account_type # The customer's type of ACH account
      end

      def add_order_info(post, options)
        post[:orderid]           = options[:orderid]
        post[:orderdescription]  = options[:orderdescription]
        post[:shipping_company]  = options[:shipping_company]
        post[:shipping_lastname] = options[:shipping_lastname]
      end

      def add_descriptor(post, options)
        desc = options && options[:descriptor] || @options && @options[:descriptor]
        post[:descriptor] = desc if desc
      end

      def parse(body)
        results = {}
        body.split(/&/).each do |pair|
          key, val = pair.split(%r{=})
          results[key] = val
        end

        results
      end

      def commit(action, money, parameters)
        parameters[:amount]  = amount(money) if money

        response = parse(ssl_post(self.live_url, post_data(action, parameters)))

        Response.new(response['response'] == '1', message_from(response), response,
          :authorization => response['transactionid'],
          :test => test?,
          :cvv_result => response['cvvresponse'],
          :avs_result => { :code => response['avsresponse'] }
        )

      end

      def query(desired_result_node, parameters)
        action = 'query'
        response = ssl_post(QUERY_URL, post_data(action,parameters))
        parse_xml(desired_result_node, response)
      end

      def parse_xml(desired_result_node, xml)
        xml = REXML::Document.new(xml)
        root = REXML::XPath.first(xml, "//#{desired_result_node}")
        if root
          response = parse_element(root)
        end
        response
      end

      def parse_element(node)
        if node.has_elements?
          response = {}
          node.elements.each{ |e|
            key = e.name.underscore
            value = parse_element(e)
            if response.has_key?(key)
              if response[key].is_a?(Array)
                response[key].push(value)
              else
                response[key] = [response[key], value]
              end
            else
              response[key] = parse_element(e)
            end
          }
        else
          response = node.text
        end
        response
      end

      def expdate(creditcard)
        year  = sprintf("%.4i", creditcard.year)
        month = sprintf("%.2i", creditcard.month)

        "#{month}#{year[-2..-1]}"
      end


      def message_from(response)
        case response['responsetext']
        when 'SUCCESS', 'Approved'
          'This transaction has been approved'
        when 'DECLINE'
          'This transaction has been declined'
        else
          response['responsetext']
        end
      end

      def post_data(action, parameters = {})
        post = {}
        post[:username]   = @options[:login]
        post[:password]   = @options[:password]
        post[:type]       = action if action

        request = post.merge(parameters).map { |key, value| "#{key}=#{CGI.escape(value.to_s)}" }.join('&')
        request
      end

      def determine_funding_source(source)
        case
        when source.is_a?(String) then :vault
        when CreditCard.card_companies.include?(card_brand(source)) then :credit_card
        when card_brand(source) == 'check' then :check
        else raise ArgumentError, 'Unsupported funding source provided'
        end
      end
    end
  end
end
