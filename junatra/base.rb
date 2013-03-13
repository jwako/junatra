require 'uri'
require 'rack'

module Junatra
  class Request < Rack::Request
    # Returns an array of acceptable media types for the response
    def accept
      @env['sinatra.accept'] ||= begin
        entries = @env['HTTP_ACCEPT'].to_s.split(',')
        entries.map { |e| accept_entry(e) }.sort_by(&:last).map(&:first)
      end
    end

    def preferred_type(*types)
      return accept.first if types.empty?
      types.flatten!
      accept.detect do |pattern|
        type = types.detect { |t| File.fnmatch(pattern, t) }
        return type if type
      end
    end

    alias accept? preferred_type
    alias secure? ssl?

    def forwarded?
      @env.include? "HTTP_X_FORWARDED_HOST"
    end

    def route
      @route ||= Rack::Utils.unescape(path_info)
    end

    def path_info=(value)
      @route = nil
      super
    end

    private

    def accept_entry(entry)
      type, *options = entry.gsub(/\s/, '').split(';')
      quality = 0 # we sort smalles first
      options.delete_if { |e| quality = 1 - e[2..-1].to_f if e.start_with? 'q=' }
      [type, [quality, type.count('*'), 1 - options.size]]
    end
  end
  
  class Response < Rack::Response
    def finish
puts "113.#finish"
      @body = block if block_given?
      if [204, 304].include?(status.to_i)
        header.delete "Content-Type"
        [status.to_i, header.to_hash, []]
      else
        body = @body || []
        body = [body] if body.respond_to? :to_str
        if body.respond_to?(:to_ary)
          header["Content-Length"] = body.to_ary.
            inject(0) { |len, part| len + Rack::Utils.bytesize(part) }.to_s
        end
        [status.to_i, header.to_hash, body]
      end
    end
  end
  
  class NotFound < NameError #:nodoc:
    def code ; 404 ; end
  end
  
  module Helpers
    # Set or retrieve the response status code.
    def status(value=nil)
      response.status = value if value
      response.status
    end

    # Set or retrieve the response body. When a block is given,
    # evaluation is deferred until the body is read with #each.
    def body(value=nil, &block)
      if block_given?
        def block.each; yield(call) end
        response.body = block
      elsif value
        response.body = value
      else
        response.body
      end
    end
    
    # Halt processing and redirect to the URI provided.
    def redirect(uri, *args)
      status 302

      # According to RFC 2616 section 14.30, "the field value consists of a
      # single absolute URI"
      response['Location'] = uri(uri, settings.absolute_redirects?, settings.prefixed_redirects?)
      halt(*args)
    end

    # Generates the absolute URI for a given path in the app.
    # Takes Rack routers and reverse proxies into account.
    def uri(addr = nil, absolute = true, add_script_name = true)
      return addr if addr =~ /\A[A-z][A-z0-9\+\.\-]*:/
      uri = [host = ""]
      if absolute
        host << 'http'
        host << 's' if request.secure?
        host << "://"
        if request.forwarded? or request.port != (request.secure? ? 443 : 80)
          host << request.host_with_port
        else
          host << request.host
        end
      end
      uri << request.script_name.to_s if add_script_name
      uri << (addr ? addr : request.path_info).to_s
      File.join uri
    end

    alias url uri
    alias to uri

    # Halt processing and return the error status provided.
    def error(code, body=nil)
      code, body    = 500, code.to_str if code.respond_to? :to_str
      response.body = body unless body.nil?
      halt code
    end

    # Halt processing and return a 404 Not Found.
    def not_found(body=nil)
      error 404, body
    end

    # Set multiple response headers with Hash.
    def headers(hash=nil)
      response.headers.merge! hash if hash
      response.headers
    end

    # Access the underlying Rack session.
    def session
      request.session
    end

    # Access shared logger object.
    def logger
      request.logger
    end

    # Look up a media type by file extension in Rack's mime registry.
    def mime_type(type)
      Base.mime_type(type)
    end

    # Set the Content-Type of the response body given a media type or file
    # extension.
    def content_type(type = nil, params={})
      return response['Content-Type'] unless type
      default = params.delete :default
      mime_type = mime_type(type) || default
      fail "Unknown media type: %p" % type if mime_type.nil?
      mime_type = mime_type.dup
      unless params.include? :charset or settings.add_charset.all? { |p| not p === mime_type }
        params[:charset] = params.delete('charset') || settings.default_encoding
      end
      params.delete :charset if mime_type.include? 'charset'
      unless params.empty?
        mime_type << (mime_type.include?(';') ? ', ' : ';')
        mime_type << params.map { |kv| kv.join('=') }.join(', ')
      end
      response['Content-Type'] = mime_type
    end

    # Set the Content-Disposition to "attachment" with the specified filename,
    # instructing the user agents to prompt to save.
    def attachment(filename=nil)
      response['Content-Disposition'] = 'attachment'
      if filename
        params = '; filename="%s"' % File.basename(filename)
        response['Content-Disposition'] << params
      end
    end
  end
  
  class Base
    include Rack::Utils
    include Helpers

    attr_accessor :app

    def initialize(app=nil)
      @app = app
      yield self if block_given?
    end

    # Rack call interface.
    def call(env)
puts "103.Base#call"
      dup.call!(env)
    end

    attr_accessor :env, :request, :response, :params

    def call!(env) # :nodoc:
puts "104.Base#call!"
      @env      = env
      @request  = Request.new(env)
      @response = Response.new
      @params   = indifferent_params(@request.params)
      # template_cache.clear if settings.reload_templates
      # force_encoding(@request.route)
      # force_encoding(@params)

      @response['Content-Type'] = nil
      invoke { dispatch! }
      invoke { error_block!(response.status) }
puts "112.after invoke"
      unless @response['Content-Type']
        if body.respond_to?(:to_ary) and body.first.respond_to? :content_type
          content_type body.first.content_type
        else
          content_type :html
        end
      end

      @response.finish
    end
        
    # Access settings defined with Base.set.
    def self.settings
      self
    end

    # Access settings defined with Base.set.
    def settings
      self.class.settings
    end
  
    def halt(*response)
      response = response.first if response.length == 1
      throw :halt, response
    end
    
    def pass(&block)
puts "throw :pass"
      throw :pass, block
    end
    
    def forward
      fail "downstream app not set" unless @app.respond_to? :call
      status, headers, body = @app.call env
      @response.status = status
      @response.body = body
      @response.headers.merge! headers
      nil
    end
      
    # Run filters defined on the class and all superclasses.
    def filter!(type, base = settings)
      filter! type, base.superclass if base.superclass.respond_to?(:filters)
      base.filters[type].each { |block| instance_eval(&block) }
    end

    # Run routes defined on the class and all superclasses.
    def route!(base = settings, pass_block=nil)
puts "107.#route!"
puts base.routes[@request.request_method]
puts "true" if routes = base.routes[@request.request_method]
puts "false" unless routes = base.routes[@request.request_method]
      if routes = base.routes[@request.request_method]
        routes.each do |pattern, keys, conditions, block|
          pass_block = process_route(pattern, keys, conditions) do
puts "110.call route_eval"
            route_eval(&block)
          end
        end
      end

      # Run routes defined in superclass.
      if base.superclass.respond_to?(:routes)
puts "base.superclass"
        return route!(base.superclass, pass_block)
      end

puts "110-2.call route_eval"
      route_eval(&pass_block) if pass_block
      route_missing
    end

    # Run a route block and throw :halt with the result.
    def route_eval(&block)
puts "110-1.#route_eval"
      throw :halt, instance_eval(&block)
    end

    # If the current request matches pattern and conditions, fill params
    # with keys and call the given block.
    # Revert params afterwards.
    #
    # Returns pass block.
    def process_route(pattern, keys, conditions)
puts "108.#process_route"      
      @original_params ||= @params
      route = @request.route
      route = '/' if route.empty? and not settings.empty_path_info?
      if match = pattern.match(route)
        values = match.captures.to_a
        params =
          if keys.any?
            keys.zip(values).inject({}) do |hash,(k,v)|
              if k == 'splat'
                (hash[k] ||= []) << v
              else
                hash[k] = v
              end
              hash
            end
          elsif values.any?
            {'captures' => values}
          else
            {}
          end
        @params = @original_params.merge(params)
        @block_params = values
puts "108-2.route is : " + route
        catch(:pass) do
puts "109.catch :pass"
          conditions.each { |cond|
            throw :pass if instance_eval(&cond) == false }
          yield
        end
      end
    ensure
      @params = @original_params
    end

    # No matching route was found or all routes passed. The default
    # implementation is to forward the request downstream when running
    # as middleware (@app is non-nil); when no downstream app is set, raise
    # a NotFound exception. Subclasses can override this method to perform
    # custom route miss logic.
    def route_missing
puts "150.#route_missing"      
      if @app
        forward
      else
puts "151.NOT FOUND"
        raise NotFound
      end
    end

    # Attempt to serve static files from public directory. Throws :halt when
    # a matching file is found, returns nil otherwise.
    def static!
      return if (public_dir = settings.public).nil?
      public_dir = File.expand_path(public_dir)

      path = File.expand_path(public_dir + unescape(request.path_info))
      return unless path.start_with?(public_dir) and File.file?(path)

      env['sinatra.static_file'] = path
      send_file path, :disposition => nil
    end
    
    def indifferent_params(params)
      params = indifferent_hash.merge(params)
      params.each do |key, value|
        next unless value.is_a?(Hash)
        params[key] = indifferent_params(value)
      end
    end
    
    # Creates a Hash with indifferent access.
    def indifferent_hash
      Hash.new {|hash,key| hash[key.to_s] if Symbol === key }
    end
      
    def invoke(&block)
puts "105.#invoke"
      res = catch(:halt) { instance_eval(&block) }
puts "111.get res as :"
puts res
      return if res.nil?
    
      case
      when res.respond_to?(:to_str)
        @response.body = [res]
      when res.respond_to?(:to_ary)
        res = res.to_ary
        if Fixnum === res.first
          if res.length == 3
            @response.status, headers, body = res
            @response.body = body if body
            headers.each { |k, v| @response.headers[k] = v } if headers
          elsif res.length == 2
            @response.status = res.first
            @response.body   = res.last
          else
            raise TypeError, "#{res.inspect} not supported"
          end
        else
          @response.body = res
        end
      when res.respond_to?(:each)
        @response.body = res
      when (100..599) === res
        @response.status = res
      end
    
      res
    end
    
    # Dispatch a request with error handling.
    def dispatch!
puts "106.#dispatch!"      
      static! if settings.static? && (request.get? || request.head?)
      filter! :before
      route!
    rescue NotFound => boom
puts "152.handle_not_found!"
      handle_not_found!(boom)
    rescue ::Exception => boom
      handle_exception!(boom)
    ensure
      filter! :after unless env['sinatra.static_file']
    end

    # Special treatment for 404s in order to play nice with cascades.
    def handle_not_found!(boom)
      @env['sinatra.error']          = boom
      @response.status               = 404
      @response.headers['X-Cascade'] = 'pass'
      @response.body                 = ['<h1>Not Found</h1>']
      error_block! boom.class, NotFound
    end

    # Error handling during requests.
    def handle_exception!(boom)
      @env['sinatra.error'] = boom

      dump_errors!(boom) if settings.dump_errors?
      raise boom if settings.show_exceptions? and settings.show_exceptions != :after_handler

      @response.status = 500
      if res = error_block!(boom.class)
        res
      elsif settings.raise_errors?
        raise boom
      else
        error_block!(Exception)
      end
    end

    # Find an custom error block for the key(s) specified.
    def error_block!(*keys)
      keys.each do |key|
        base = settings
        while base.respond_to?(:errors)
          if block = base.errors[key]
            # found a handler, eval and return result
            return instance_eval(&block)
          else
            base = base.superclass
          end
        end
      end
      raise boom if settings.show_exceptions? and keys == Exception
      nil
    end

    def dump_errors!(boom)
      msg = ["#{boom.class} - #{boom.message}:",
        *boom.backtrace].join("\n ")
      @env['rack.errors'].puts(msg)
    end
            
    class << self
      attr_reader :routes, :filters, :templates, :errors
      
      def reset!
        @conditions     = []
        @routes         = {}
        @filters        = {:before => [], :after => []}
        @errors         = {}
        @middleware     = []
        @prototype      = nil
        @extensions     = []
    
        if superclass.respond_to?(:templates)
          @templates = Hash.new { |hash,key| superclass.templates[key] }
        else
          @templates = {}
        end
      end
      
      def extensions
puts "14-2.#extensions"        
        @extensions = []
        if superclass.respond_to?(:extensions)
          (@extensions + superclass.extensions).uniq
        else
          @extensions
        end
      end
      
      def middleware
        if superclass.respond_to?(:middleware)
          superclass.middleware + @middleware
        else
          @middleware
        end
      end
      
      # Lookup or register a mime type in Rack's mime registry.
      def mime_type(type, value=nil)
        return type if type.nil? || type.to_s.include?('/')
        type = ".#{type}" unless type.to_s[0] == ?.
        return Rack::Mime.mime_type(type, nil) unless value
        Rack::Mime::MIME_TYPES[type] = value
      end

      # provides all mime types matching type, including deprecated types:
      #   mime_types :html # => ['text/html']
      #   mime_types :js   # => ['application/javascript', 'text/javascript']
      def mime_types(type)
        type = mime_type type
        type =~ /^application\/(xml|javascript)$/ ? [type, "text/#$1"] : [type]
      end

      # Define a before filter; runs before all requests within the same
      # context as route handlers and may access/modify the request and
      # response.
      def before(path = nil, options = {}, &block)
        add_filter(:before, path, options, &block)
      end

      # Define an after filter; runs after all requests within the same
      # context as route handlers and may access/modify the request and
      # response.
      def after(path = nil, options = {}, &block)
        add_filter(:after, path, options, &block)
      end
      
      def set(option, value = (not_set = true), &block)
        value = block if block
        if value.kind_of?(Proc)
          metadef(option, &value)
          metadef("#{option}?") { !!__send__(option) }
          metadef("#{option}=") { |val| metadef(option, &Proc.new{val}) }
        elsif not_set
          option.each { |k,v| set(k, v) }
        elsif respond_to?("#{option}=")
          __send__ "#{option}=", value
        else
          set option, Proc.new{value}
        end
        self
      end
      
      def metadef(message, &block)
        (class << self; self; end).
          send :define_method, message, &block
      end

      def inherited(subclass)
puts "3. #inherited"
# subclass is Junatra::Application
        subclass.reset!
        super
      end
      
#COME HERE 110      
      @@mutex = Mutex.new
      def synchronize(&block)
        if lock?
          @@mutex.synchronize(&block)
        else
          yield
        end
      end
      
      def get(path, opts={}, &block)
puts "13.#get"
        conditions = @conditions.dup
        route('GET', path, opts, &block)

        @conditions = conditions
        route('HEAD', path, opts, &block)
      end
      
      def route(verb, path, options={}, &block)
puts "14.#route"
        # Because of self.options.host
        host_name(options.delete(:host)) if options.key?(:host)
        enable :empty_path_info if path == "" and empty_path_info.nil?

        block, pattern, keys, conditions = compile! verb, path, block, options
        invoke_hook(:route_added, verb, path, block)
        (@routes[verb] ||= []).
          push([pattern, keys, conditions, block]).last
      end
            
      def invoke_hook(name, *args)
puts "14-1.#invoke_hook"
        extensions.each { |e| e.send(name, *args) if e.respond_to?(name) }
      end
    
      def compile!(verb, path, block, options = {})
puts "14-0.#compile!"
        options.each_pair { |option, args| send(option, *args) }
        method_name = "#{verb} #{path}"
# define method of 'GET /'
        define_method(method_name, &block)
# instance_method method is Module method. it returns UnboundMethod object
        unbound_method          = instance_method method_name
        pattern, keys           = compile(path)
        conditions, @conditions = @conditions, []
        remove_method method_name
    
        [ block.arity != 0 ?
            proc { unbound_method.bind(self).call(*@block_params) } :
# unbound_method is #<UnboundMethod: Junatra::Application#GET />
# unbound_method.bind(self) is #<Method: Junatra::Application(Junatra::Application)#GET />
            proc { puts unbound_method.bind(self) ; puts "110-2.unbound_method.bind(self).call" ; unbound_method.bind(self).call },
          pattern, keys, conditions ]
      end
    
      def compile(path)
        keys = []
        if path.respond_to? :to_str
          special_chars = %w{. + ( ) $}
          pattern =
            path.to_str.gsub(/((:\w+)|[\*#{special_chars.join}])/) do |match|
              case match
              when "*"
                keys << 'splat'
                "(.*?)"
              when *special_chars
                Regexp.escape(match)
              else
                keys << $2[1..-1]
                "([^/?#]+)"
              end
            end
          [/^#{pattern}$/, keys]
        elsif path.respond_to?(:keys) && path.respond_to?(:match)
          [path, path.keys]
        elsif path.respond_to?(:names) && path.respond_to?(:match)
          [path, path.names]
        elsif path.respond_to? :match
          [path, keys]
        else
          raise TypeError, path
        end
      end

      def prototype
puts "101.#prototype"        
        @prototype ||= new
      end

      # Create a new instance without middleware in front of it.
      alias new! new unless method_defined? :new!

      # Create a new instance of the class fronted by its middleware
      # pipeline. The object is guaranteed to respond to #call but may not be
      # an instance of the class new was called on.
      def new(*args, &bk)
        build(*args, &bk).to_app
      end

      # Creates a Rack::Builder instance with all the middleware set up and
      # an instance of this class as end point.
      def build(*args, &bk)
puts "102.#build"        
        builder = Rack::Builder.new
        builder.use Rack::MethodOverride if method_override?
        # builder.use ShowExceptions       if show_exceptions?
        builder.use Rack::Head
        # setup_logging  builder
        setup_sessions builder
        middleware.each { |c,a,b| builder.use(c, *a, &b) }
        builder.run new!(*args, &bk)
        builder
      end
      
      def development?; environment == :development end
      def production?;  environment == :production  end
      def test?;        environment == :test        end
      
      def use(middleware, *args, &block)
        @prototype = nil
        @middleware << [middleware, args, block]
      end
          
      def quit!(server, handler_name)
        # Use Thin's hard #stop! if available, otherwise just #stop.
        server.respond_to?(:stop!) ? server.stop! : server.stop
        puts "\n== Junatra has ended his set (crowd applauds)" unless handler_name =~/cgi/i
      end
    
      def run!(options={})
puts "17.Application.run!"
        set options
        handler      = detect_rack_handler
        handler_name = handler.name.gsub(/.*::/, '')
        puts "== Junatra has taken the stage " unless handler_name =~/cgi/i       
        handler.run self, :Host => bind, :Port => port do |server|
          [:INT, :TERM].each { |sig| trap(sig) { quit!(server, handler_name) } }
          set :running, true
        end
      rescue Errno::EADDRINUSE => e
        puts "== Someone is already performing on port #{port}!"
      end
      
      def setup_sessions(builder)
        return unless sessions?
        options = {}
        options[:secret] = session_secret if session_secret?
        options.merge! sessions.to_hash if sessions.respond_to? :to_hash
        builder.use Rack::Session::Cookie, options
      end
      
      def detect_rack_handler
        servers = Array(server)
        servers.each do |server_name|
          begin
            return Rack::Handler.get(server_name.downcase)
          rescue LoadError
          rescue NameError
          end
        end
        fail "Server handler (#{servers.join(',')}) not found."
      end

      # if user enter localhost:4567, rack access this method.
      def call(env)
puts "100.#call from rack"
        synchronize { prototype.call(env) }
      end
       
    end
puts "2.reset!" 
    reset!
    
    set :environment, (ENV['RACK_ENV'] || :development).to_sym
    set :raise_errors, Proc.new { test? }
    set :dump_errors, Proc.new { !test? }
    set :show_exceptions, Proc.new { true }
    set :sessions, false
    set :logging, false
    set :method_override, false
    set :default_encoding, "utf-8"
    set :add_charset, [/^text\//, 'application/javascript', 'application/xml', 'application/xhtml+xml']

    # explicitly generating this eagerly to play nice with preforking
    set :session_secret, '%x' % rand(2**255)

    class << self
      alias_method :methodoverride?, :method_override?
      alias_method :methodoverride=, :method_override=
    end
    
    set :server, %w[thin mongrel webrick]
    set :bind, '0.0.0.0'
    set :port, 4567

    set :absolute_redirects, true
    set :prefixed_redirects, false
    set :empty_path_info, nil

    set :app_file, nil
    set :root, Proc.new { app_file && File.expand_path(File.dirname(app_file)) }
    set :views, Proc.new { root && File.join(root, 'views') }
    set :reload_templates, Proc.new { development? }
    set :lock, false

    set :public, Proc.new { root && File.join(root, 'public') }
    set :static, Proc.new { public && File.exist?(public) }
    
  end

  class Application < Base
puts "4.load Application"
    # set :logging, Proc.new { ! test? }
    # set :method_override, true
    set :run, Proc.new { ! test? }
    # set :session_secret, Proc.new { super() unless development? }

    def self.register(*extensions, &block) #:nodoc:
puts "COME Application.register"      
      added_methods = extensions.map {|m| m.public_instance_methods }.flatten
      Delegator.delegate(*added_methods)
      super(*extensions, &block)
    end
  end

  # Sinatra delegation mixin. Mixing this module into an object causes all
  # methods to be delegated to the Sinatra::Application class. Used primarily
  # at the top-level.
  module Delegator #:nodoc:
    def self.delegate(*methods)
puts "6.self.delegate"   
      methods.each do |method_name|
        define_method(method_name) do |*args, &block|
puts "11.if there is *args, define_method is executed."
          # every method is always false at first
          return super(*args, &block) if respond_to? method_name
puts "12.exec Delegator.target.send"
          Delegator.target.send(method_name, *args, &block)
        end
        private method_name
      end
    end

puts "5.delegate :get"
    # call self.delegate. but it doesn't execute define_method because of lack of args, block.
    # but if there is get '/' ... in app.rb, it execute define_method because there is '/' (=args)
    delegate :get

    class << self
      attr_accessor :target
    end

    self.target = Application
  end
  
  # def self.register(*extensions, &block)
  #   Delegator.target.register(*extensions, &block)
  # end
end