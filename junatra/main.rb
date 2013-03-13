require 'junatra/base'

module Junatra
  class Application < Base
puts "7.set app_file"    
    # COME HERE 10
    # $0 is comandline value "app.rb"
    set :app_file, "app.rb" || $0
    set :run, Proc.new { $0 == app_file }
  end
puts "8.at_exit"
  # at_exit is a Kernel method
  at_exit { 
    puts "16.at_exit in block"
    Application.run! if $!.nil? && Application.run? 
  }
end
# COME HERE 30
puts "9.include Delegator"
include Junatra::Delegator