$LOAD_PATH.push('.')
puts "1.require 'junatra'"

require 'junatra'

puts "10.get in app.rb"

get '/' do
  'Hello world!Junatra'
end

# get '/home' do
#   'Hello home world!Junatra'
# end

puts "15.after get in app.rb"

set_trace_func lambda { |event, file, line ,id, binding, klass|
  if event =~ /call/ && id.to_s == "call" && klass != Proc
    puts "#{klass}#call is called! as #{event} :#{file} line:#{line}"
  end
}