require 'bcrypt'
require 'rotp'
require 'yaml'

class User
  include BCrypt
  attr_reader :name
  
  def self.authenticate(params = {})
    return nil if params[:username].blank? || params[:password].blank?
    
    @@credentials ||= YAML.load_file(File.join(__dir__, '../credentials.yml'))
    username = params[:username].downcase
    return nil if username != @@credentials['username']
    
    password_hash = Password.new(@@credentials['password_hash'])
    User.new(username) if password_hash == params[:password] # The password param gets hashed for us by the == method.
  end
  
  def initialize(username)
    @name = username.capitalize
  end
  
  def verify_code(params = {})
    code = params[:code]
    return false if code.blank?
    
    totp = ROTP::TOTP.new(@@credentials['secret'])
    totp.verify(code)
  end
end
