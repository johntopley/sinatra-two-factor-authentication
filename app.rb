require 'sinatra'
require 'sinatra/flash'

require_relative 'lib/core_ext/object'
require_relative 'lib/authentication'
require_relative 'lib/user'

NO_2FA_COOKIE = 'sideprojectsoftware_no_2fa'
TEN_MINUTES   = 60 * 10
THIRTY_DAYS   = 60 * 60 * 24 * 30

use Rack::Session::Pool, expire_after: TEN_MINUTES # Expire sessions after ten minutes of inactivity
helpers Authentication

helpers do
  def redirect_to_original_request
    user = session[:user]
    flash[:notice] = "Welcome back #{user.name}."
    original_request = session[:original_request]
    session[:original_request] = nil
    redirect original_request
  end
end

before do
  headers 'Content-Type' => 'text/html; charset=utf-8'
end

get '/signin/?' do
  erb :signin, locals: { title: 'Sign In' }
end

post '/signin/?' do
  if user = User.authenticate(params)
    session[:user] = user
    if request.cookies[NO_2FA_COOKIE]
      session[:valid_token] = true
      redirect_to_original_request
    else
      redirect '/signin/secondfactor'
    end
  else
    flash[:notice] = 'You could not be signed in. Did you enter the correct username and password?'
    redirect '/signin'
  end
end

get '/signin/secondfactor/?' do
  unless session[:user]
    flash[:notice] = 'Please sign in first.'
    redirect '/signin'
  end
  erb :second_factor, locals: { title: 'Sign In' }
end

post '/signin/secondfactor/?' do
  unless session[:user]
    flash[:notice] = 'Your session has expired. Please sign in again.'
    redirect '/signin'
  end
  if session[:user].verify_code(params)
    if params[:rememberme]
      response.set_cookie(NO_2FA_COOKIE, value: '1', max_age: THIRTY_DAYS.to_s)
    else
      response.delete_cookie(NO_2FA_COOKIE)
    end
    session[:valid_token] = true
    redirect_to_original_request
  else
    flash[:notice] = 'The code you entered is incorrect. Please try again.'
    redirect '/signin/secondfactor'
  end
end

get '/signout' do
  session[:user] = nil
  session[:valid_token] = nil
  flash[:notice] = 'You have been signed out.'
  redirect '/'
end

get '/?' do
  erb :index, locals: { title: 'Home' }
end

get '/protected/?' do
  authenticate!
  erb :protected, locals: { title: 'Protected Page' }
end
