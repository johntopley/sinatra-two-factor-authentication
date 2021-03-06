Sinatra Two Factor Authentication Example
=========================================
This Sinatra application demonstrates a simple authentication scheme including two-factor authentication (2FA). See
https://sideprojectsoftware.com/blog/2018/03/16/sinatra-two-factor-authentication for a full explanation.

Prerequisites
-------------
The application depends on the following RubyGems:

* [bcrypt](https://github.com/codahale/bcrypt-ruby)
* [rotp](https://github.com/mdp/rotp)
* [sinatra](https://github.com/sinatra/sinatra)
* [sinatra-flash](https://github.com/SFEley/sinatra-flash)

Running
-------
To run the application in development use:

 `ruby app.rb`

and access using [http://localhost:4567](http://localhost:4567)

Alternatively, to run the web application using a [Rackup](http://rack.github.io/) file use:

 `rackup config.ru` (the `config.ru` may be omitted as Rack looks for this file by default)

and access using [http://localhost:9292](http://localhost:9292)

Credentials
-----------
The credentials for signing in to the app are:

* Username: user
* Password: secret123
