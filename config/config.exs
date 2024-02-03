import Config

config :logger, :default_handler, false
config :logger, :console, format: "$date $time [$level] $message\n"
