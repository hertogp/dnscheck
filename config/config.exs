import Config

config :logger, :default_handler, false

config :logger, :console,
  format: "$date $time [$level] $metadata$message\n",
  metadata: [:mfa]
