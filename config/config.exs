import Config

config :logger, :console,
  format: "$date $time [$level] $message\n",
  device: :standard_error
