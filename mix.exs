defmodule Dnscheck.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/hertogp/dnscheck"

  def project do
    [
      app: :dnscheck,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: []
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:pfx, "~> 0.14"},
      {:ex_doc, "~> 0.27", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:benchee, "~> 1.0", only: :dev, runtime: false},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false}
    ]
  end

  defp docs() do
    [
      main: "readme",
      extras: [
        "README.md": [title: "Overview"],
        "LICENSE.md": [title: "License"],
        "CHANGELOG.md": []
      ],
      source_url: @source_url,
      # source_ref: "v#{@version}",
      formatters: ["html"],
      assets: "assets"
    ]
  end
end
