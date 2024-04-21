defmodule Dnscheck do
  @moduledoc """
  Documentation for `Dnscheck`.
  """

  @doc """

  """
  def main(args) do
    args |> parse |> run
    IO.inspect(args, label: :main)
  end

  def parse(args) do
    {opts, host, invalid} =
      OptionParser.parse(args,
        strict: [
          proto: :boolean,
          type: :string,
          class: :string,
          validate: :boolean,
          trace: :boolean,
          all: :boolean
        ],
        aliases: [p: :proto, t: :type, c: :class, v: :validate, T: :trace, a: :all]
      )

    if invalid != [],
      do: IO.inspect(invalid, label: :ignoring)

    {opts, host}
  end

  def run({opts, hosts}) do
    IO.inspect(opts)

    type =
      Keyword.get(opts, :type, "A")
      |> DNS.Msg.Terms.decode_rr_type()

    for host <- hosts do
      DNS.resolve(host, type)
      |> IO.inspect(label: :result)
    end
  end
end
