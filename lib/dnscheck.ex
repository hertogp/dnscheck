defmodule Dnscheck do
  @moduledoc """
  Documentation for `Dnscheck`.
  """

  @doc """

  """
  def resolve(name, type, opts \\ []) do
    opts =
      opts
      |> Keyword.put(:nameservers, [{{8, 8, 8, 8}, 53}])
      |> Keyword.put(:edns, 0)

    :inet_res.resolve(name, :in, type, opts)
  end
end
