defmodule Dnscheck do
  @moduledoc """
  Documentation for `Dnscheck`.
  """

  @doc """

  """
  def resolve(name, type, opts \\ []) do
    nameservers = Keyword.get(opts, :nameservers, [{{8, 8, 8, 8}, 53}])

    :inet_res.resolve(name, :in, type, edns: 0, dnssec_ok: true, nameservers: nameservers)
  end
end
