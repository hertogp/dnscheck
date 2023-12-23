defmodule DNS.Cache do
  @moduledoc """
  Simple DNS cache for RR's with TTLs.

  """

  @cache :dns_cache

  @doc """
    Creates and initializes the cache

  """
  def init() do
    :ets.new(@cache, [:set, :public, :named_table, {:keypos, 1}, {:read_concurrency, true}])
  end

  @doc """
  Puts a single RR in the #{@cache}.

  If the RR already exists in the cache, it will be overwritten with a new time
  to die.

  The RR will be ignored if:
  - its TTL < 1, or
  - its type is :OPT

  ## Examples

      iex> rr = DNS.Msg.RR.new(name: "example.com", type: :A, ttl: 1, rdmap: %{ip: "10.1.1.1"})
      iex> init()
      iex> put(rr)
      iex> get("example.com", :IN, :A)
      [%DNS.Msg.RR{
        name: "example.com",
        type: :A,
        class: :IN,
        ttl: 1,
        raw: false,
        rdlen: 0,
        rdmap: %{ip: "10.1.1.1"},
        rdata: "",
        wdata: ""}
      ]
      iex> Process.sleep(1100)
      iex> DNS.Cache.get("example.com", :IN, :A)
      []

  """
  @spec put(DNS.Msg.RR.t()) :: :ok | :ignored | :error
  def put(rr) do
    with {:ttl, false} <- {:ttl, rr.ttl < 1},
         {:type, false} <- {:type, rr.ttl in [41, :OPT]},
         {:ok, key} <- make_key(rr.name, rr.class, rr.type),
         {:ok, crrs} <- lookup(key),
         crrs <- Enum.filter(crrs, &alive?/1),
         crrs <- Enum.filter(crrs, fn {_ttd, crr} -> crr.rdmap != rr.rdmap end) do
      :ets.insert(@cache, {key, [wrap_ttd(rr) | crrs]})
      :ok
    else
      {:type, _} -> :ignored
      {:ttl, _} -> :ignored
      _ -> :error
    end
  end

  @doc """
  Gets the RRs for given `name`, `class` and `type`.

  A list of RR's is retrieved from the cache and expired
  RR's are removed from the results and deleted from the
  cache.

  Returns either a list of RR's or `:error` if any one
  of the arguments are invalid

  """
  @spec get(String.t(), atom, atom) :: [DNS.Msg.RR.t()] | :error
  def get(name, class, type) do
    with {:ok, key} <- make_key(name, class, type),
         {:ok, crrs} <- lookup(key),
         {rrs, dead} <- Enum.split_with(crrs, &alive?/1) do
      # some died, save the living (if any)
      if rrs != [] and dead != [],
        do: :ets.insert(@cache, {key, rrs})

      # all gone, delete key
      if rrs == [],
        do: :ets.delete(@cache, key)

      Enum.map(rrs, &unwrap_ttd/1)
    else
      _ -> :error
    end
  end

  @doc """
  Puts the RR's found in given dns `msg` in the cache.

  Each RR found in either the answer, authority or additional section
  of the DNS `msg` is inserted using `put/1`.
  """
  def put_msg(msg) do
    msg.answer
    |> Enum.concat(msg.authority)
    |> Enum.concat(msg.additional)
    |> Enum.map(&put/1)

    :ok
  end

  # [[ HELPERS ]]
  defp alive?({ttd, _rr}),
    do: now() < ttd

  defp lookup(key) do
    # since @cache is a set, last clause should never be hit
    case :ets.lookup(@cache, key) do
      [] -> {:ok, []}
      [{^key, rrs}] -> {:ok, rrs}
      _ -> :error
    end
  end

  defp make_key(name, class, type) do
    ntype = DNS.Msg.Terms.encode_rr_type(type)

    nclass =
      case type do
        :OPT -> 1
        _ -> DNS.Msg.Terms.encode_dns_class(class)
      end

    with {:ok, name} <- normalize(name) do
      {:ok, {name, nclass, ntype}}
    else
      _ -> :error
    end
  end

  defp normalize(name) do
    # TODO: properly parse and normalize the name
    {:ok, String.downcase(name)}
  end

  # TODO: move this into Utils somewhere
  defp now(),
    do: System.os_time(:second)

  # (un)wrap time to die
  defp unwrap_ttd({_ttd, rr}),
    do: rr

  defp wrap_ttd(rr) do
    {now() + rr.ttl, rr}
  end
end
