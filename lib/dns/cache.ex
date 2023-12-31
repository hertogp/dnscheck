defmodule DNS.Cache do
  @cache :dns_cache
  @uncacheable [:OPT, :MAILA, :MAILB, :AXFR, :IXFR, :ANY, :*]

  @moduledoc """
  A simple DNS cache for RR's, honouring their TTL's.

  When an [RR](`DNS.Msg.RR`) is cached, it:
  - has its `rdata` and `wdata` fields cleared, unless it's a raw RR
  - is wrapped with a future point in monotonic time based on its TTL
  - is stored under the key constructed from `name`, `class` and `type`
  - is appended to the list (if any) of other RR's with the same key

  Upon retrieval, those that expired are excluded from the results and those
  that remain have their TTL's reduced by the amount of time they spent in the
  cache.

  The cache is *not* wrapped in a genserver and hence it is not periodically
  purged of old entries.  Those only get removed once an attempt is made to
  retrieve them after their time to live has ended.

  Some RR types are never cached, these include:
  #{Enum.map(@uncacheable, fn r -> "- `:#{r}`\n" end) |> Enum.join()}

  """

  import DNS.Utils

  # TODO:
  # [ ] initialize cache with root name servers (query via priv/named.root.rrs)
  # [ ] normalize dname properly
  # [ ] maybe add get_ns(domain name) -> searches the cache?
  # [ ] handle put_msg better!
  # [ ] clear rdata/wdata before caching if not raw
  # [ ] should we cache RR's with wildcard domain names?

  @doc """
  Creates and initializes to an empty cache.

  If the cache already exists, it is cleared.

  ## Examples

      iex> init()
      :dns_cache
      iex> rr = DNS.Msg.RR.new(ttl: 10)
      iex> :ok = put(rr)
      iex> size()
      1
      # (re)initializing means cache is cleared
      iex> init()
      iex> size()
      0

  """
  @spec init() :: atom
  def init() do
    case :ets.whereis(@cache) do
      :undefined ->
        :ets.new(@cache, [:set, :public, :named_table, {:keypos, 1}, {:read_concurrency, true}])

      _ ->
        :ets.delete_all_objects(@cache)
        @cache
    end
  end

  @doc """
  Returns the number of entries in the DNS cache

  If the cache hasn't been created yet, it returns :undefined
  """
  @spec size() :: non_neg_integer | :undefined
  def size() do
    :ets.info(@cache, :size)
  end

  @doc """
  Puts either a single RR or a Msg's RR's in the `#{inspect(@cache)}`.

  If an RR already exists in the cache, it will be overwritten with a new TTL.
  Before caching, the `rdata` and `wdata` fields are cleared, unless it is a
  raw RR.

  When given a `t:DNS.Msg.t/0`, the RR's in the answer section are cached if
  their domain name is equal to the queried domain name.

  If there are no answer RR's, the NS records in the authority section will be cached
  if the queried domain is a subdomain of the zone given.  Any A and AAAA records in
  the additional section are cached if their domain name is listed as a nameserver in
  the authority section.

  Note that an RR will be ignored if its TTL < 1 or its type is one of:
  #{Enum.map(@uncacheable, fn r -> "- `:#{r}`\n" end) |> Enum.join()}

  ## Examples

      iex> rr = DNS.Msg.RR.new(name: "example.org", type: :A, ttl: 10, rdmap: %{ip: "10.1.1.1"})
      iex> init()
      iex> :ok = put(rr)
      iex> [{key, [{_t, crr}]}] = :ets.tab2list(:dns_cache)
      iex> key
      {"example.org", 1, 1}
      iex> crr == rr
      true

      # TTL < 1 is ignored
      iex> rr = DNS.Msg.RR.new(name: "example.org", type: :A, ttl: 0, rdmap: %{ip: "10.1.1.1"})
      iex> put(rr)
      :ignored

      # ignores unrelated RR's in answer section
      iex> init()
      iex> qtn = [[name: "example.com", type: :A]]
      iex> ans = [[name: "example.com", type: :A, ttl: 100, rdmap: %{ip: "10.2.1.1"}],
      ...>        [name: "example.net", type: :A, ttl: 100, rdmap: %{ip: "10.3.1.1"}]]
      iex> {:ok, msg} = DNS.Msg.new(qtn: qtn, ans: ans)
      iex> :ok = put(msg)
      iex> get("example.net", :IN, :A)
      []
      iex> [rr] = get("example.com", :IN, :A)
      iex> {rr.name, rr.rdmap.ip}
      iex> {"example.com", "10.2.1.1"}

      # ignores unrelated RR's in additional section
      iex> init()
      iex> qtn = [[name: "example.com", type: :A]]
      iex> aut = [[name: "com", type: :NS, rdmap: %{name: "ns1.tld-servers.com"}]]
      iex> add = [[name: "ns1.tld-servers.com", type: :A, ttl: 100, rdmap: %{ip: "10.4.1.1"}],
      ...>        [name: "ns1.tld-servers.net", type: :A, ttl: 100, rdmap: %{ip: "10.5.1.1"}]]
      iex> {:ok, msg} = DNS.Msg.new(qtn: qtn, aut: aut, add: add)
      iex> :ok = put(msg)
      iex> get("ns1.tld-servers.net", :IN, :A)
      []
      iex> [rr] = get("ns1.tld-servers.com", :IN, :A)
      iex> {rr.name, rr.rdmap.ip}
      iex> {"ns1.tld-servers.com", "10.4.1.1"}

  """
  @spec put(DNS.Msg.RR.t() | DNS.Msg.t()) :: :ok | :ignored | :error
  def put(rr_or_msg)

  def put(%DNS.Msg.RR{} = rr) do
    # make_key before check on cacheable? so we get error not ignored
    # if one of the key components is illegal.
    with {:ttl, false} <- {:ttl, rr.ttl < 1},
         {:ok, key} <- make_key(rr.name, rr.class, rr.type),
         {:type, true} <- {:type, cacheable?(rr.type)},
         {:ok, crrs} <- lookup(key),
         crrs <- Enum.filter(crrs, &alive?/1),
         crrs <- Enum.filter(crrs, fn {_ttd, crr} -> crr.rdmap != rr.rdmap end) do
      rr =
        if rr.raw,
          do: rr,
          else: %{rr | rdata: "", wdata: ""}

      :ets.insert(@cache, {key, [wrap_ttd(rr) | crrs]})
      :ok
    else
      {:type, _} -> :ignored
      {:ttl, _} -> :ignored
      _ -> :error
    end
  end

  def put(%DNS.Msg{answer: [_ | _]} = msg) do
    qname = (msg.question |> hd).name

    msg.answer
    |> Enum.filter(fn rr -> dname_equal?(rr.name, qname) end)
    |> Enum.map(&put/1)

    :ok
  rescue
    _ -> :error
  end

  def put(%DNS.Msg{answer: []} = msg) do
    qname = (msg.question |> hd).name

    rrs =
      msg.authority
      |> Enum.filter(fn rr -> rr.type in [:NS, :DS, :RRSIG] end)
      |> Enum.filter(fn rr -> dname_subzone?(qname, rr.name) end)

    nsnames =
      rrs
      |> Enum.filter(fn rr -> rr.type == :NS end)
      |> Enum.map(fn rr -> rr.rdmap.name end)

    msg.additional
    |> Enum.filter(fn rr -> rr.name in nsnames end)
    |> Enum.concat(rrs)
    |> Enum.map(&put/1)

    :ok
  end

  @doc """
  Gets the RRs for given `name`, `class` and `type`.

  A list of RR's is retrieved from the cache, expired
  RR's are removed from the results and deleted from the
  cache.

  Returns an empty list if any one of the arguments are invalid.

  ## Examples

      iex> rr = DNS.Msg.RR.new(name: "example.com", type: :A, ttl: 1, rdmap: %{ip: "10.1.1.1"})
      iex> init()
      iex> put(rr)
      :ok
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
      iex> Process.sleep(1500)
      iex> DNS.Cache.get("example.com", :IN, :A)
      []

      # illegal values won't get you anything
      iex> get("example.com", :IN, 65536)
      []

  """
  @spec get(binary, atom | non_neg_integer, atom | non_neg_integer) :: [DNS.Msg.RR.t()]
  def get(name, class, type) do
    with {:ok, key} <- make_key(name, class, type),
         {:ok, crrs} <- lookup(key),
         {rrs, dead} <- Enum.split_with(crrs, &alive?/1) do
      if dead != [] do
        # some died, so clean up cache
        if rrs == [],
          do: :ets.delete(@cache, key),
          else: :ets.insert(@cache, {key, rrs})
      end

      Enum.map(rrs, &unwrap_ttd/1)
    else
      _ -> []
    end
  end

  # [[ HELPERS ]]

  # ttd is absolute, monotonic time_to_die
  defp alive?({ttd, _rr}),
    do: timeout(ttd) > 0

  defp cacheable?(type) do
    type = DNS.Msg.Terms.decode_rr_type(type)
    type not in @uncacheable
  rescue
    _ -> false
  end

  defp lookup(key) do
    # an empty result list is :ok too (for put)
    case :ets.lookup(@cache, key) do
      [] -> {:ok, []}
      [{^key, rrs}] -> {:ok, rrs}
    end
  end

  defp make_key(name, class, type) do
    ntype = DNS.Msg.Terms.encode_rr_type(type)
    nclass = DNS.Msg.Terms.encode_dns_class(class)
    {:ok, name} = normalize(name)
    {:ok, {name, nclass, ntype}}
  rescue
    _ -> :error
  end

  defp normalize(name) do
    # TODO: properly parse and normalize the name
    {:ok, String.downcase(name)}
  end

  # (un)wrap time to die
  defp unwrap_ttd({ttd, rr}) do
    ttl = div(timeout(ttd), 1000)
    %{rr | ttl: ttl}
  end

  defp wrap_ttd(rr) do
    {time(rr.ttl * 1000), rr}
  end
end
