defmodule DNS.Cache do
  # above moduledoc since it's enumerated in doc
  @uncacheable [:OPT, :ANY, :*, :MAILA, :MAILB, :AXFR, :IXFR]
  @cache :dns_cache
  # max ttl in cache is 1 days
  @maxttl 86_400
  # root hints
  @priv :code.priv_dir(:dnscheck)
  @fname_nss Path.join([@priv, "root.nss"])
  @root_nss Code.eval_file(@fname_nss) |> elem(0)

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
  alias Logger, as: Log
  require Logger

  @type key :: {binary, non_neg_integer, non_neg_integer}
  @type rr :: DNS.Msg.RR.t()

  @doc """
  Creates and initializes to an empty cache.

  If the cache already exists, it is cleared.

  ## Examples

      iex> init(clear: true)
      :dns_cache
      iex> rr = DNS.Msg.RR.new(name: "example.com", ttl: 10)
      iex> put(rr)
      true
      iex> size()
      1
      # (re)initializing and clear cache
      iex> init(clear: true)
      iex> size()
      0

  """
  @spec init(Keyword.t()) :: atom
  def init(opts \\ []) do
    case :ets.whereis(@cache) do
      :undefined ->
        :ets.new(@cache, [:set, :public, :named_table, {:keypos, 1}, {:read_concurrency, true}])

      _ ->
        if Keyword.get(opts, :clear, false),
          do: :ets.delete_all_objects(@cache)

        @cache
    end
  end

  @spec clear() :: boolean
  def clear() do
    case :ets.whereis(@cache) do
      :undefined -> false
      _ -> :ets.delete_all_objects(@cache)
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
      iex> put(rr)
      true
      iex> [{key, [{_t, crr}]}] = :ets.tab2list(:dns_cache)
      iex> key
      {"example.org", 1, 1}
      iex> crr == rr
      true

      # TTL < 1 is ignored
      iex> rr = DNS.Msg.RR.new(name: "example.org", type: :A, ttl: 0, rdmap: %{ip: "10.1.1.1"})
      iex> put(rr)
      false


      # unrelated RR's in answer section are filtered out
      iex> init()
      iex> hdr = [opcode: :QUERY, qr: 1]
      iex> qtn = [[name: "example.com", type: :A]]
      iex> ans = [[name: "example.com", type: :A, ttl: 100, rdmap: %{ip: "10.2.1.1"}],
      ...>        [name: "example.net", type: :A, ttl: 100, rdmap: %{ip: "10.3.1.1"}]]
      iex> {:ok, msg} = DNS.Msg.new(hdr: hdr, qtn: qtn, ans: ans)
      iex> size()
      0
      iex> put(msg)
      true
      iex> size()
      1
      iex> get("example.net", :IN, :A)
      []
      iex> [rr] = get("example.com", :IN, :A)
      iex> {rr.name, rr.rdmap.ip}
      {"example.com", "10.2.1.1"}

      # ignores unrelated RR's in additional section
      iex> init()
      iex> hdr = [qr: 1]
      iex> qtn = [[name: "example.com", type: :A]]
      iex> aut = [[name: "com", type: :NS, rdmap: %{name: "ns1.tld-servers.com"}]]
      iex> add = [[name: "ns1.tld-servers.com", type: :A, ttl: 100, rdmap: %{ip: "10.4.1.1"}],
      ...>        [name: "ns1.tld-servers.net", type: :A, ttl: 100, rdmap: %{ip: "10.5.1.1"}]]
      iex> {:ok, msg} = DNS.Msg.new(hdr: hdr, qtn: qtn, aut: aut, add: add)
      iex> put(msg)
      false
      iex> get("ns1.tld-servers.net", :IN, :A)
      []
      iex> [rr] = get("ns1.tld-servers.com", :IN, :A)
      iex> {rr.name, rr.rdmap.ip}
      iex> {"ns1.tld-servers.com", "10.4.1.1"}

  """
  @spec put(DNS.Msg.RR.t() | DNS.Msg.t()) :: boolean
  def put(rr_or_msg)

  def put(%DNS.Msg.RR{name: name} = rr) when name in ["", "."] do
    # explicitly ignore RR's referencing root
    Log.warning("ignoring #{inspect(rr)}")
    false
  end

  def put(%DNS.Msg.RR{} = rr) do
    # make_key before check on cacheable? so we get error not ignored
    # if one of the key components is illegal.
    # - assumes rdmap hasn't been tampered/played with (i.e. org fields only)
    # TODO: keep cached rrs whose ttl > rr.ttl
    with true <- rr.ttl > 0,
         {:ok, key} <- make_key(rr.name, rr.class, rr.type),
         true <- cacheable?(rr),
         maxttl <- min(@maxttl, rr.ttl),
         {:ok, crrs} <- lookup(key),
         crrs <- Enum.filter(crrs, &alive?/1),
         crrs <- Enum.filter(crrs, fn {_ttd, crr} -> crr.rdmap != rr.rdmap end) do
      rr =
        if rr.raw,
          do: rr,
          else: %{rr | ttl: maxttl, rdata: "", wdata: ""}

      Log.info("caching #{inspect(rr)}")
      :ets.insert(@cache, {key, [wrap_ttd(rr) | crrs]})
    else
      _e -> false
    end
  end

  def put(%DNS.Msg{answer: [_ | _]} = msg) do
    # Msg has answer RR's
    # - only take relevant RRs from answer section
    # REVIEW: donot ignore aut/add sections
    # TODO: ignore answers that have a irrelevant SOA in aut-section
    # Log.info("msg is #{msg}")

    with true <- cacheable?(msg),
         qname <- hd(msg.question).name do
      msg.answer
      |> Enum.filter(fn rr -> dname_equal?(rr.name, qname) end)
      |> Enum.map(&put/1)
      |> Enum.all?(& &1)
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  def put(%DNS.Msg{answer: []} = msg) do
    # https://www.rfc-editor.org/rfc/rfc1035#section-7.4 - using the cache
    # - ignores message if truncated, etc
    # - ignores aut-RR's unless it's a parent for qname
    # - checks add-RR's are listed in remaining aut-NSs
    # Log.info("msg offered is #{msg}")

    if cacheable?(msg) do
      qname = hd(msg.question).name

      rrs =
        msg.authority
        |> Enum.filter(fn rr -> rr.type in [:NS, :DS, :RRSIG] end)
        |> Enum.filter(fn rr ->
          dname_subdomain?(qname, rr.name) or dname_equal?(qname, rr.name)
        end)

      nsnames =
        rrs
        |> Enum.filter(fn rr -> rr.type == :NS end)
        |> Enum.map(fn rr -> rr.rdmap.name end)
        |> Enum.map(fn name -> dname_normalize(name) end)

      msg.additional
      |> Enum.filter(fn rr -> dname_normalize(rr.name) in nsnames end)
      |> Enum.concat(rrs)
      |> Enum.map(&put/1)
      |> Enum.all?(& &1)
    else
      false
    end
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
      true
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
      iex> Process.sleep(1800)
      iex> DNS.Cache.get("example.com", :IN, :A)
      []

      # illegal values won't get you anything
      iex> get("example.com", :IN, 65536)
      []

  """
  @spec get(binary, atom | non_neg_integer, atom | non_neg_integer, boolean) :: [DNS.Msg.RR.t()]
  def get(name, class, type, strict \\ false) do
    # REVIEW: maybe add opts for :strict, :stale (serve expired RR's ?)
    with {:ok, key} <- make_key(name, class, type),
         {:ok, crrs} <- lookup(key),
         {rrs, dead} <- Enum.split_with(crrs, &alive?/1) do
      if dead != [] do
        Log.info("{#{name}, #{class}, #{type}} -> removing #{length(dead)} expired RR(s)")

        if rrs == [],
          do: :ets.delete(@cache, key),
          else: :ets.insert(@cache, {key, rrs})
      end

      if crrs == [] and not strict and type != :CNAME,
        do: get(name, class, :CNAME, true),
        else: Enum.map(rrs, &unwrap_ttd/1)
    else
      _ ->
        Log.error("failed to make key for #{inspect({name, class, type})}")
        []
    end
  end

  @doc """
  Returns either a list of nameservers or false for given `zone`

  The cache is searched, dropping front labels until either a list of
  nameservers is found or the labels have been exhausted.  In the first case,
  the list represents the 'closest' set of nameservers for given `zone`.  In
  the latter case, `false` is returned.

  A nameserver in the list is represented as `{:inet.ip_address, 53}`.

  ## Example

      iex> init()
      iex> put(DNS.Msg.RR.new(name: "example.com", type: :NS, ttl: 10, rdmap: %{name: "ns1.example.com"}))
      iex> put(DNS.Msg.RR.new(name: "example.com", type: :NS, ttl: 10, rdmap: %{name: "ns2.example.net"}))
      iex> put(DNS.Msg.RR.new(name: "ns1.example.com", type: :A, ttl: 10, rdmap: %{ip: "10.1.1.1"}))
      iex> put(DNS.Msg.RR.new(name: "ns2.example.net", type: :A, ttl: 10, rdmap: %{ip: "10.2.1.1"}))
      iex> size()
      3
      iex> nss = nss("host.example.com")
      iex> {{10, 1, 1, 1}, 53} in nss
      true
      iex> {{10, 2, 1, 1}, 53} in nss
      true
      iex> length(nss)
      2

  """
  @spec nss(binary) :: [{:inet.ip_address(), integer}]
  def nss(zone) when is_binary(zone) do
    with {:ok, labels} <- dname_normalize(zone, join: false) do
      nssp(labels)
    else
      _ ->
        Log.error("illegal zone name #{inspect(zone)}")
        []
    end
  end

  # return a list of :NS names or empty list
  defp nssp([]),
    do: Enum.shuffle(@root_nss)

  defp nssp([first | rest]) do
    zone = Enum.join([first | rest], ".")

    case get(zone, :IN, :NS, true) do
      [] ->
        Log.debug("zone #{zone} has no nss in cache")
        nssp(rest)

      nss ->
        Log.info("zone #{zone} has #{length(nss)} nss")

        nss
        |> Enum.map(fn rr -> rr.rdmap.name end)
        |> Enum.map(fn name -> [get(name, :IN, :A, true), get(name, :IN, :AAAA, true)] end)
        |> List.flatten()
        |> Enum.map(fn rr -> {Pfx.to_tuple(rr.rdmap.ip, mask: false), 53} end)
        |> Enum.shuffle()
        |> case do
          [] -> nssp(rest)
          nss -> nss
        end
    end
  end

  # [[ HELPERS ]]

  # ttd is absolute, monotonic time_to_die
  defp alive?({ttd, _rr}),
    do: timeout(ttd) > 0

  defp cacheable?(%DNS.Msg.RR{} = rr) do
    # https://datatracker.ietf.org/doc/html/rfc1123#section-6
    # [ ] never cache NS from root hints
    type = DNS.Msg.Terms.decode_rr_type(rr.type)

    cond do
      type in @uncacheable -> false
      rr.ttl < 1 -> false
      true -> true
    end
  rescue
    _ -> false
  end

  defp cacheable?(%DNS.Msg{} = msg) do
    # https://datatracker.ietf.org/doc/html/rfc1123#section-6
    # [ ] MUST never cache NS from root hints
    # [ ] SHOULD cache temporary failures (TTL order of minutes)
    # [ ] SHOULD cache negative responses
    # [ ] never cache MSG when rcode=REFUSED, NOTIMPL
    # [ ] never cache RRs from bogus/lame response_type
    # https://www.rfc-editor.org/rfc/rfc1035#section-7.4 - Using the cache
    # [x] do not cache RR's from a truncated response
    # [x] do not cache RR's from *inverse query* (QTYPE)
    # [x] do not cache results that have QNAME with a wildcard label  (*.xyz.tld, or xyz.*.tld)
    # [?] do not RR's of responses of dubious reliability, but how to determine that?
    # [?] should responses from e.g. 9.9.9.9 be cached? (their TTL's for
    #     NXDOMAIN are all over the place.. i.e. non-authoritative answers.
    # [x] unsollicited responses or RR DATA that was not requested (resolver MUST check this)
    #  `-> done by put(msg)
    # Sometimes cache data MUST be replaced
    # [ ] cached data is not authoritative and the current msg is authoritative
    qname = hd(msg.question).name
    labels = dname_to_labels(qname)
    wildcard = List.starts_with?(labels, ["*"])

    cond do
      wildcard -> false
      msg.header.tc == 1 -> false
      msg.header.qr == 0 -> false
      msg.header.opcode not in [0, :QUERY] -> false
      true -> true
    end
  rescue
    _ -> false
  end

  @spec lookup(key) :: {:ok, [rr]}
  defp lookup(key) do
    # an empty result list is :ok too (for put)
    # REVIEW: @spec lookup(key) :: [rr], do not need {:ok, ...}
    case :ets.lookup(@cache, key) do
      [] -> {:ok, []}
      [{^key, rrs}] -> {:ok, rrs}
    end
  end

  @spec make_key(binary, atom, atom) :: {:ok, tuple} | :error
  defp make_key(name, class, type) do
    ntype = DNS.Msg.Terms.encode_rr_type(type)
    nclass = DNS.Msg.Terms.encode_dns_class(class)
    {:ok, name} = dname_normalize(name)
    {:ok, {name, nclass, ntype}}
  rescue
    _ -> :error
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
