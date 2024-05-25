defmodule DNS.Telemetry do
  @moduledoc """
  `Telemetry` integration for DNS event metrics and logging.

  ## Events

  When iterating down the DNS tree, the resolver generates a number of events
  in different contexts:
  - `ns`, events related to an individual nameserver
  - `nss`, events related to dealing with a (changing) nameserver set
  - `query`, events related to questions posed and answers given (or not)
  - `cache`, events related to the (simple) DNS cache

  All events are emitted as `[:dns, context, event]`.

  ### `:ns` events

  Emitted as `[:dns, :ns, event]`, where event includes:
  - `:query`, a query was sent
  - `:reply`, a reply was received
  - `:error`, a error occurred while talking to a nameserver
  - `:lame`, a lame reply was received
  - `:loop`, reply leads to cname or zone loop

  ### `:nss` events

  These include:
  - `:select`, a name server was selected
  - `:switch`, the resolver switched to a new set of nameservers after a referral
  - `:drop`, a nameserver was dropped from the nameserver set
  - `:fail`, a nameserver was added to the failed list for (possibly) later use
  - `:rotate`, the failed nss was selected as the new nss

  ### `cache` events

  Emitted as `[:dns, :cache, event]`, where `event` is one of:
  - `:hit`, cache has RRs for given query
  - `:miss`, cache has no RRs for given query
  - `:expired`, one or more RRs were removed due to TTL
  - `:error`, a cache request encountered an error

  """

  require Logger
  import DNS.Utils

  @handler_id "dns-default-logger"

  @events [
    [:dns, :cache, :hit],
    [:dns, :cache, :miss],
    [:dns, :cache, :expired],
    [:dns, :cache, :insert],
    #
    [:dns, :nss, :switch],
    [:dns, :nss, :select],
    [:dns, :nss, :fail],
    [:dns, :nss, :drop],
    [:dns, :nss, :error],
    #
    [:dns, :ns, :query],
    [:dns, :ns, :reply],
    [:dns, :ns, :loop],
    [:dns, :ns, :lame],
    [:dns, :ns, :error]
  ]

  # [[ DEFAULT LOGGER ]]

  defp do_opts(opts) when map_size(opts) == 0 do
    do_opts(%{
      [:dns] => :info,
      [:dns, :nss, :drop] => :warning,
      [:dns, :nss, :fail] => :warning,
      [:dns, :nss, :error] => :error,
      [:dns, :ns, :loop] => :error,
      [:dns, :ns, :lame] => :warning,
      [:dns, :ns, :error] => :error,
      [:dns, :cache] => :debug
    })
  end

  defp do_opts(opts) do
    # short(er) keys first
    sorted =
      opts
      |> Map.to_list()
      |> Enum.sort()

    # replace possible short keys with all longer instances
    for {k, v} <- sorted do
      Enum.filter(@events, fn evt -> List.starts_with?(evt, k) end)
      |> Enum.map(fn k -> {k, v} end)
    end
    |> List.flatten()
    |> Enum.into(%{})
  end

  def(attach_default_logger(opts \\ %{})) do
    opts = do_opts(opts)
    :telemetry.detach(@handler_id)
    :telemetry.attach_many(@handler_id, Map.keys(opts), &DNS.Telemetry.handle_event/4, opts)
  end

  def detach_default_handler() do
    :telemetry.detach(@handler_id)
  end

  # [[ NS events ]]

  def handle_event([:dns, :ns, topic] = event, _metrics, meta, cfg) do
    lvl = level(cfg, event)

    Logger.log(lvl, fn ->
      details =
        case topic do
          :query ->
            ["PROTO:", meta.proto, " NS:", to_str(meta.ns), " QTN:", to_str(meta.qry.question)]

          :reply ->
            ["TYPE:#{meta.type}", " REPLY:", to_iodata(meta.msg)]

          :error ->
            ["NS:", to_str(meta.ns), " REASON:", meta.reason]

          :loop ->
            ["REASON:", to_str(meta.reason), " SEEN:", to_str(meta.seen)]

          :lame ->
            ["NS:", to_str(meta.ns), " REPLY:", to_iodata(meta.msg)]
        end

      [logid(meta.ctx), " ns:#{topic} ", details]
    end)
  end

  # [[ NSS events ]]

  def handle_event([:dns, :nss, topic] = event, _metrics, meta, cfg) do
    lvl = level(cfg, event)

    Logger.log(lvl, fn ->
      details =
        case topic do
          :switch ->
            glued = "#{length(meta.in_glue)}/#{length(meta.nss)}"

            [
              "NS:",
              meta.ns,
              " ZONE:",
              meta.zone,
              " GLUED:#{glued}",
              " NSS:",
              to_str(meta.nss),
              " DROP:",
              to_str(meta.ex_glue)
            ]

          :select ->
            ["NS:", to_str(meta.ns)]

          :fail ->
            ["NS:", to_str(meta.ns), " REASON:", to_str(meta.error)]

          :drop ->
            ["NS:", to_str(meta.ns), " REASON:", to_str(meta.error)]
        end

      [logid(meta.ctx), " nss:#{topic} ", details]
    end)
  end

  # [[ CACHE events ]]

  def handle_event([:dns, :cache, topic] = event, _metrics, meta, cfg) do
    lvl = level(cfg, event)

    Logger.log(lvl, fn ->
      details =
        case topic do
          :miss ->
            ["KEY:", to_str(meta.key)]

          :hit ->
            ["KEY:", to_str(meta.key), " RRS:", to_str(meta.rrs)]

          :expired ->
            ["KEY:", to_str(meta.key), " RRS:", to_str(meta.rrs)]

          :insert ->
            ["KEY:", to_str(meta.key), " RRS:", to_str(meta.rrs)]

          :error ->
            ["ERROR KEY:", to_str(meta.key), "REASON:", "#{meta.reason}"]

          _ ->
            ["ERROR cache event not handled, meta:#{inspect(meta)}"]
        end

      ["cache:#{topic} ", details]
    end)
  end

  def set_level(level) do
    Logger.put_module_level(__MODULE__, level)
  end

  # [[ HELPERS ]]
  defp logid(ctx),
    do: ["DNS:", "#{ctx.qid} [#{ctx.depth},#{now() - ctx.tstart}ms]"]

  def to_iodata(%DNS.Msg{} = msg) do
    [
      "[HDR:",
      to_str(msg.header),
      " QTN:",
      to_str(msg.question),
      " AUT:",
      to_str(msg.authority),
      " ANS:",
      to_str(msg.answer),
      " ADD:",
      to_str(msg.additional),
      " XDATA:",
      to_str(msg.xdata),
      "]"
    ]
  end

  def to_str(m) when is_map(m) do
    m
    |> Map.drop([:__struct__, :rdata, :wdata])
    |> Map.to_list()
    |> to_str()
  end

  def to_str(l) when is_list(l) do
    [
      "[",
      l
      |> Enum.map(&to_str/1)
      |> Enum.intersperse(", "),
      "]"
    ]
  end

  def to_str(a) when is_atom(a),
    do: Atom.to_string(a)

  def to_str(b) when is_binary(b) do
    if String.printable?(b),
      do: b,
      else: inspect(b, limit: :infinity)
  end

  def to_str({k, v}) do
    [to_str(k), ":", to_str(v)]
  end

  def to_str(n) when is_number(n),
    do: "#{n}"

  def to_str(other) do
    [inspect(other)]
  end

  # [[ log ]]

  def level(_cfg, []),
    do: :info

  def level(cfg, [_ | rest] = event) do
    case cfg[event] do
      nil -> level(cfg, rest)
      level -> level
    end
  end
end
