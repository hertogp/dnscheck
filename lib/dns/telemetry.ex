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
  import DNS.Time
  alias DNS.Param

  @handler_id "dns-default-logger"

  @events [
    [:dns, :cache, :hit],
    [:dns, :cache, :miss],
    [:dns, :cache, :expired],
    [:dns, :cache, :insert],
    [:dns, :cache, :error],
    #
    [:dns, :nss, :switch],
    [:dns, :nss, :select],
    [:dns, :nss, :fail],
    [:dns, :nss, :drop],
    [:dns, :nss, :error],
    [:dns, :nss, :rotate],
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

  def attach_default_logger(opts \\ %{}) do
    opts = do_opts(opts)
    :telemetry.detach(@handler_id)
    :telemetry.attach_many(@handler_id, Map.keys(opts), &DNS.Telemetry.handle_event/4, opts)
  end

  def detach_default_handler() do
    :telemetry.detach(@handler_id)
  end

  @doc """
  Returns the default logger's current configuration.

  If the optional `default` is set to true, returns the default
  configuration that would be used when attaching the default logger
  with no specific configuration.
  """
  @spec config(Keyword.t()) :: map
  def config(opts \\ []) do
    if Keyword.get(opts, :default, false) do
      do_opts(%{})
    else
      :telemetry.list_handlers([:dns])
      |> Enum.map(fn cfg -> cfg.config end)
      |> Enum.reduce(%{}, fn c, acc -> Map.merge(acc, c) end)
    end
  end

  @doc """
  Get or set `DNS.Telemetry`'s logging level.

  Use the option `:set` to set the module's logging level.
  When omitted, returns the current logging level.

  """

  @spec level(Keyword.t()) :: :ok | {:error, term} | atom
  def level(opts \\ []) do
    level = Keyword.get(opts, :set, nil)

    if level do
      Logger.put_module_level(__MODULE__, level)
    else
      Logger.get_module_level(__MODULE__)
      |> Enum.find({__MODULE__, :none}, fn t -> elem(t, 0) == __MODULE__ end)
      |> elem(1)
    end
  end

  # [[ NS events ]]

  def handle_event([:dns, :ns, topic] = event, _metrics, meta, cfg) do
    # FIXME: [:dns, :ns, :error] event has no ctx
    # - don't emit from lower levels, emit from places where ctx is available
    Logger.log(cfg[event], fn ->
      details =
        if cfg[event] == :debug do
          to_str(meta)
        else
          case topic do
            :query ->
              {ns, ip, port} = meta.ns
              qry = Enum.map(meta.qry.question, fn q -> "#{q.name}/#{q.class}/#{q.type}" end)

              [to_str(qry), " @#{Pfx.new(ip)}##{port}/#{meta.proto} (#{ns})"]

            :reply ->
              tc = if meta.msg.header.tc == 1, do: " (truncated)", else: ""
              qtn = Enum.frequencies_by(meta.msg.question, fn rr -> rr.type end)
              aut = Enum.frequencies_by(meta.msg.authority, fn rr -> rr.type end)
              add = Enum.frequencies_by(meta.msg.additional, fn rr -> rr.type end)

              ans =
                if meta.type == :answer,
                  do: Enum.map(meta.msg.answer, fn rr -> "(#{rr})" end),
                  else: Enum.frequencies_by(meta.msg.answer, fn rr -> rr.type end)

              [
                "#{meta.type}",
                " QTN:",
                to_str(qtn),
                " AUT:",
                to_str(aut),
                " ANS:",
                to_str(ans),
                " ADD:",
                to_str(add),
                tc
              ]

            :error ->
              {ns, ip, port} = meta.ns
              qry = Enum.map(meta.qry.question, fn q -> "#{q.name}/#{q.class}/#{q.type}" end)
              [to_str(qry), " @#{Pfx.new(ip)}#{port}/#{meta.proto} (#{ns}) ", to_str(meta.reason)]

            :loop ->
              ["REASON:", to_str(meta.reason), " SEEN:", to_str(meta.seen)]

            :lame ->
              ["NS:", to_str(meta.ns), " REPLY:", to_iodata(meta.msg)]
          end
        end

      [logid(meta.ctx), " ns:#{topic} ", details]
    end)
  end

  # [[ NSS events ]]

  def handle_event([:dns, :nss, topic] = event, _metrics, meta, cfg) do
    Logger.log(cfg[event], fn ->
      details =
        if cfg[event] == :debug do
          [to_str(meta)]
        else
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
              [
                " REASON:",
                to_str(meta.reason),
                " FAILED",
                to_str([meta.ns | meta.failed])
              ]

            :drop ->
              ["NS:", to_str(meta.ns), " REASON:", to_str(meta.error)]

            :rotate ->
              ["RETRY:", to_str(meta.nth), " NSSFAILED:", to_str(meta.failed)]

            :error ->
              [to_str(meta.error)]
          end
        end

      [logid(meta.ctx), " nss:#{topic} ", details]
    end)
  end

  # [[ CACHE events ]]

  def handle_event([:dns, :cache, topic] = event, _metrics, meta, cfg) do
    Logger.log(cfg[event], fn ->
      details =
        if cfg[event] == :debug do
          [to_str(meta)]
        else
          {name, class, type} = meta.key
          key = {name, Param.class_decode(class), Param.rrtype_decode(type)} |> to_str

          case topic do
            :miss ->
              ["KEY:", key]

            :error ->
              ["ERROR KEY:", key, " REASON:", to_str(meta.reason)]

            :hit ->
              ["KEY:", key, " RRS:", to_str(meta.rrs)]

            :expired ->
              ["KEY:", key, " RRS:", to_str(meta.rrs)]

            :insert ->
              ["KEY:", key, " RRS:", to_str(meta.rrs)]
          end
        end

      [logid(meta.ctx), " cache:#{topic} ", details]
    end)
  end

  def set_level(level) do
    Logger.put_module_level(__MODULE__, level)
  end

  # [[ HELPERS ]]

  @spec to_iodata(DNS.Msg.t(), Keyword.t()) :: iolist
  def to_iodata(%DNS.Msg{} = msg, opts \\ []) do
    drop = [:rdata, :wdata] -- (Keyword.get(opts, :keep, []) |> List.wrap())

    [
      "[header:",
      to_str(Map.drop(msg.header, drop)),
      " question:",
      to_str(Enum.map(msg.question, fn qtn -> Map.drop(qtn, drop) end)),
      " authority:",
      to_str(Enum.map(msg.authority, fn rr -> Map.drop(rr, drop) end)),
      " answer:",
      to_str(Enum.map(msg.answer, fn rr -> Map.drop(rr, drop) end)),
      " additional:",
      to_str(Enum.map(msg.additional, fn rr -> Map.drop(rr, drop) end)),
      " xdata:",
      to_str(msg.xdata),
      "]"
    ]
  end

  @spec to_str(any) :: String.t() | [String.t()]
  def to_str(m) when is_struct(m),
    do: Map.from_struct(m) |> to_str()

  def to_str(m) when is_map(m),
    do: Map.to_list(m) |> to_str()

  def to_str([]),
    do: "[]"

  def to_str([h | t]),
    do: ["[", Enum.reduce(t, to_str(h), fn e, acc -> [acc, ", ", to_str(e)] end), "]"]

  def to_str(a) when is_atom(a),
    do: Atom.to_string(a)

  def to_str(<<>>),
    do: "<<>>"

  def to_str(b) when is_binary(b) do
    if String.printable?(b),
      do: b,
      else: inspect(b, limit: :infinity)
  end

  def to_str({k, v}),
    do: [to_str(k), ":", to_str(v)]

  def to_str(other),
    do: inspect(other, limit: :infinity)

  # [[ log ]]

  @doc false
  def logid(ctx) do
    ms = String.pad_leading("#{now() - ctx.tstart}", 4)
    ["DNS:", "#{ctx.logid} [#{ctx.depth},#{ms}ms]"]
  end

  # For modules that use DNS.Telemetry
  @doc """
  Emits an event via `Telemetry.execute/2`.

  This convenience function prepends `:dns` to the event and takes
  a keyword list, which is turned into a map when calling `Telemetry.execute/2`.

  Modules can use `import DNS.Telemetry, only: [emit: 2]`.

  """
  @spec emit(Telemetry.event_name(), Keyword.t()) :: :ok
  def emit(event, meta),
    do: :telemetry.execute([:dns | event], %{}, Map.new(meta))
end
