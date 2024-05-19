defmodule DNS.Telemetry do
  @moduledoc """
  `Telemetry` integration for DNS event metrics and logging.

  A number of things may occur during resolving:
  - a msg was sent
  - a msg was received
  - a query was resolved (span event)
  - a query failed to resolve
  - a ns was resolved
  - a ns refused a query
  - a ns timed out and sent to retry list
    - udp timeout
    - tcp timeout
  - fallback to tcp occurred due to msg being truncated
  - a nss was swapped (failed -> try again nss)
  - a nss was exhausted (none could be reached)
  - a msg recvd contained a referral
  - a msg could not be encoded/decoded
  - a msg contained a lame answer
  - an unsollicited msg was received
  - a msg was (partially) cached
  - a rr was cached or rejected by cache
  - a cache miss/hit occurred
  - an answer was synthesized from cache
  - a cache action limited a TTL



  ## Eevents

  metadata:
  - uqid = hash of qname, proto, qtype of original user query
  - cqid = hash of current qname, proto, qtype

  :dns, :query, :sent      %{type: :user|:system, src,sport,dst,dport,proto}
  :dns, :query, :resolved  %{type: :user|:system, ,,}
  :dns, :query, :failed    %{type, :user|:system, ,,}

  :dns, :reply, :received  %{type: :referral|:lame|:answer..}
  :dns, :reply, :unsollicited %{type: ...}

  :dns, :socket, :created
  ...


  """

  require Logger

  @handler_id "dns-default-logger"

  # [[ DEFAULT LOGGER ]]

  def attach_default_logger(opts) do
    opts =
      opts
      |> Map.put_new([:query], :info)
      |> Map.put_new([:cache], :debug)
      |> Map.put_new([:expired, :cache], :info)
      |> Map.put_new([:nss], :info)

    :telemetry.detach(@handler_id)

    :telemetry.attach_many(
      @handler_id,
      [
        [:dns, :query, :start],
        [:dns, :query, :stop],
        [:dns, :query, :exception],
        [:dns, :query, :ns],
        [:dns, :query, :reply],
        [:dns, :cache, :hit],
        [:dns, :cache, :miss],
        [:dns, :cache, :expired],
        [:dns, :cache, :insert],
        [:dns, :nss, :switch]
      ],
      &DNS.Telemetry.handle_event/4,
      opts
    )
  end

  def detach_default_handler() do
    :telemetry.detach(@handler_id)
  end

  # [[ QUERY events ]]

  def handle_event([:dns, :query, event], metrics, meta, cfg) do
    evt = [logid(meta.ctx), " query:#{event} "]
    lvl = level(cfg, [event, :query])

    case event do
      :start ->
        log(lvl, [evt, " QRY:", to_str(meta.qry), " NSS:", to_str(meta.nss)])

      :stop ->
        case meta.resp do
          {:ok, msg} ->
            ms = System.convert_time_unit(metrics.duration, :native, :millisecond)

            log(lvl, [evt, "TIME:#{ms}ms ", "REPLY:", to_str(msg)])

          {:error, {reason, msg}} ->
            ms = System.convert_time_unit(metrics.duration, :native, :millisecond)
            Logger.info("#{evt} #{ms}ms, #{reason} #{inspect(msg)}")
        end

      :exception ->
        error = Exception.format_banner(meta.kind, meta.reason, meta.stacktrace)
        Logger.error("#{evt} EXCEPTION, #{inspect(error)}")

      :ns ->
        log(lvl, [evt, "QRY:", to_str(meta.qry), "NS:", to_str(meta.ns)])

      :reply ->
        log(lvl, [evt, "type:#{meta.type}"])
    end
  end

  # [[ CACHE events ]]

  def handle_event([:dns, :cache, event], _metrics, meta, cfg) do
    evt = "cache:#{event} "
    lvl = level(cfg, [event, :cache])

    Logger.log(lvl, fn ->
      case event do
        :miss ->
          [evt, "KEY:", to_str(meta.key)]

        :hit ->
          [evt, "KEY:", to_str(meta.key), " RRS:", to_str(meta.rrs)]

        :expired ->
          [evt, "KEY:", to_str(meta.key), " RRS:", to_str(meta.rrs)]

        :insert ->
          [evt, "KEY:", to_str(meta.key), " RRS:", to_str(meta.rrs)]

        :error ->
          ["#{evt} ERROR KEY:", to_str(meta.key), "REASON:", "#{meta.reason}"]

        _ ->
          ["#{evt} ERROR not handled, meta:#{inspect(meta)}"]
      end
    end)
  end

  # [[ NSS events ]]

  def handle_event([:dns, :nss, event], _metrics, meta, cfg) do
    lvl = level(cfg, [event, :nss])

    Logger.log(lvl, fn ->
      evt = "#{logid(meta.ctx)} nss:#{event} "

      case event do
        :switch ->
          glued = "#{length(meta.in_glue)}/#{length(meta.nss)}"
          iodata = [evt, "ZONE:#{meta.zone}", " GLUED:#{glued}", " NSS:", to_str(meta.nss)]

          if meta.ex_glue != [],
            do: [iodata, [evt, "ZONE:#{meta.zone}", " DROP:", to_str(meta.ex_glue)]],
            else: iodata
      end
    end)
  end

  # catch all
  def handle_event(event, metrics, meta, _config) do
    Logger.info(
      "** UNKNOWN QUERY EVENT ** #{inspect(event)} #{inspect(metrics)} #{inspect(meta)}"
    )
  end

  def set_level(level) do
    Logger.put_module_level(__MODULE__, level)
  end

  # [[ HELPERS ]]
  defp logid(ctx),
    do: ["DNS:", "#{ctx.qid}-#{ctx.qnr}"]

  def to_iodata(%DNS.Msg{} = msg) do
    [
      "HDR:",
      to_str(msg.header),
      " QTN:",
      to_str(msg.question),
      " AUT:",
      to_str(msg.authority),
      " ANS:",
      to_str(msg.answer),
      " ADD:",
      to_str(msg.additional)
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

  defp log(level, iodata),
    do: Logger.log(level, IO.iodata_to_binary(iodata))
end
