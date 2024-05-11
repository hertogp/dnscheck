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

  def attach_default_logger() do
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
        [:dns, :nss, :switch]
      ],
      &DNS.Telemetry.handle_event/4,
      nil
    )
  end

  def detach_default_handler() do
    :telemetry.detach(@handler_id)
  end

  # [[ QUERY events ]]

  def handle_event([:dns, :query, event], metrics, meta, _config) do
    evt = "#{format_id(meta.ctx)} query:#{event}"
    qry = format_qtn(meta.qry)

    case event do
      :start ->
        hdr = format_hdr(meta.qry)
        nss = Enum.map(meta.nss, fn ns -> "#{inspect(ns)}" end) |> Enum.join(", ")
        Logger.info("#{evt} qry:[#{qry}] hdr:#{hdr}")
        Logger.info("#{evt} qry:[#{qry}] nss:#{nss}")

      :stop ->
        case meta.resp do
          {:ok, msg} ->
            ms = System.convert_time_unit(metrics.duration, :native, :millisecond)
            hdr = format_hdr(msg)
            resp = format_msg(msg)
            rcode = DNS.xrcode(msg)

            Logger.info("#{evt} #{ms}ms, #{rcode}, hdr:#{hdr}")
            Logger.info("#{evt} ans:[#{resp}]}")

          {:error, {reason, msg}} ->
            ms = System.convert_time_unit(metrics.duration, :native, :millisecond)
            Logger.info("#{evt} #{ms}ms, #{reason} #{inspect(msg)}")
        end

      :exception ->
        error = Exception.format_banner(meta.kind, meta.reason, meta.stacktrace)
        Logger.error("#{evt} EXCEPTION, #{inspect(error)}")

      :ns ->
        {name, ip, port} = meta.ns
        ip = Pfx.new(ip)
        Logger.info("#{evt} qry:[#{qry}] ns:#{name} (#{ip}@#{port})")

      :reply ->
        Logger.info("#{evt} type:#{meta.type}")
    end
  end

  # [[ CACHE events ]]

  def handle_event([:dns, :cache, event], _metrics, meta, _config) do
    evt = "cache:#{event}"

    case event do
      :miss ->
        Logger.info("#{evt} qry:[(#{meta.qry})]")

      :hit ->
        rrs = format_rrs(meta.rrs)
        Logger.info("#{evt} RRs:[#{rrs}]")

      :expired ->
        rrs = format_rrs(meta.rrs)
        Logger.info("#{evt} RRs:[#{rrs}]")

      :error ->
        Logger.error("#{evt} #{meta.reason}")

      _ ->
        Logger.error("#{evt} not handled, meta:#{inspect(meta)}")
    end
  end

  # [[ NSS events ]]

  def handle_event([:dns, :nss, event], _metrics, meta, _config) do
    evt = "#{format_id(meta.ctx)} nss:#{event}"

    case event do
      :switch ->
        zone = meta.zone
        nss = Enum.join(meta.nss, ", ")
        glued = "#{length(meta.in_glue)}/#{length(meta.nss)}"

        Logger.info("#{evt} zone:#{zone}, glued:#{glued}, nss:[#{nss}]")

        if meta.ex_glue != [] do
          ex_glue = Enum.join(meta.ex_glue, ",")
          Logger.warning("#{evt} zone:#{zone} no glue, dropped:[#{ex_glue}]")
        end
    end
  end

  # catch all
  def handle_event(event, metrics, meta, _config) do
    Logger.info(
      "** UNKNOWN QUERY EVENT ** #{inspect(event)} #{inspect(metrics)} #{inspect(meta)}"
    )
  end

  # [[ HELPERS ]]
  defp format_id(ctx),
    do: "DNS.#{ctx.qid}-#{ctx.qnr}"

  defp format_hdr(%DNS.Msg{header: hdr}) do
    hdr
    |> Map.delete(:__struct__)
    |> Map.delete(:wdata)
    |> inspect()
  end

  defp format_qtn(%DNS.Msg{} = msg) do
    msg.question
    |> Enum.map(fn rr -> "(#{rr.name},#{rr.class},#{rr.type})" end)
    |> Enum.join(",")
  end

  # TODO: once level is added, also add auth/add-rrs for debug level
  defp format_msg(%DNS.Msg{} = msg),
    do: format_rrs(msg.answer)

  defp format_rrs(rrs) do
    rrs
    |> Enum.map(fn rr -> "(#{rr.name},#{rr.class},#{rr.type},#{inspect(rr.rdmap)})" end)
    |> Enum.join(", ")
  end
end
