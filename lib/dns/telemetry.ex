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
        [:dns, :cache, :hit]
      ],
      &DNS.Telemetry.handle_event/4,
      nil
    )
  end

  def detach_default_handler() do
    :telemetry.detach(@handler_id)
  end

  # [[ QUERY EVENTS ]]

  def handle_event([:dns, :query, event], metrics, meta, _config) do
    id = format_id(meta.ctx)

    case event do
      :start ->
        nil

      :stop ->
        ms = System.convert_time_unit(metrics.duration, :native, :millisecond)
        resp = format_resp(meta.resp)
        Logger.info("#{id} #{ms} ms #{resp}")

      :exception ->
        Logger.error("#{id} #{inspect(meta)}")
    end
  end

  # [[ CACHE events ]]
  def handle_event([:dns, :cache, :hit], _metrics, meta, _config) do
    id = format_id(meta.ctx)
    rrs = Enum.map(meta.rrs, fn rr -> "#{rr}" end) |> Enum.join(", ")
    Logger.info("#{id} from cache: [#{rrs}]")
  end

  # catch all
  def handle_event(event, metrics, meta, _config) do
    Logger.info(
      "** UNKNOWN QUERY EVENT ** #{inspect(event)} #{inspect(metrics)} #{inspect(meta)}"
    )
  end

  # [[ HELPERS ]]
  defp format_id(ctx),
    do: "qry: #{ctx.qid}-#{ctx.qnr} (#{ctx.name}/#{ctx.class}/#{ctx.type})"

  defp format_resp({:error, {reason, msg}}),
    do: "ERROR #{reason} #{inspect(msg)}"

  defp format_resp({:ok, %DNS.Msg{} = msg}) do
    rcode = DNS.xrcode(msg)
    qtn = format_qtn(msg)
    "#{rcode} #{qtn}"
  end

  defp format_qtn(%DNS.Msg{question: qtns, header: hdr}) do
    qtn =
      Enum.map(qtns, fn rr -> "#{rr.name}/#{rr.class}/#{rr.type}" end)
      |> Enum.join(",")

    flags =
      for key <- [:opcode, :rcode, :cd, :rd, :ra] do
        "#{key}: #{Map.get(hdr, key)}"
      end
      |> Enum.join(", ")

    "[#{qtn}] #{flags}"
  end

  defp format_rrs(rrs) do
    Enum.map(rrs, fn rr -> "#{rr.name}/#{rr.class}/#{rr.type}: #{inspect(rr.rdmap)}" end)
    |> Enum.join(", ")
  end
end
