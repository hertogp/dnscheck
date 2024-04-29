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

  def attach_default_logger() do
    :telemetry.attach_many(
      "dnscheck-default-logger",
      [
        [:dns, :query, :start],
        [:dns, :query, :stop],
        [:dns, :query, :exception]
      ],
      &DNS.Telemetry.handle_event/4,
      nil
    )
  end

  def handle_event([:dns, :query, event], metrics, meta, _config) do
    qid = meta.ctx.qid
    qnr = meta.ctx.qnr

    case event do
      :start ->
        nil

      :stop ->
        ms = System.convert_time_unit(metrics.duration, :native, :millisecond)
        Logger.info("#{qid}-#{qnr} #{ms} ms, #{inspect(meta)}")

      :exception ->
        Logger.error("#{qid}-#{qnr} #{inspect(meta)}")
    end
  end

  # catch all (remaining) events
  def handle_event(event, metrics, meta, _config) do
    Logger.info("[....] #{inspect(event)} #{inspect(metrics)} #{inspect(meta)}")
  end
end
