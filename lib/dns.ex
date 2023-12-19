defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  alias DNS.Msg

  # [[ TODO ]]
  # https://www.rfc-editor.org/rfc/rfc1034#section-5
  # https://www.rfc-editor.org/rfc/rfc1035#section-7
  # - udp & fallback to tcp
  # - do iterative queries, unless required to do rd=1 to specific nameserver
  # - handle timeout and multiple nameservers
  # Notes
  # - public-dns.info has lists of public nameservers
  # - when asking for google.nl & google.com in 1 query, some servers:
  #   - timeout (simply donot respond it seems)
  #   - respond with FORMERR
  #   - answer only the first question (e.g. 8.8.8.8 or 9.9.9.9)
  #   - answer both! (e.g. 46.166.189.67)

  # [[ RESOLVE ]]

  @doc """
  Queries DNS for given `name` and `type`, returns `t:DNS.Msg.t/0`

  Options include:
  - `rd`, defaults to 1 (recursion desired, true)
  - `id`, defaults to 0 (used to link replies to requests)
  - `opcode`, defaults to 0
  - `bufsize`, defaults to 1410 if edns0 is used
  - `do`, defaults to 0 (dnssec ok, false)
  - `cd`, defaults to 0 (dnssec check disable, fals)
  - `nameserver`, defaults to `{{8,8,8,8}, 53}`

  If any of the `bufsize, do or cd` options is used, a pseudo-RR
  is added to the additonal section of the `Msg`.


  """
  @spec resolve(binary, atom) :: {:ok, Msg.t()} | {:error, any}
  def resolve(name, type, opts \\ []) do
    opts = Keyword.put_new(opts, :id, Enum.random(0..65535))
    {edns_opts, opts} = Keyword.split(opts, [:bufsize, :do])
    {hdr_opts, opts} = Keyword.split(opts, [:rd, :id, :opcode, :cd])
    # only one question
    qtn_opts = [[name: name, type: type]]
    edns_opts = if edns_opts == [], do: [], else: [Keyword.put(edns_opts, :type, :OPT)]

    qry =
      Msg.new(qtn: qtn_opts, hdr: hdr_opts, add: edns_opts)
      |> Msg.encode()
      |> IO.inspect(label: :query)

    {rcode, rsp} =
      udp_query(qry.wdata, opts)
      |> case do
        {:error, reason} -> {:error, reason}
        response -> decode_response(response)
      end

    case rcode do
      :NOERROR -> validate(qry, rsp)
      other -> {other, rsp}
    end
  end

  defp decode_response(wdata) do
    # decode wdata, calculate rcode (no TSIG's yet)
    rsp = Msg.decode(wdata)

    xrcode =
      Enum.find(rsp.additional, %{}, fn rr -> rr.type == :OPT end)
      |> Map.get(:rdmap, %{})
      |> Map.get(:xrcode, :NOERROR)
      |> Msg.Terms.encode_dns_rcode()

    rcode =
      (16 * xrcode + DNS.Msg.Terms.encode_dns_rcode(rsp.header.rcode))
      |> Msg.Terms.decode_dns_rcode()

    {rcode, rsp}
  end

  defp validate(qry, rsp) do
    # https://github.com/erlang/otp/blob/master/lib/kernel/src/inet_res.erl#L1093C5-L1093C5
    # https://github.com/erlang/otp/blob/master/lib/kernel/src/inet_res.erl#L1131
    # erlang's inet_res checks:
    # - that header fields id, opcode and rd are the same
    # - that header qr == 1
    # - rr TYPE, CLASS and dname correspond with the question asked
    [rq] = rsp.question

    with true <- qry.header.id == rsp.header.id,
         1 <- rsp.header.qr,
         true <- Enum.all?(rsp.answer, fn rr -> validate_rsp_rr(rr, rq) end) do
      {:ok, rsp}
    else
      _ -> {:error, {:bad_response, rsp}}
    end
  end

  defp validate_rsp_rr(rr, rq) do
    # todo:
    # - case-insensitive compare of names
    # - are there more DNSSEC related RR's that might show up in answer RR's?
    rr.name == rq.name and
      rr.class == rq.class and
      (rr.type == rq.type or rr.type in [:RRSIG])
  end

  # [[ SEND/RECV MSG ]]

  def udp_query(msg, opts \\ []) do
    nameserver = Keyword.get(opts, :nameserver, {{8, 8, 8, 8}, 53})
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, recbuf: 4000])
    :ok = :gen_udp.send(sock, nameserver, msg)

    timeout_ms = 3000
    time_sent = System.monotonic_time(:millisecond)

    case :gen_udp.recv(sock, 0, timeout_ms) do
      {:ok, {address, port, response}} ->
        duration = System.monotonic_time(:millisecond) - time_sent
        IO.puts("#{inspect(address)}:#{port} replied, took #{duration} ms")
        response

      {:error, reason} ->
        {:error, reason}
    end
  end
end
