defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  @root_nss File.read!("priv/named.root.rrs")
            |> :erlang.binary_to_term()
            |> Enum.map(fn rr -> {Pfx.to_tuple(rr.rdmap.ip, mask: false), 53} end)

  alias DNS.Msg
  import DNS.Msg.Terms
  import DNS.Utils

  # [[ TODO ]]
  # https://www.rfc-editor.org/rfc/rfc1034#section-5
  # https://www.rfc-editor.org/rfc/rfc1035#section-7
  # - udp & fallback to tcp
  # - do iterative queries, unless required to do rd=0 to specific nameserver
  # - handle timeout and multiple nameservers
  # Notes
  # - public-dns.info has lists of public nameservers
  # - question section SHOULD contain only 1 question
  # - A resolver MUST:
  #   a. Ignore non-authoritative answers
  #      - accept only answers to the question asked (ID, name, rrtype=as-asked or in DNSSEC)
  #      - exception is glue records from parent zone
  #   b. check that:
  #      - IP src and Port are correct (IP stack does that)
  #      - DNS ID field is correct
  #   c. make cache poisining harder:
  #      - randomize src Port
  #      - randomize ID field
  #   d. use DNSSEC validation to be safe from on-path villains
  #   e. handle loops (NS, DS, CNAME, NAPTR, loops etc)

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
  is added to the additional section of the `Msg`.

  """
  @spec resolve(binary, atom) :: {:ok, Msg.t()} | {:error, any}
  def resolve(name, type, opts \\ []) do
    # TODO: move all this option splitting to Msg.new()
    opts = Keyword.put_new(opts, :id, Enum.random(0..65535))
    {edns_opts, opts} = Keyword.split(opts, [:bufsize, :do])
    {hdr_opts, opts} = Keyword.split(opts, [:rd, :id, :opcode, :cd])
    # only one question
    qtn_opts = [[name: name, type: type]]
    edns_opts = if edns_opts == [], do: [], else: [Keyword.put(edns_opts, :type, :OPT)]

    qry =
      Msg.new!(qtn: qtn_opts, hdr: hdr_opts, add: edns_opts)
      |> Msg.encode()
      |> IO.inspect(label: :query)

    {rcode, rsp} =
      case udp_query(qry.wdata, opts) do
        {:error, reason} -> {:error, reason}
        response -> decode_response(response)
      end

    case rcode do
      :NOERROR -> validate(qry, rsp)
      other -> {other, rsp}
    end
  end

  # [[ BUILD QUERY ]]

  def make_query(name, type, opts \\ []) do
    with true <- dname_valid?(name),
         true <- encode_rr_type(type) |> is_u16() do
      log(opts.verbose, "hi there!")
    end
  end

  # [[ SEND/RECV MSG ]]

  def udp_query(msg, opts \\ []) do
    nameserver = Keyword.get(opts, :nameserver, {{8, 8, 8, 8}, 53})
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, recbuf: 4000])
    :ok = :gen_udp.send(sock, nameserver, msg)

    timeout_ms = 3000
    time_sent = now(:millisecond)

    case :gen_udp.recv(sock, 0, timeout_ms) do
      {:ok, {address, port, response}} ->
        duration = now(:millisecond) - time_sent
        IO.puts("#{inspect(address)}:#{port} replied, took #{duration} ms")
        response

      {:error, reason} ->
        {:error, reason}
    end
  end

  def tcp_query(_msg, _opts) do
    # TODO
    {:error, :notimp}
  end

  # [[ OPTIONS ]]

  def make_options(opts \\ []) do
    edns = opts[:do] == 1 or opts[:cd] == 1 or Keyword.has_key?(opts, :bufsize)

    opts2 = %{
      nameservers: Keyword.get(opts, :nameservers, @root_nss),
      srvfail_wait: Keyword.get(opts, :srvfail_wait, 1500),
      verbose: Keyword.get(opts, :verbose, false),
      bufsize: Keyword.get(opts, :bufsize, 1280),
      timeout: Keyword.get(opts, :timeout, 2000),
      retry: Keyword.get(opts, :retry, 3),
      tcp: Keyword.get(opts, :tcp, false),
      do: Keyword.get(opts, :do, 0),
      rd: Keyword.get(opts, :rd, 0),
      cd: Keyword.get(opts, :cd, 0)
    }

    with {:nss, true} <- {:nss, check_nss(opts2.nameservers)},
         {:srv, true} <- {:srv, opts2.srvfail_wait in 0..5000},
         {:vrb, true} <- {:vrb, is_boolean(opts2.verbose)},
         {:bfs, true} <- {:bfs, is_u16(opts2.bufsize)},
         {:tmo, true} <- {:tmo, opts2.timeout in 0..5000},
         {:ret, true} <- {:ret, opts2.retry in 0..5},
         {:tcp, true} <- {:tcp, is_boolean(opts2.tcp)},
         {:do, true} <- {:do, opts2.do in 0..1},
         {:rd, true} <- {:rd, opts2.rd in 0..1},
         {:cd, true} <- {:cd, opts2.cd in 0..1} do
      {:ok, Map.put(opts2, :edns, edns)}
    else
      {:nss, _} -> {:error, "bad nameserver(s) #{inspect(opts2.nameservers)}"}
      {:srv, _} -> {:error, "srvfail_wait not in range 0..5000"}
      {:vrb, _} -> {:error, "verbose should be true or false"}
      {:bfs, _} -> {:error, "bufsize out of u16 range"}
      {:tmo, _} -> {:error, "timeout not in range 0..5000"}
      {:ret, _} -> {:error, "retry not in range 0..5"}
      {:tcp, _} -> {:error, "tcp should be either true or false"}
      {:do, _} -> {:error, "do bit should be either 0 or 1"}
      {:rd, _} -> {:error, "rd bit should be either 0 or 1"}
      {:cd, _} -> {:error, "cd bit should be either 0 or 1"}
    end
  end

  defp check_nss([]),
    do: true

  defp check_nss([{ip, port} | nss]) do
    if Pfx.valid?(ip) and is_tuple(ip) and is_u16(port),
      do: check_nss(nss),
      else: false
  end

  # [[ HELPERS ]]

  defp decode_response(wdata) do
    # decode wdata, calculate rcode (no TSIG's yet)
    rsp = Msg.decode(wdata)

    # TODO: move this to DNS.Msg en/decode ..
    # if rcode > 16, then update the EDNS RR (or add one if missing)
    # update docu to reflect that the rcode is the extended rcode
    # when encoding: <<132::4>> still only encodes lowest 4 bits
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

  defp log(false, _),
    do: :ok

  defp log(true, msg),
    do: IO.puts(msg)

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

  # wait for given timeout (in ms)
  defp wait(timeout) do
    # this won't match any messages!
    receive do
    after
      timeout -> :ok
    end
  end
end
