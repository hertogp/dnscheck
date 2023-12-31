defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  @root_nss File.read!("priv/named.root.rrs")
            |> :erlang.binary_to_term()
            |> Enum.map(fn rr -> {Pfx.to_tuple(rr.rdmap.ip, mask: false), 53} end)

  alias DNS.Msg
  # import DNS.Msg.Terms
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
  - `nameservers`, defaults to root nameservers

  If any of the `bufsize, do or cd` options is used, a pseudo-RR
  is added to the additional section of the `Msg`.

  """
  @spec resolve(binary, atom | non_neg_integer, Keyword.t()) :: {:ok, DNS.Msg.t()} | {:error, any}
  def resolve(name, type, opts \\ []) do
    with {:ok, opts} <- make_options(opts),
         {:ok, qry} <- make_query(name, type, opts) do
      tstop = time(opts.maxtime)
      nss = opts.nameservers
      query_nss(nss, qry, opts, tstop, 0, _failed = [])
    else
      e -> e
    end
  end

  def query_nss([] = _nss, _qry, _opts, _tstop, _n, [] = _failed),
    do: {:error, :noservers}

  def query_nss([] = _nss, qry, opts, tstop, n, failed),
    do: query_nss(Enum.reverse(failed), qry, opts, tstop, n + 1, [])

  def query_nss([ns | nss], qry, opts, tstop, n, failed) do
    cond do
      timeout(tstop) == 0 ->
        {:error, "no more time"}

      opts.retry < n ->
        {:error, "no more retries"}

      true ->
        ns = unwrap(ns)

        case query_ns(ns, qry, opts, tstop, n) do
          {:error, :servfail} ->
            log(opts.verbose, "pushing #{inspect(ns)} onto failed list (:servfail)")
            query_nss(nss, qry, opts, tstop, n, [wrap(ns, opts.srvfail_wait) | failed])

          {:error, :timeout} ->
            log(opts.verbose, "pushing #{inspect(ns)} onto failed list (:timeout)")
            query_nss(nss, qry, opts, tstop, n, [wrap(ns, opts.srvfail_wait) | failed])

          {:error, error} ->
            log(opts.verbose, "dropping #{inspect(ns)}, due to error: #{inspect(error)}")
            query_nss(nss, qry, opts, tstop, n, failed)

          {:ok, rsp} ->
            {:ok, rsp}
        end
    end
  end

  def query_ns(ns, qry, opts, tstop, n) do
    # queries a single nameserver, returns {:ok, msg} | {:error, reason}
    # - servfail or timeout -> ns will be tried later again
    # - any other error -> ns is dropped and not visited again
    bufsize = opts.bufsize
    timeout = opts.timeout
    payload = byte_size(qry.wdata)

    if payload > bufsize or opts.tcp do
      query_tcp(ns, qry, timeout, tstop)
    else
      udp_timeout = udp_timeout(timeout, opts.retry, n, tstop)
      log(true, "udp: t0 is #{udp_timeout}, t1 is #{timeout(tstop)}")

      case query_udp(ns, qry, udp_timeout, bufsize) do
        {:ok, rsp} when rsp.header.tc == 1 -> query_tcp(ns, qry, timeout, tstop)
        result -> result
      end
    end
  end

  def query_udp(_ns, _qry, 0, _bufsize),
    do: {:error, :timeout}

  def query_udp({ip, port}, qry, timeout, bufsize) do
    log(true, "udp: t0 #{inspect(timeout)}")

    iptype =
      case Pfx.type(ip) do
        :ip4 -> :inet
        :ip6 -> :inet6
        _ -> :einvalid
      end

    # gen_udp:
    # - open -> {:ok, socket} | {:error, posix | :system_limit}
    # - connect -> :ok, {:error, reason}
    # - send -> :ok | {:error, posix | not_owner}
    # - recv -> {:ok, dta} | {:error, posix | not_owner | timeout}
    # Msg.decode -> {:ok, Msg.t} | {:error, DNS.MsgError.t}
    # TODO
    # - query_udp_recv to poll, with limit, the socket for correct answer
    # - query_udp_connect -> only receive replies from 'connected' ns

    opts = [:binary, iptype, active: false, recbuf: bufsize]

    {:ok, sock} = :gen_udp.open(0, opts)

    with :ok <- :gen_udp.connect(sock, ip, port),
         :ok <- :gen_udp.send(sock, qry.wdata),
         tsent <- now(),
         {:ok, {addr, port, rsp}} <- :gen_udp.recv(sock, 0, timeout) do
      :gen_udp.close(sock)
      duration = now() - tsent
      log(true, "#{inspect(addr)}, port #{port}/udp replied, took #{duration} ms")
      Msg.decode(rsp)
    else
      {:error, %DNS.MsgError{} = e} ->
        :gen_udp.close(sock)
        log(true, "error decoding response from #{inspect(ip)}")
        {:error, e.data}

      other ->
        :gen_udp.close(sock)
        log(true, "udp server error #{inspect(ip)}, #{inspect(other)}")
        other
    end
  rescue
    # :gen_udp.open may return {:error, reason} instead of {:ok, sock}
    e in MatchError -> e.term
  end

  def query_tcp(_ns, _qry, 0),
    do: {:error, :timeout}

  def query_tcp({ip, port}, qry, timeout, tstop) do
    # port = port + 1
    tcp_timeout = min(timeout, timeout(tstop))

    iptype =
      case Pfx.type(ip) do
        :ip4 -> :inet
        :ip6 -> :inet6
      end

    opts = [:binary, iptype, active: false, packet: 2]

    # :gen_tcp.connect -> {:ok, sock} | {:error, :timeout | posix}
    # connect outside with block, so we can always close the socket
    {:ok, sock} = :gen_tcp.connect(ip, port, opts, tcp_timeout)

    with :ok <- :gen_tcp.send(sock, qry.wdata),
         {:ok, rsp} <- :gen_tcp.recv(sock, 0, timeout) do
      :gen_tcp.close(sock)
      log(true, "query_tcp received #{byte_size(rsp)} bytes")
      Msg.decode(rsp)
    else
      {:error, e} ->
        log(true, "query_tcp error #{inspect(e)}")
        :gen_tcp.close(sock)
        {:error, e}
    end
  rescue
    # when gen_tcp.connect fails, {:ok, sock} won't match {:error, reason}
    e in MatchError -> e.term
  end

  # [[ MAKE QRY MSG ]]

  @spec make_query(binary, atom | non_neg_integer, map) :: {:ok, DNS.Msg.t()} | {:error, any}
  def make_query(name, type, opts) do
    # assumes opts is safe (made by make_options)

    edns_opts =
      if opts.edns,
        do: [[bufsize: opts.bufsize, do: opts.do, type: :OPT]],
        else: []

    qtn_opts = [[name: name, type: type]]
    hdr_opts = [rd: opts.rd, cd: opts.cd, id: Enum.random(0..65535)]

    case Msg.new(hdr: hdr_opts, qtn: qtn_opts, add: edns_opts) do
      {:ok, qry} -> Msg.encode(qry)
      {:error, e} -> {:error, e.data}
    end
  end

  # [[ OPTIONS ]]

  @spec make_options(Keyword.t()) :: {:ok, map} | {:error, binary}
  def make_options(opts \\ []) do
    edns = opts[:do] == 1 or opts[:cd] == 1 or opts[:bufsize] != nil
    recurse = opts[:nameservers] == nil

    opts2 = %{
      nameservers: Keyword.get(opts, :nameservers, @root_nss),
      srvfail_wait: Keyword.get(opts, :srvfail_wait, 1500),
      verbose: Keyword.get(opts, :verbose, false),
      bufsize: Keyword.get(opts, :bufsize, 1280),
      timeout: Keyword.get(opts, :timeout, 2000),
      maxtime: Keyword.get(opts, :maxtime, 20_000),
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
         {:mxt, true} <- {:mxt, is_integer(opts2.maxtime) and opts2.maxtime > 0},
         {:ret, true} <- {:ret, opts2.retry in 0..5},
         {:tcp, true} <- {:tcp, is_boolean(opts2.tcp)},
         {:do, true} <- {:do, opts2.do in 0..1},
         {:rd, true} <- {:rd, opts2.rd in 0..1},
         {:cd, true} <- {:cd, opts2.cd in 0..1} do
      {:ok, Map.put(opts2, :edns, edns) |> Map.put(:recurse, recurse)}
    else
      {:nss, _} -> {:error, "bad nameserver(s) #{inspect(opts2.nameservers)}"}
      {:srv, _} -> {:error, "srvfail_wait not in range 0..5000"}
      {:vrb, _} -> {:error, "verbose should be true or false"}
      {:bfs, _} -> {:error, "bufsize out of u16 range"}
      {:tmo, _} -> {:error, "timeout not in range 0..5000"}
      {:mxt, _} -> {:error, "max time not non_neg_integer"}
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
    # - when rr.type is ANY what do we accept then?
    dname_equal?(rr.name, rq.name) and
      rr.class == rq.class and
      (rr.type == rq.type or rr.type in [:RRSIG])
  end

  # wrap a nameserver with an absolute point in time,
  # later on, when revisiting, we'll wait the remaining time
  defp wrap(ns, timeout),
    do: {ns, time(timeout)}

  defp unwrap({{_ip, _port} = ns, t}) do
    wait(timeout(t))
    ns
  end

  defp unwrap(ns),
    do: ns

  defp udp_timeout(timeout, retry, n, tstop) do
    tdelta = div(timeout * 2 ** n, retry)

    tdelta
    |> time()
    |> timeout(tstop)
    |> min(tdelta)
  end
end
