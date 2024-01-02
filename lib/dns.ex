defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  # TODO:
  # - change iana.update hints -> store hints as [{:inet.ip_address, 53}], and
  # - use Code.eval_file("priv/root.nss") here
  # that way, the priv/root.nss file is actually readable
  @root_nss File.read!("priv/named.root.rrs")
            |> :erlang.binary_to_term()
            |> Enum.map(fn rr -> {Pfx.to_tuple(rr.rdmap.ip, mask: false), 53} end)

  alias DNS.Msg
  # import DNS.Msg.Terms
  import DNS.Utils
  # import DNS.Msg.Terms
  alias DNS.Cache

  @typedoc "Type of RR, as atom or non negative integer"
  @type type :: atom | non_neg_integer
  @typedoc "Nameserver is tuple of IPv4/6 address and port number"
  @type ns :: {:inet.ip_address(), non_neg_integer}
  @typedoc "A struct representing a nameserver message"
  @type msg :: DNS.Msg.t()

  # [[ NOTES ]]
  # https://www.rfc-editor.org/rfc/rfc1034#section-5
  # https://www.rfc-editor.org/rfc/rfc1035#section-7
  # - udp & fallback to tcp
  # - do iterative queries, unless user specifies its own nameserver
  # - handle timeout and multiple nameservers
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
  @spec resolve(binary, type, Keyword.t()) :: {:ok, msg} | {:error, any}
  def resolve(name, type, opts \\ []) do
    # TODO:
    # [ ] consult the cache and if possible, synthesize the answer
    # [ ] optimize by replacing root nss with ones closer to the QNAME
    #     e.g. so we don't have to recurse all the way from root again
    Cache.init(clear: false)

    with {:ok, opts} <- make_options(opts),
         {:ok, qry} <- make_query(name, type, opts),
         tstop <- time(opts.maxtime),
         nss <- opts.nameservers,
         {:ok, msg} <- query_nss(nss, qry, opts, tstop, 0, _failed = []),
         xrcode <- xrcode(msg),
         anc = msg.header.anc,
         nsc = msg.header.nsc,
         arc = msg.header.arc do
      log(true, "got a reply: #{xrcode}, #{anc} answers, #{nsc} authority, #{arc} additional")

      # TODO:
      # - since res_recurse may call resolve, we need to add seen to resolve
      # func signature in order to always be able to detect loops?
      if anc == 0 and opts.recurse and nsc > 0 and :NOERROR == xrcode,
        do: res_recurse(qry, msg, opts, tstop, %{}),
        else: {:ok, msg}
    else
      e -> e
    end
  end

  def res_recurse(qry, msg, opts, tstop, seen) do
    # https://www.rfc-editor.org/rfc/rfc1035#section-7     - resolver implementation
    # https://www.rfc-editor.org/rfc/rfc1035#section-7.4   - using the cache
    # https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2 - handle CNAMEs
    # https://datatracker.ietf.org/doc/html/rfc1123#section-6
    # TODO
    # [ ] if qname is ip address, convert it to reverse ptr name
    # [ ] query for NS names in aut section (ex. tourdewadden.nl)
    # [x] detect NS loops
    # [ ] detect CNAME loops

    log(true, "recursing for #{hd(msg.question)}")
    log(true, "recursing cache size is #{Cache.size()}")
    Cache.put(msg)

    # always move forward, never cirle back hence filtering seen
    nss =
      msg.authority
      |> Enum.filter(fn rr -> rr.type == :NS end)
      |> Enum.map(fn rr -> rr.rdmap.name end)
      |> res_recurse_nss()
      |> Enum.filter(fn ns -> not Map.has_key?(seen, ns) end)

    # keep track of where we've been
    seen = Enum.reduce(nss, seen, fn ns, acc -> Map.put(acc, ns, []) end)

    # TODO: report an error when all ns were seen before
    log(true, "recursing with nss: #{inspect(nss)}")

    with {:ok, msg} <- query_nss(nss, qry, opts, tstop, 0, []),
         xrcode <- xrcode(msg),
         anc <- msg.header.anc,
         nsc <- msg.header.nsc do
      case xrcode do
        :NOERROR when anc == 0 and nsc > 0 -> res_recurse(qry, msg, opts, tstop, seen)
        :NOERROR when anc > 0 -> {:ok, msg}
        other -> {:error, {other, msg}}
      end
    else
      {:error, reason} -> {:error, {reason, msg}}
      other -> {:error, other}
    end
  end

  @spec res_recurse_nss([binary]) :: [{:inet.ip_address(), integer}]
  def res_recurse_nss(nsnames) do
    nss =
      for ns <- nsnames, type <- [:A, :AAAA] do
        Cache.get(ns, :IN, type)
      end
      |> List.flatten()

    old =
      nss
      |> Enum.map(fn rr -> rr.name end)
      |> Enum.map(fn name -> dname_normalize(name) |> elem(1) end)
      |> Enum.filter(fn n -> not is_atom(n) end)

    new =
      nsnames
      |> Enum.map(fn name -> dname_normalize(name) |> elem(1) end)
      |> Enum.filter(fn name -> name not in old end)
      |> Enum.filter(fn n -> not is_atom(n) end)

    for ns <- new, type <- [:A, :AAAA] do
      case resolve(ns, type) do
        {:ok, msg} -> msg.answer
        _ -> []
      end
    end
    |> List.flatten()
    |> Enum.concat(nss)
    |> Enum.map(fn rr -> rr.rdmap.ip end)
    |> Enum.map(fn ip -> {Pfx.to_tuple(ip, mask: false), 53} end)

    # Process.exit(self(), :abort)
  end

  @spec query_nss([ns], DNS.Msg.t(), map, integer, non_neg_integer, [ns]) ::
          {:ok, DNS.Msg.t()} | {:error, any}
  def query_nss([] = _nss, _qry, _opts, _tstop, _nth, [] = _failed),
    do: {:error, :nxdomain}

  def query_nss([] = _nss, qry, opts, tstop, nth, failed),
    do: query_nss(Enum.reverse(failed), qry, opts, tstop, nth + 1, [])

  def query_nss([ns | nss], qry, opts, tstop, nth, failed) do
    cond do
      timeout(tstop) == 0 ->
        {:error, :timeout}

      opts.retry < nth ->
        {:error, :timeout}

      true ->
        ns = unwrap(ns)

        case query_ns(ns, qry, opts, tstop, nth) do
          {:error, :servfail} ->
            log(opts.verbose, "pushing #{inspect(ns)} onto failed list (:servfail)")
            query_nss(nss, qry, opts, tstop, nth, [wrap(ns, opts.srvfail_wait) | failed])

          {:error, :timeout} ->
            log(opts.verbose, "pushing #{inspect(ns)} onto failed list (:timeout)")
            query_nss(nss, qry, opts, tstop, nth, [wrap(ns, opts.srvfail_wait) | failed])

          {:error, error} ->
            log(opts.verbose, "dropping #{inspect(ns)}, due to error: #{inspect(error)}")
            query_nss(nss, qry, opts, tstop, nth, failed)

          {:ok, rsp} ->
            {:ok, rsp}
        end
    end
  end

  @spec query_ns(ns, DNS.Msg.t(), map, integer, non_neg_integer) ::
          {:ok, DNS.Msg.t()} | {:error, any}
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

      case query_udp(ns, qry, udp_timeout, bufsize) do
        {:ok, rsp} when rsp.header.tc == 1 -> query_tcp(ns, qry, timeout, tstop)
        result -> result
      end
    end
  end

  @spec query_udp(ns, DNS.Msg.t(), non_neg_integer, non_neg_integer) ::
          {:ok, DNS.Msg.t()} | {:error, any}
  def query_udp(_ns, _qry, 0, _bufsize),
    do: {:error, :timeout}

  def query_udp({ip, port}, qry, timeout, bufsize) do
    # query_udp_open checks ip/port so we don't exit with :badarg
    # query_udp_recv polls until timeout has passed

    {:ok, sock} = query_udp_open(ip, port, bufsize)

    with :ok <- :gen_udp.connect(sock, ip, port),
         :ok <- :gen_udp.send(sock, qry.wdata),
         {:ok, msg} <- query_udp_recv(sock, qry, timeout) do
      # :inet.getstat(sock, [:recv_cnt, :recv_oct])
      # |> IO.inspect(label: :getstat)

      :gen_udp.close(sock)
      {:ok, msg}
    else
      error ->
        :gen_udp.close(sock)
        log(true, "udp socket error #{inspect(ip)}, #{inspect(error)}")
        error
    end
  rescue
    # when query_udp_open returns {:error, :socket}
    e in MatchError -> e.term
  end

  @spec query_udp_open(:inet.ip_address(), non_neg_integer, non_neg_integer) ::
          {:ok, :gen_udp.socket()} | {:error, any}
  def query_udp_open(ip, port, bufsize) do
    # avoid exit :badarg from gen_udp.open
    iptype =
      case Pfx.type(ip) do
        :ip4 -> :inet
        :ip6 -> :inet6
      end

    with true <- is_u16(port),
         true <- iptype in [:inet, :inet6] do
      opts = [:binary, iptype, active: false, recbuf: bufsize]
      :gen_udp.open(0, opts)
    else
      false -> {:error, :badarg}
    end
  end

  @spec query_udp_recv(:inet.socket(), DNS.Msg.t(), non_neg_integer) ::
          {:ok, DNS.Msg.t()} | {:error, any}
  def query_udp_recv(_sock, _qry, 0),
    do: {:error, :timeout}

  def query_udp_recv(sock, qry, timeout) do
    # gen_udp.recv -> {:ok, dta} | {:error, posix | not_owner | timeout}
    # - checks that header qry/rsp id's match and it's actually a reply msg
    # - keeps trying until timeout has passed
    # - sock is connected, so addr,port *should* be ok
    {:ok, {ip, p}} = :inet.peername(sock)
    log(true, "trying #{Pfx.new(ip)}:#{p}/udp, timeout #{timeout} ms")
    tstart = now()
    tstop = time(timeout)

    with {:ok, {addr, port, rsp}} <- :gen_udp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- msg.header.id == qry.header.id,
         true <- msg.header.qr == 1 do
      t = now() - tstart
      b = byte_size(msg.wdata)
      log(true, "recv'd #{b} bytes in #{t} ms, from #{Pfx.new(addr)}:#{port}/udp")

      {:ok, msg}
    else
      false -> query_udp_recv(sock, qry, timeout(tstop))
      other -> other
    end
  end

  @spec query_tcp(ns, DNS.Msg.t(), non_neg_integer, non_neg_integer) ::
          {:ok, DNS.Msg.t()} | {:error, any}
  def query_tcp(_ns, _qry, 0, _tstop),
    do: {:error, :timeout}

  def query_tcp({ip, port}, qry, timeout, tstop) do
    # :gen_tcp.connect -> {:ok, sock} | {:error, :timeout | posix}
    # connect outside with block, so we can always close the socket
    {:ok, sock} = query_tcp_connect(ip, port, timeout, tstop)
    t0 = now()

    with :ok <- :gen_tcp.send(sock, qry.wdata),
         {:ok, rsp} <- :gen_tcp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- msg.header.id == qry.header.id,
         true <- msg.header.qr == 1 do
      :gen_tcp.close(sock)
      t = now() - t0
      log(true, "recv'd #{byte_size(rsp)} bytes from #{Pfx.new(ip)}:#{port}/tcp in #{t} ms")
      {:ok, msg}
    else
      false ->
        {:error, :noreply}

      {:error, e} ->
        log(true, "query_tcp error #{inspect(e)}")
        :gen_tcp.close(sock)
        {:error, e}
    end
  rescue
    # when query_tcp_connect returns {:error, any}
    e in MatchError -> e.term
  end

  @spec query_tcp_connect(:inet.ip_address(), non_neg_integer, non_neg_integer, integer) ::
          {:ok, :inet.socket()} | {:error, any}
  def query_tcp_connect(ip, port, timeout, tstop) do
    # avoid exit badarg by checking ip/port's validity
    log(true, "query tcp: #{inspect(ip)}, #{port}/tcp, timeout #{timeout}")

    iptype =
      case Pfx.type(ip) do
        :ip4 -> :inet
        :ip6 -> :inet6
      end

    tcp_timeout = min(timeout, timeout(tstop))

    with true <- is_u16(port),
         true <- iptype in [:inet, :inet6] do
      opts = [:binary, iptype, active: false, packet: 2]
      :gen_tcp.connect(ip, port, opts, tcp_timeout)
    else
      false -> {:error, :badarg}
    end
  end

  # [[ MAKE QRY/RSP MSG ]]

  @spec make_query(binary, atom | non_neg_integer, map) :: {:ok, DNS.Msg.t()} | {:error, any}
  def make_query(name, type, opts) do
    # assumes opts is safe (made by make_options)

    name =
      if Pfx.valid?(name) do
        Pfx.dns_ptr(name)
      else
        with {:ok, name} <- dname_normalize(name) do
          name
        else
          _ -> name
        end
      end

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
    # cd is hdr option, not edns option
    edns = opts[:do] == 1 or opts[:bufsize] != nil
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

  defp xrcode(msg) do
    # calculate rcode (no TSIG's yet)

    xrcode =
      Enum.find(msg.additional, %{}, fn rr -> rr.type == :OPT end)
      |> Map.get(:rdmap, %{})
      |> Map.get(:xrcode, :NOERROR)
      |> Msg.Terms.encode_dns_rcode()

    rcode =
      (16 * xrcode + DNS.Msg.Terms.encode_dns_rcode(msg.header.rcode))
      |> Msg.Terms.decode_dns_rcode()

    rcode
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
      (rr.type == rq.type or rr.type in [:DS, :RRSIG])
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
