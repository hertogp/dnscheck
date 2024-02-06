defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  import DNS.Utils
  alias DNS.Msg
  alias DNS.Cache
  alias DNS.Msg.Terms
  alias Logger, as: Log
  require Logger

  @typedoc "Type of RR, as atom or non negative integer"
  @type type :: atom | non_neg_integer
  @typedoc "Nameserver is tuple of IPv4/6 address-tuple and port number"
  @type ns :: {:inet.ip_address(), non_neg_integer}
  @typedoc "A struct representing a nameserver message"
  @type msg :: DNS.Msg.t()
  @typedoc "Reasons why resolving may fail"
  @type reason ::
          :timeout
          | :servfail
          | DNS.MsgError.t()
          | :inet.posix()
          | :badarg
          | :system_limit
          | :not_owner
  @typedoc "A counter is shorthand for non negative integer"
  @type counter :: non_neg_integer
  @typedoc "timeT is a, possibly future, absolute point in monolithic time"
  @type timeT :: integer

  # [[ LINKS ]]
  # https://www.rfc-editor.org/rfc/rfc1034#section-5
  # https://www.rfc-editor.org/rfc/rfc1035#section-7
  # https://public-dns.info/  (lists of public dns servers)

  # [[ RESOLVE ]]

  @doc """
  Queries DNS for given `name` and `type`, returns either {:ok, `t:DNS.Msg.t/0`}
  or `{:error, {reason, desc}}`.

  TODO:
  [ ] error returns are always {:error, {:some_reason, desc}}
      where desc can be a binary of DNS.Msg (e.g. when rcode = NXDOMAIN)
      or when :some_reason is :lame or :bogus, :cname_loop, :referral_loop etc..
  [ ] ensure @spec is modified accordingly, e.g. define reason as series of tuples:
      @type reason ::
      {:timeout, desc}
      {:servfail, desc}
      {:nxdomain, DNS.Msg.t()}
      {:lame, DNS.Msg.t()}
      {:cname_loop, DNS.Msg.t()}
      {:referral_loop, DNS.Msg.t()}
      ...
      {:encode, DNS.MsgError.t()}
      {:decode, DNS.MsgError.t()}
      etc ...

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
  @spec resolve(binary, type, Keyword.t()) :: {:ok, msg} | {:error, reason}
  def resolve(name, type, opts \\ []) do
    # TODO: probably move Cache.init/1 to dnscheck.ex at some point
    Cache.init(clear: false)
    recurse = opts[:nameservers] == nil
    Log.info("Start user query for #{name}, #{type}, recurse: #{recurse}.")

    ctx = %{
      bufsize: Keyword.get(opts, :bufsize, 1280),
      cd: Keyword.get(opts, :cd, 0),
      class: Keyword.get(opts, :class, :IN) |> Terms.decode_dns_class(),
      do: Keyword.get(opts, :do, 0),
      edns: opts[:do] == 1 or opts[:bufsize] != nil,
      maxtime: Keyword.get(opts, :maxtime, 5_000),
      nameservers: Keyword.get(opts, :nameservers, Cache.nss(name)),
      opcode: Keyword.get(opts, :opcode, :QUERY) |> Terms.encode_dns_opcode(),
      rd: (recurse && 0) || Keyword.get(opts, :rd, 1),
      retry: Keyword.get(opts, :retry, 3),
      srvfail_wait: Keyword.get(opts, :srvfail_wait, 1500),
      tcp: Keyword.get(opts, :tcp, false),
      timeout: Keyword.get(opts, :timeout, 2_000),
      # house keeping
      recurse: recurse,
      name: name,
      type: type,
      # referral loops are bounded by iterative query, so:
      # - is (re)set each time a new iteration starts (via resolvep)
      # - is updated by reply_handler when following referrals
      zones: [""],
      # cname loops cross the boundary of iterative queries, so:
      # - is initialized for each new caller's query
      # - is updated by reply_handler when following cname(s)
      cnames: [name]
    }

    # TODO: put limit on length of CNAME-chain, e.g. 10?
    # TODO: put limit on number of referrals to follow, e.g. 10?
    cond do
      not is_u16(ctx.bufsize) -> "bufsize out of u16 range"
      ctx.cd not in 0..1 -> "cd bit should be 0 or 1"
      ctx.class not in [:IN, :CH, :HS] -> "unknown DNS class: #{ctx.class}"
      ctx.do not in 0..1 -> "do bit should be 0 or 1"
      not is_integer(ctx.maxtime) -> "maxtime should be an integer"
      ctx.maxtime < 0 -> "maxtime should be positive integer"
      not check_nss(ctx.nameservers) -> "bad nameserver(s) #{inspect(ctx.nameservers)}"
      ctx.opcode not in 0..15 -> "opcode not in 0..15"
      ctx.rd not in 0..1 -> "rd bit should be 0 or 1"
      ctx.retry not in 0..5 -> "retry not in range 0..5"
      ctx.srvfail_wait not in 0..5000 -> "srvfail_wait not in 0..5000"
      not is_boolean(ctx.tcp) -> "tcp should be true of false"
      ctx.timeout not in 0..5000 -> "timeout not in 0..5000"
      true -> {:ok, ctx}
    end
    |> case do
      {:ok, ctx} ->
        resolvep(name, type, ctx)

      error ->
        Log.error("Option error: #{error}")
        {:error, {:option, error}}
    end
  end

  @spec resolvep(binary, type, map) :: {:ok, msg} | {:error, reason} | {:error, {atom, msg}}
  defp resolvep(name, type, ctx) do
    # resolvep called by:
    # - resolve to answer caller's query
    # - recurse_nss during referral, to resolve non-glue NS's
    # - resolve_handler, to follow cnames and/or referrals
    with {:ok, qry} <- make_query(name, type, ctx),
         qname <- hd(qry.question).name,
         cached <- Cache.get(qname, ctx.class, type) do
      Log.info("iterative mode is #{ctx.recurse}")

      case cached do
        [] ->
          nss = ctx[:nameservers] || Cache.nss(qname)
          Log.info("#{name} #{type} got #{length(nss)} nameservers")
          tstop = time(ctx.maxtime)

          case query_nss(nss, qry, ctx, tstop, 0, _failed = []) do
            {:ok, msg} ->
              xrcode = xrcode(msg)
              anc = msg.header.anc
              nsc = msg.header.nsc
              arc = msg.header.arc
              rsp_type = reply_type(msg)

              Log.info(
                "qry #{qname} #{type} -> reply (#{rsp_type}): #{xrcode}, ANSWERS #{anc}, AUTHORITY #{nsc}, ADDITIONAL #{arc}"
              )

              # try www.azure.com for a cname chain
              reply_handler(qry, msg, ctx, tstop)

            {:error, reason} ->
              {:error, reason}
          end

        rrs ->
          Log.info("using #{length(rrs)} cached RR's")
          {:ok, msg} = reply_make(qry, rrs)
          tstop = time(ctx.maxtime)
          reply_handler(qry, msg, ctx, tstop)
      end
    else
      error -> error
    end
  end

  # [[ RECURSE ]]

  @spec recurse(msg, msg, map, timeT) :: {:ok, msg} | {:error, {reason, msg}}
  defp recurse(qry, msg, ctx, tstop) do
    # only to be called by reply_handler when following referral
    # - so same qry, different nameservers due to redirection
    # - a referral does not necessarily have all addresses of the NS's it
    #   mentions in authority as glue RR's in additional available.
    #   Hence non-glue names are `resolve`d (a new, fresh iterative query,
    #   respecting overall tstop and cname loop detection)
    # https://www.rfc-editor.org/rfc/rfc1035#section-7     - resolver implementation
    # https://www.rfc-editor.org/rfc/rfc1035#section-7.4   - using the cache
    # https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2 - handle CNAMEs
    # https://datatracker.ietf.org/doc/html/rfc1123#section-6

    with nss <- recurse_nss(msg, ctx, tstop),
         {:ok, msg} <- query_nss(nss, qry, ctx, tstop, 0, []) do
      reply_handler(qry, msg, ctx, tstop)
    else
      {:error, reason} -> {:error, {reason, msg}}
      other -> {:error, other}
    end
  end

  @spec recurse_nss(msg, map, timeT) :: [ns]
  defp recurse_nss(msg, ctx, tstop) do
    # - resolve non-glue NS in referral msg & return NSS, respecting maxtime
    # - glue NS A/AAAA RRs are already in the cache
    # - drop NS's that are subdomains of `zone` but not in glue records to avoid looping
    with :referral <- reply_type(msg),
         zone <- hd(msg.authority).name,
         rrs <- Enum.filter(msg.authority, fn rr -> rr.type == :NS end),
         glue <- Enum.map(msg.additional, fn rr -> String.downcase(rr.name) end),
         nsnames <- Enum.map(rrs, fn rr -> String.downcase(rr.rdmap.name) end),
         nsnames <- Enum.filter(nsnames, fn name -> name not in glue end),
         unglued <- Enum.filter(nsnames, fn name -> dname_subdomain?(name, zone) end) do
      Log.info("#{hd(msg.question).name}, following referral to #{zone}")

      if glue != [],
        do: Log.info("glue ns: #{inspect(glue)}")

      if unglued != [],
        do: Log.warning("dropping NSs due to missing glue #{inspect(unglued)}")

      nsnames = nsnames -- unglued

      for name <- nsnames, type <- [:A, :AAAA] do
        ctx =
          ctx
          |> Map.put(:nameservers, nil)
          |> Map.put(:maxtime, timeout(tstop))
          |> Map.put(:rd, 1)

        case resolvep(name, type, ctx) do
          {:ok, msg} -> msg.answer
          _other -> [] |> IO.inspect(label: "!! could not resolve ns #{name} #{type}")
        end
      end

      Cache.nss(zone)
    else
      _ -> []
    end
  rescue
    _ -> []
  end

  # [[ QUERY ]]

  @spec query_nss([ns], DNS.Msg.t(), map, integer, non_neg_integer, [ns]) ::
          {:ok, DNS.Msg.t()} | {:error, reason}
  defp query_nss([] = _nss, _qry, _ctx, _tstop, _nth, [] = _failed),
    do: {:error, :timeout}

  defp query_nss([] = _nss, qry, ctx, tstop, nth, failed) do
    Log.warn("retrying #{length(failed)} failed nameservers")
    query_nss(Enum.reverse(failed), qry, ctx, tstop, nth + 1, [])
  end

  defp query_nss([ns | nss], qry, ctx, tstop, nth, failed) do
    # query_nss is responsible for getting 1 answer from NSS-list
    Log.info("time remaining #{timeout(tstop)}")

    cond do
      timeout(tstop) == 0 ->
        Log.error("global timeout for query reached")
        {:error, :timeout}

      ctx.retry < nth ->
        Log.error("maximum number of retries (#{nth}) reached")
        {:error, :timeout}

      true ->
        ns = unwrap(ns)
        Log.info("trying ns #{inspect(ns)}")

        case query_ns(ns, qry, ctx, tstop, nth) do
          {:error, :timeout} ->
            Log.warning("pushing #{inspect(ns)} onto failed list (:timeout)")
            query_nss(nss, qry, ctx, tstop, nth, [wrap(ns, ctx.srvfail_wait) | failed])

          {:error, reason} ->
            # :system_limit | :not_owner | :inet.posix() | DNS.MsgError.t do not bode well for this ns
            Log.warning("dropping #{inspect(ns)}, due to error: #{inspect(reason)}")
            query_nss(nss, qry, ctx, tstop, nth, failed)

          {:ok, msg} ->
            # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
            # https://datatracker.ietf.org/doc/rfc8914/ (extended DNS errors)
            # https://github.com/erlang/otp/blob/c55dc0d0a4a72fc59642aff186adde4621891cde/lib/kernel/src/inet_res.erl#L921
            case xrcode(msg) do
              rcode
              when rcode in [:FORMERROR, :NOTIMP, :REFUSED, :BADVERS] ->
                Log.warning("dropping #{inspect(ns)}, due to (x)RCODE: #{rcode}")
                query_nss(nss, qry, ctx, tstop, nth, failed)

              _ ->
                # the only place where msg is offered to the cache
                Cache.put(msg)
                {:ok, msg}
            end
        end
    end
  end

  @spec query_ns(ns, msg, map, timeT, counter) :: {:ok, msg} | {:error, reason}
  defp query_ns(ns, qry, ctx, tstop, n) do
    # responsible for getting 1 answer from 1 nameserver
    # [?] should we fallback to plain dns in case EDNS leads to BADVERS?
    bufsize = ctx.bufsize
    timeout = ctx.timeout
    payload = byte_size(qry.wdata)

    if payload > bufsize or ctx.tcp do
      query_tcp(ns, qry, timeout, tstop)
    else
      udp_timeout = udp_timeout(timeout, ctx.retry, n, tstop)

      case query_udp(ns, qry, udp_timeout, bufsize) do
        {:ok, rsp} when rsp.header.tc == 1 ->
          Log.info("reply truncated, switching to tcp")
          query_tcp(ns, qry, timeout, tstop)

        result ->
          result
      end
    end
  end

  @spec query_udp(ns, msg, timeout, non_neg_integer) :: {:ok, msg} | {:error, reason}
  defp query_udp(_ns, _qry, 0, _bufsize),
    do: {:error, :timeout}

  defp query_udp({ip, port}, qry, timeout, bufsize) do
    # query_udp_open protects against a process *exit* with :badarg
    {:ok, sock} = query_udp_open(ip, port, bufsize)

    with :ok <- :gen_udp.connect(sock, ip, port),
         :ok <- :gen_udp.send(sock, qry.wdata),
         {:ok, msg} <- query_udp_recv(sock, qry, timeout) do
      # note that:
      # - query_udp_open uses random src port for each query
      # - :gen_udp.connect ensures incoming data arrived at our src IP & port
      # - query_udp_recv ensures qry/msg ID's are equal and msg's qr=1
      # the higher ups will need to deal with how to handle the reply
      :gen_udp.close(sock)
      {:ok, msg}
    else
      error ->
        :gen_udp.close(sock)
        Log.error("udp socket error #{inspect(ip)}, #{inspect(error)}")
        error
    end
  rescue
    # when query_udp_open returns {:error, :badarg} (i.e. the term in e)
    e in MatchError -> e.term
  end

  @spec query_udp_open(:inet.ip_address(), non_neg_integer, non_neg_integer) ::
          {:ok, :gen_udp.socket()} | {:error, :system_limit | :badarg | :inet.posix()}
  defp query_udp_open(ip, port, bufsize) do
    # avoid exit :badarg from gen_udp.open
    # gen_udp.open -> {ok, socket} | {:error, system_limit | :inet.posix()}
    # or {:error, :badarg}
    iptype =
      case Pfx.type(ip) do
        :ip4 -> :inet
        :ip6 -> :inet6
      end

    with true <- is_u16(port),
         true <- iptype in [:inet, :inet6] do
      ctx = [:binary, iptype, active: false, recbuf: bufsize]
      :gen_udp.open(0, ctx)
    else
      false -> {:error, :badarg}
    end
  end

  @spec query_udp_recv(:inet.socket(), msg, timeout) :: {:ok, msg} | {:error, reason}
  defp query_udp_recv(_sock, _qry, 0),
    do: {:error, :timeout}

  defp query_udp_recv(sock, qry, timeout) do
    # - if it's not an answer to the question, try again until timeout has passed
    # - sock is connected, so addr,port *should* be ok
    {:ok, {ip, p}} = :inet.peername(sock)
    ns = inspect({ip, p})
    Log.info("resolving #{hd(qry.question).name} at #{ns}, timeout #{timeout} ms")
    tstart = now()
    tstop = time(timeout)

    with {:ok, {_addr, _p, rsp}} <- :gen_udp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- reply?(qry, msg) do
      span = now() - tstart
      size = byte_size(msg.wdata)
      Log.info("received #{size} bytes in #{span} ms, from #{ns}")

      {:ok, msg}
    else
      false -> query_udp_recv(sock, qry, timeout(tstop))
      other -> other
    end
  end

  @spec query_tcp(ns, msg, timeout, timeT) :: {:ok, msg} | {:error, reason}
  defp query_tcp(_ns, _qry, 0, _tstop),
    do: {:error, :timeout}

  defp query_tcp({ip, port}, qry, timeout, tstop) do
    # connect outside `with`-block, so we can always close the socket
    {:ok, sock} = query_tcp_connect({ip, port}, timeout, tstop)
    t0 = now()

    with :ok <- :gen_tcp.send(sock, qry.wdata),
         {:ok, rsp} <- :gen_tcp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- reply?(qry, msg) do
      :gen_tcp.close(sock)
      t = now() - t0
      Log.info("received #{byte_size(rsp)} bytes from #{Pfx.new(ip)}:#{port}/tcp in #{t} ms")
      {:ok, msg}
    else
      false ->
        {:error, :noreply}

      {:error, e} ->
        Log.warning("query_tcp error #{inspect(e)}")
        :gen_tcp.close(sock)
        {:error, e}
    end
  rescue
    # when query_tcp_connect returns {:error, any}
    e in MatchError -> e.term
  end

  @spec query_tcp_connect(ns, timeout, timeT) :: {:ok, :inet.socket()} | {:error, reason}
  defp query_tcp_connect({ip, port}, timeout, tstop) do
    # avoid *exit* badarg by checking ip/port's validity
    Log.info("query tcp: #{inspect(ip)}, #{port}/tcp, timeout #{timeout}")

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

  @spec make_query(binary, type, map) :: {:ok, msg} | {:error, any}
  defp make_query(name, type, ctx) do
    # assumes ctx is safe (made by resolve_contextp and maybe updated on recursion)
    # https://community.cloudflare.com/t/servfail-from-1-1-1-1/578704/9
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
      if ctx.edns,
        do: [[bufsize: ctx.bufsize, do: ctx.do, type: :OPT, class: :IN]],
        else: []

    qtn_opts = [[name: name, type: type, class: ctx.class]]
    hdr_opts = [rd: ctx.rd, cd: ctx.cd, opcode: ctx.opcode, id: Enum.random(0..65535)]

    case Msg.new(hdr: hdr_opts, qtn: qtn_opts, add: edns_opts) do
      {:ok, qry} -> Msg.encode(qry)
      {:error, e} -> {:error, e.data}
    end
  end

  # [[ REPLIES ]]
  @spec reply_handler(msg, msg, map, timeT) :: {:ok, msg} | {:error, {atom, msg}}
  defp reply_handler(_qry, msg, %{recurse: false}, _tstop) do
    case reply_type(msg) do
      :lame ->
        Log.warning("lame reply for #{msg.question}")
        Log.debug("lame reply msg was #{msg}")
        {:error, {:lame, msg}}

      _ ->
        {:ok, msg}
    end
  end

  defp reply_handler(qry, msg, ctx, tstop) do
    qtn = hd(qry.question)

    case reply_type(msg) do
      :answer ->
        {:ok, msg}

      :referral ->
        # TODO: loop detection for referrals goes here
        zone = hd(msg.authority).name
        Log.info("#{qtn.name} #{qtn.type} - got referral to #{zone}")
        recurse(qry, msg, ctx, tstop)

      :cname ->
        rr = Enum.find(msg.answer, fn rr -> rr.type == :CNAME end)
        {:ok, cname} = dname_normalize(rr.rdmap.name)

        if Enum.member?(ctx.cnames, cname) do
          Log.warning("cname loop detected for cname #{rr.name} CNAME  #{cname}")
          {:error, {:cname_loop, msg}}
        else
          ctx =
            %{ctx | cnames: [cname | ctx.cnames]}
            |> Map.delete(:nameservers)
            |> Map.put(:maxtime, timeout(tstop))
            |> Map.put(:rd, 0)

          # use canonical name as-is to preserve case
          case resolvep(rr.rdmap.name, qtn.type, ctx) do
            {:ok, msg} ->
              # Modify message: prepend cname-RR, restore original question
              # (AA=0 since msg is synthesized)
              question = [%{qtn | wdata: <<>>}]
              answer = [%{rr | wdata: <<>>} | msg.answer]
              header = %{msg.header | aa: 0, anc: length(answer), wdata: <<>>}
              msg = %{msg | header: header, question: question, answer: answer}
              {:ok, msg}

            {:error, {:cname_loop, msg}} ->
              header = %{msg.header | aa: 0, anc: msg.header.anc + 1, wdata: <<>>}
              question = [%{qtn | wdata: <<>>}]
              answer = [%{rr | wdata: <<>>} | msg.answer]
              msg = %{msg | header: header, question: question, answer: answer}
              {:error, {:cname_loop, msg}}

            error ->
              error
          end
        end

      :nodata ->
        Log.info("got a NODATA reply to #{qry}")
        {:ok, msg}

      :lame ->
        Log.warning("got a lame reply to #{qry}")
        {:error, {:lame, msg}}
    end
  end

  @spec reply_make(msg, [DNS.Msg.RR.t()]) :: {:ok, msg}
  defp reply_make(qry, rrs) do
    # a synthesized answer from cache:
    # - is created by copying & updating the vanilla qry msg
    # - has no wdata and id of 0
    # - aa=0, since we're not an authoritative source
    # - ra=1, since we're answering and recursion is available
    # Note: individual RR's *will* have wdata if they are raw RR's
    # TODO: we need to deal with qtype=CNAME (i.e. add RR's for canon name if
    # available)
    hdr = %{qry.header | anc: length(rrs), aa: 0, ra: 1, qr: 1, id: 0, wdata: ""}
    qtn = %{hd(qry.question) | wdata: ""}

    rsp = %{qry | header: hdr, question: [qtn], answer: rrs, wdata: ""}
    {:ok, rsp}
  end

  @spec reply_type(msg) :: :referral | :cname | :answer | :lame | :nodata
  defp reply_type(%{
         header: %{anc: 0, nsc: nsc, rcode: :NOERROR},
         question: [%{name: qname}],
         answer: [],
         authority: aut
       })
       when nsc > 0 do
    # see also
    # - https://datatracker.ietf.org/doc/html/rfc2308#section-2.1 (NAME ERROR)
    # - https://datatracker.ietf.org/doc/html/rfc2308#section-2.2 (NODATA)
    # - https://www.ietf.org/rfc/rfc4470.txt (white lies)
    # - https://datatracker.ietf.org/doc/rfc9471/  (glue records)
    # - https://blog.cloudflare.com/black-lies/
    # - https://datatracker.ietf.org/doc/html/draft-valsorda-dnsop-black-lies
    # REVIEW: use-cases in the wild:
    #   dig www.azure.com @ns1.cloudns.net -> DNS hijacking:
    #   -> ANSWER w/ cloudns IP for site with ads, AUTHORITY with SOA for "" (!) <- :lame (!)
    #   dig www.example.com @ns1.cloudns.net -> weird SOA record
    #   -> ANSWER 0, AUTHORITY SOA example.com is ns1.cloudns.net (?)
    #   dig ns example.com @ns1.cloudns.net -> list themselves in NSS (?)
    #
    #
    # actually, should check is previous zone is parent to new zone, otherwise its bogus...
    match = fn zone -> dname_subdomain?(qname, zone) or dname_equal?(qname, zone) end

    case aut do
      [] ->
        # REVIEW: log error (nsc>0 and aut==[] is actually a formerr)
        :nodata

      _ ->
        soa = Enum.any?(aut, fn rr -> rr.type == :SOA end)
        nss = Enum.any?(aut, fn rr -> rr.type == :NS and match.(rr.name) end)

        cond do
          soa -> :nodata
          nss -> :referral
          true -> :lame
        end
    end
  end

  defp reply_type(%{
         header: %{anc: anc, qdc: 1, rcode: :NOERROR},
         question: [%{type: qtype}],
         answer: answer
       })
       when anc > 0 do
    # see also
    # - https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2
    # - https://www.rfc-editor.org/rfc/rfc1034#section-4.3.2
    # - https://datatracker.ietf.org/doc/html/rfc2308#section-1
    # - https://datatracker.ietf.org/doc/html/rfc2181#section-10.1
    # * if query was for :CNAME, always qualify reply as :answer
    # * if answer includes a :CNAME and some RR's of qtype, then we assume:
    #   - that ns is also authoritative for the cname, and
    #   - that the RR's with qtype are for the cname given
    #   otherwise the :answer would actually be :lame. For now that is
    #   up to the caller to detect/decide
    #   TODO: should we check those RR's of qtype are for the cname?
    # * if answer includes a :CNAME and no RR's of qtype, then
    #   nameserver is not authoritative for zone of canonical name
    #   and `resolve` will have to follow up on the canonical name
    cname = Enum.any?(answer, fn rr -> rr.type == :CNAME end)
    wants = Enum.any?(answer, fn rr -> rr.type == qtype end)

    cond do
      qtype == :CNAME -> :answer
      wants -> :answer
      cname -> :cname
      true -> :lame
    end
  end

  defp reply_type(_),
    do: :answer

  # [[ NSS helpers ]]

  defp check_nss([]),
    do: true

  defp check_nss([{ip, port} | nss]) do
    if Pfx.valid?(ip) and is_tuple(ip) and is_u16(port),
      do: check_nss(nss),
      else: false
  end

  # [[ HELPERS ]]

  @spec reply?(msg, msg) :: boolean
  defp reply?(qry, rsp) do
    # https://datatracker.ietf.org/doc/html/rfc5452.html#section-9.1
    # - not named in rfc5452, but rsp.header.qr must be 1 (!)
    # - [?] also check the opcode's line up
    # - note: this says nothing about the contents of answer/aut/add sections
    #   some auth nameservers provide an actual reply with bogus content
    #   (e.g. aa=1, a=127.0.0.2, NS "" is localhost !, when asked for something
    #    they are not authoritative for ...)
    cond do
      qry.header.id != rsp.header.id ->
        false

      qry.header.opcode != rsp.header.opcode ->
        false

      rsp.header.qr != 1 ->
        false

      length(qry.question) != length(rsp.question) ->
        false

      true ->
        # nowadays a question section with more than 1 question is unlikely,
        # still it is possible.  Direct wdata comparison is not possible:
        # - domain name compression might be present in the reply, or
        # - domain name in reply might have different case (?)
        # so qry/rsp names are normalized so both sort the same
        ql =
          qry.question
          |> Enum.map(fn q -> {elem(dname_normalize(q.name), 1), q.type, q.class} end)
          |> Enum.sort()

        rl =
          rsp.question
          |> Enum.map(fn r -> {elem(dname_normalize(r.name), 1), r.type, r.class} end)
          |> Enum.sort()

        ql == rl
    end
  end

  @spec xrcode(msg) :: atom | non_neg_integer
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

  # wrap a nameserver with an absolute point in time,
  # later on, when revisiting, we'll wait the remaining time
  defp wrap(ns, timeout),
    do: {ns, time(timeout)}
end
