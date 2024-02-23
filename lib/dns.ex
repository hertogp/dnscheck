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
  @type desc :: binary | DNS.ErrorMsg.t() | msg
  @typedoc "Reasons why resolving may fail"
  @type reason ::
          {:timeout, desc}
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
  @spec resolve(binary, type, Keyword.t()) ::
          {:ok, msg}
          | {:error, {:option, binary}}
          # resolvep
          | {:error, {:query, binary}}
          | {:error, {:timeout, binary}}
          | {:error, {:retries, binary}}
          | {:error, {:lame, msg}}
          | {:error, {:rzone_loop, msg}}
          | {:error, {:cname_loop, msg}}

  def resolve(name, type, opts \\ []) do
    # notes
    # ctx.zones -> detect referral loop (per iterative query)
    # - is (re)set each time a new iteration starts (in resolvep)
    # - is updated when following referrals (by reply_handler)s
    # ctx.cnames -> detect cname loops (across iterative queries)
    # - is initialized for each new caller's query (i.e. here)
    # - is updated when following cnames (by reply_handler)
    # TODO:
    # [ ] put limit on length of CNAME-chain, e.g. 10?
    # [ ] put limit on number of referrals to follow, e.g. 10?
    # [ ] probably move Cache.init/1 to dnscheck.ex at some point
    Cache.init(clear: false)
    recurse = opts[:nameservers] == nil
    Log.info("User query for #{name}, #{type}, recurse: #{recurse}.")

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
      # name: name,
      # type: type,
      rzones: ["."],
      cnames: [name]
    }

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
      {:ok, ctx} -> resolvep(name, type, ctx)
      error -> {:error, {:option, error}}
    end
  rescue
    # Terms.en/decode may raise an DNS.MsgError
    err in DNS.MsgError -> {:error, {:option, err.data}}
  end

  @spec resolvep(binary, type, map) ::
          {:ok, msg}
          # make_query
          | {:error, {:query, binary}}
          # query_nss/reply_handler
          | {:error, {:timeout, binary}}
          | {:error, {:retries, binary}}
          | {:error, {:lame, msg}}
          | {:error, {:rzone_loop, msg}}
          | {:error, {:cname_loop, msg}}
  defp resolvep(name, type, ctx) do
    # resolvep called by:
    # - resolve to answer caller's query
    # - recurse_nss during referral, to resolve non-glue NS's
    # - resolve_handler, to follow cnames and/or referrals
    with {:ok, qry} <- make_query(name, type, ctx),
         qname <- hd(qry.question).name,
         cached <- Cache.get(qname, ctx.class, type),
         tstop <- time(ctx.maxtime) do
      Log.info("iterative mode is #{ctx.recurse}")

      case cached do
        [] ->
          nss = ctx[:nameservers] || Cache.nss(qname)
          Log.info("#{name} #{type} got #{length(nss)} nameservers")

          case query_nss(nss, qry, ctx, tstop, 0, _failed = []) do
            {:ok, msg} -> reply_handler(qry, msg, ctx, tstop)
            error -> error
          end

        rrs ->
          Log.info("answering from cache, using #{length(rrs)} RR's")
          {:ok, msg} = reply_make(qry, rrs)
          reply_handler(qry, msg, ctx, tstop)
      end
    else
      error -> error
    end
  end

  # [[ RECURSE ]]

  @spec recurse(msg, msg, map, timeT) ::
          {:ok, msg}
          # reply_handler
          | {:error, {:rzone_loop, msg}}
          | {:error, {:cname_loop, msg}}
          | {:error, {:lame, msg}}
          | {:error, {:query, binary}}
          # query_nss
          | {:error, {:timeout, binary}}
          | {:error, {:retries, binary}}
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
      error -> error
    end
  end

  @spec recurse_nss(msg, map, timeT) :: [ns]
  defp recurse_nss(msg, ctx, tstop) do
    # - glue NS A/AAAA RRs are already in the cache
    # - drop NS's that are subdomains of `zone` but not in glue records to avoid looping
    # - then resolve remaining non-glued NS in referral msg & return NSS, respecting maxtime
    # - be paranoid: accept only glue rrs with type  A/AAAA from additional
    # FIXME: make stuff below simpler with Enum.reduce
    #   glue = Enum.reduce(msg.additional, [], fn rr, acc ->
    #            if rr.type in [:A, :AAAA],
    #              do: [String.downcase(rr.rdmap.name) | acc],
    #             else: acc
    #             end)
    # REVIEW: the rescue part is not necessary since a referral always has NS's..
    #         just to be sure, maybe use List.first(nss)[:name] -> nil or binary
    with :referral <- reply_type(msg),
         glue <- Enum.filter(msg.additional, fn rr -> rr.type in [:A, :AAAA] end),
         glue <- Enum.map(glue, fn rr -> String.downcase(rr.name) end),
         nss <- Enum.filter(msg.authority, fn rr -> rr.type == :NS end),
         zone <- hd(nss).name,
         nsnames <- Enum.map(nss, fn rr -> String.downcase(rr.rdmap.name) end),
         nsnames <- Enum.filter(nsnames, fn name -> name not in glue end),
         missing <- Enum.filter(nsnames, fn name -> dname_subdomain?(name, zone) end),
         nsnames <- nsnames -- missing do
      if glue != [],
        do: Log.info("glue ns: #{inspect(glue)}")

      if missing != [],
        do: Log.warning("dropped NS's due to missing but required glue #{inspect(missing)}")

      # TODO: put ns in nss as: {:inet.address, 53} or {fqdn} and only resolve
      # fqdn when needed.  Requires different handling of Cache.nss's response
      # Reason: we're pre-fetching/resolving nameservers that might never be used ...
      # which takes time and slows down resolving caller's query.
      for name <- nsnames, type <- [:A, :AAAA] do
        # resolvep NS names, so they end up in the cache
        ctx =
          ctx
          |> Map.put(:nameservers, nil)
          |> Map.put(:recurse, true)
          |> Map.put(:maxtime, timeout(tstop))

        case resolvep(name, type, ctx) do
          {:ok, msg} ->
            msg.answer

          _ ->
            Log.error("could not resolve ns #{name} #{type}")
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

  @spec query_nss([ns | {ns, integer}], DNS.Msg.t(), map, timeT, counter, [{ns, integer}]) ::
          {:ok, msg}
          | {:error, {:timeout, binary}}
          | {:error, {:retries, binary}}

  defp query_nss([] = _nss, _qry, _ctx, _tstop, _nth, [] = _failed),
    do: {:error, {:timeout, "nameserver(s) failed to reply properly"}}

  defp query_nss([] = _nss, qry, ctx, tstop, nth, failed) do
    Log.warn("retrying #{length(failed)} failed nameservers")
    query_nss(Enum.reverse(failed), qry, ctx, tstop, nth + 1, [])
  end

  defp query_nss([ns | nss], qry, ctx, tstop, nth, failed) do
    # query_nss is responsible for getting 1 answer from NSS-list
    Log.info("time remaining #{timeout(tstop)}")

    cond do
      timeout(tstop) == 0 ->
        {:error, {:timeout, "Query timeout for query reached"}}

      ctx.retry < nth ->
        {:error, {:retries, "Query max retries (#{nth}) reached"}}

      true ->
        ns = unwrap(ns)
        Log.info("trying ns #{inspect(ns)}")

        case query_ns(ns, qry, ctx, tstop, nth) do
          {:error, :timeout} ->
            Log.warning("pushing #{inspect(ns)} onto failed list (:timeout)")
            query_nss(nss, qry, ctx, tstop, nth, [wrap(ns, ctx.srvfail_wait) | failed])

          {:error, reason} ->
            # REVIEW: some query_ns errors (e.g. :system_limit or :inet.posix()) might require a
            # full stop here ...
            Log.warning("dropping #{inspect(ns)}, due to error: #{inspect(reason)}")
            query_nss(nss, qry, ctx, tstop, nth, failed)

          {:ok, msg} ->
            # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
            # https://datatracker.ietf.org/doc/rfc8914/ (extended DNS errors)
            # https://github.com/erlang/otp/blob/c55dc0d0a4a72fc59642aff186adde4621891cde/lib/kernel/src/inet_res.erl#L921
            # REVIEW:
            # - a reply with FORMERROR may also mean EDNS is not supported by NS
            case xrcode(msg) do
              rcode
              when rcode in [:FORMERROR, :NOTIMP, :REFUSED, :BADVERS] ->
                Log.warning("dropping ns #{inspect(ns)}: it replied with (x)RCODE: #{rcode}")
                query_nss(nss, qry, ctx, tstop, nth, failed)

              _ ->
                # the only place where msg is offered to the cache
                # TODO: move to reply_handler, we donot wat to cache RR's from
                # e.g. :lame responses ..
                # Cache.put(msg)
                {:ok, msg}
            end
        end
    end
  end

  @spec query_ns(ns, msg, map, timeT, counter) ::
          {:ok, msg}
          | {:error,
             :timeout
             | :badarg
             | :system_limit
             | :not_owner
             | :inet.posix()
             | DNS.MsgError.t()
             | :notreply
             | {:timeout, binary}
             | :closed}
  defp query_ns(ns, qry, ctx, tstop, n) do
    # responsible for getting 1 answer from 1 nameserver
    # REVIEW: perhaps fallback to plain dns when EDNS leads to BADVERS or FORMERROR ?
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

  @spec query_udp(ns, msg, timeout, non_neg_integer) ::
          {:ok, msg}
          | {:error,
             :timeout | :badarg | :system_limit | :not_owner | :inet.posix() | DNS.MsgError.t()}
  defp query_udp(_ns, _qry, 0, _bufsize),
    do: {:error, :timeout}

  defp query_udp({ip, port}, qry, timeout, bufsize) do
    # note that:
    # - query_udp_open uses random src port for each query
    # - :gen_udp.connect ensures incoming data arrived at our src IP:port
    # - query_udp_recv ensures qry/msg ID's are equal and msg's qr=1
    # the higher ups will need to decide on how to handle the reply
    {:ok, sock} = query_udp_open({ip, port}, bufsize)

    with :ok <- :gen_udp.connect(sock, ip, port),
         :ok <- :gen_udp.send(sock, qry.wdata),
         {:ok, msg} <- query_udp_recv(sock, qry, timeout) do
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

  @spec query_udp_open(ns, non_neg_integer) ::
          {:ok, :gen_udp.socket()} | {:error, :badarg | :system_limit | :inet.posix()}
  defp query_udp_open({ip, port}, bufsize) do
    # avoid *process exit* (!) with :badarg from :gen_udp.open
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

  @spec query_udp_recv(:inet.socket(), msg, timeout) ::
          {:ok, msg} | {:error, :not_owner | :timeout | :inet.posix() | DNS.MsgError.t()}

  defp query_udp_recv(_sock, _qry, 0) do
    {:error, :timeout}
  end

  defp query_udp_recv(sock, qry, timeout) do
    # - if it's not an answer to the question, try again until timeout has passed
    # - sock is connected, so `addr`,`port` *should* match `ip`,`p`
    {:ok, {ip, p}} = :inet.peername(sock)
    ns = inspect({ip, p})
    Log.info("resolving #{hd(qry.question).name} at #{ns}, timeout #{timeout} ms")
    tstart = now()
    tstop = time(timeout)

    # REVIEW: after decoding, rcode might indicate that's its no use retrying
    # this server, e.g. FORMERR or NOTIMP or REFUSED.  In the case of FORMERR
    # the rsp msg will have question/answer/authority/additional all empty (!)
    with {:ok, {_addr, _p, rsp}} <- :gen_udp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- reply?(qry, msg) do
      span = now() - tstart
      size = byte_size(msg.wdata)
      Log.info("received #{size} bytes in #{span} ms, from #{ns}")

      {:ok, msg}
    else
      false ->
        Log.warning("retry udp_recv for #{inspect(qry.question)}")
        query_udp_recv(sock, qry, timeout(tstop))

      # other is {:error, :not_owner | :timeout | :inet.posix | DNS.MsgError.t}
      other ->
        other
    end
  end

  @spec query_tcp(ns, msg, timeout, timeT) ::
          {:ok, msg}
          | {:error,
             :notreply | :timeout | {:timeout, binary} | :badarg | :closed | :inet.posix()}
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
        {:error, :notreply}

      {:error, e} ->
        Log.warning("query_tcp error #{inspect(e)}")
        :gen_tcp.close(sock)
        {:error, e}
    end
  rescue
    # when query_tcp_connect returns {:error, ...} (see spec below)
    e in MatchError -> e.term
  end

  @spec query_tcp_connect(ns, timeout, timeT) ::
          {:ok, :inet.socket()} | {:error, :badarg | :timeout | :inet.posix()}
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

  @spec make_query(binary, type, map) :: {:ok, msg} | {:error, {:query, binary}}
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

    with {:ok, msg} <- Msg.new(hdr: hdr_opts, qtn: qtn_opts, add: edns_opts),
         {:ok, qry} <- Msg.encode(msg) do
      {:ok, qry}
    else
      {:error, dnsMsgErr} -> {:error, {:query, "#{inspect(dnsMsgErr.data)}"}}
    end
  end

  # [[ REPLIES ]]
  @spec reply_handler(msg, msg, map, timeT) ::
          {:ok, msg}
          | {:error, {:lame, msg}}
          | {:error, {:cname_loop, msg}}
          | {:error, {:rzone_loop, msg}}
          # resolvep/recurse
          | {:error, {:query, binary}}
          | {:error, {:timeout, binary}}
          | {:error, {:retries, binary}}
  defp reply_handler(_qry, msg, %{recurse: false}, _tstop) do
    case reply_type(msg) do
      :lame ->
        Log.warning("lame reply for #{inspect(msg.question)}")
        Log.debug("lame reply msg was #{msg}")
        {:error, {:lame, msg}}

      _ ->
        Cache.put(msg)
        {:ok, msg}
    end
  end

  defp reply_handler(qry, msg, ctx, tstop) do
    qtn = hd(qry.question)

    case reply_type(msg) do
      :answer ->
        Cache.put(msg)
        {:ok, msg}

      :referral ->
        # referral loop detection using ctx.rzones
        zone = hd(msg.authority).name
        Log.info("#{qtn.name} #{qtn.type} - got referral to #{zone}")
        seen = Enum.any?(ctx.rzones, &dname_equal?(&1, zone))

        if seen do
          Log.error("zone #{zone} seen before: #{inspect(ctx.rzones)}")
          {:error, {:rzone_loop, msg}}
        else
          Cache.put(msg)
          # these are fine:
          # ctx = %{ctx | rzones: [zone | ctx[:rzones]]}
          # ctx = Map.put(ctx, :zones, [zone | ctx.zones])
          # below yields complaint (when using "#{inspect(ctx.rzones)}"
          ctx = %{ctx | rzones: [zone | ctx[:rzones]]}
          Log.debug("qname=#{qtn.name} -> zones seen are: #{inspect(ctx.rzones)}")
          recurse(qry, msg, ctx, tstop)
        end

      :cname ->
        Cache.put(msg)
        rr = Enum.find(msg.answer, fn rr -> rr.type == :CNAME end)
        # REVIEW: handle a {:error, :eencode} return from dname_normalize
        {:ok, cname} = dname_normalize(rr.rdmap.name)

        # cname loop detection using ctx.cnames
        if Enum.member?(ctx.cnames, cname) do
          Log.error("cname #{cname} seen before: #{inspect(ctx.cnames)}")
          {:error, {:cname_loop, msg}}
        else
          ctx =
            %{ctx | cnames: [cname | ctx[:cnames]]}
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
        # Cache.put(msg)
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

  # Notes:
  # - query type :* or :ANY has answers come out as lame, but actually, the
  # anwer contains many diff RR-type, just not type ANY
  #
  #
  # """
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
    # actually, should check is previous zone is parent to new zone, otherwise its bogus...

    case aut do
      [] ->
        # REVIEW: log error (nsc>0 and aut==[] is actually a formerr)
        :nodata

      _ ->
        soa = Enum.any?(aut, fn rr -> rr.type == :SOA end)
        nss = Enum.any?(aut, fn rr -> rr.type == :NS and dname_indomain?(qname, rr.name) end)

        cond do
          soa -> :nodata
          nss -> :referral
          true -> :lame
        end
    end
  end

  defp reply_type(%{
         header: %{anc: anc, qdc: 1, rcode: :NOERROR},
         question: [%{name: qname, type: qtype}],
         answer: answer,
         authority: authority
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
    #   otherwise the :answer is actually :lame
    #   TODO: should we check those RR's of qtype are for the cname?
    # * if answer includes a :CNAME and no RR's of qtype, then
    #   nameserver is not authoritative for zone of canonical name
    #   and `resolve` will have to follow up on the canonical name
    # REVIEW: use-cases in the wild:
    # * dig www.azure.com @ns1.cloudns.net -> DNS hijacking:
    #   -> ANSWER w/ cloudns IP for site with ads, AUTHORITY with SOA for "" (!) <- :lame (!)
    # * dig www.example.com @ns1.cloudns.net -> weird SOA record
    #   -> AA=1, ANSWER 0, AUTHORITY SOA example.com is ns1.cloudns.net (?)
    # * dig ns example.com @ns1.cloudns.net -> list themselves in NSS (?)

    cname = Enum.any?(answer, fn rr -> rr.type == :CNAME end)
    # TODO: qtype :ANY or :* won't have answer rr's with rrtype==qtype (!)
    # so now, these are labelled :lame, which is not correct!
    # FIXME: also, query for type :* works, but type :ANY does not???
    wants = Enum.any?(answer, fn rr -> rr.type == qtype end)
    upref = Enum.any?(authority, fn rr -> rr.type == :NS and upward?(qname, rr.name) end)

    cond do
      qtype == :CNAME -> :answer
      # qtype == :ANY -> :answer
      qtype == :* -> :answer
      upref -> :lame
      wants -> :answer
      cname -> :cname
      true -> :lame
    end
  end

  defp reply_type(_),
    do: :answer

  defp upward?(qname, zone) do
    cond do
      zone in ["", "."] -> true
      dname_indomain?(qname, zone) -> false
      true -> true
    end
  end

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
    # `-> check srcIP, srcPort (see query_tcp/udp), ID, qname, qtype & qclass
    # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
    # `-> rsp.header.qr must be set to 1 in a response
    # `-> opcode set by originator and copied into response
    # https://www.rfc-editor.org/rfc/rfc1035#section-7.3
    # `-> match response (qtn) to current resolver requested info (qry.question)
    # note:
    # - a valid reply still might not be a useful answer
    #   e.g. a :FORMERROR response usually has all sections (incl. qtn) empty
    # - a msg with other RCODEs: qry.question and rsp.question should be same
    cond do
      qry.header.id != rsp.header.id ->
        Log.warning("ignoring reply: query ID does not match")
        false

      rsp.header.qr != 1 ->
        Log.warning("ignoring reply: expected qr=1, got #{rsp.header.qr}")
        false

      qry.header.opcode != rsp.header.opcode ->
        Log.warning("ignoring reply: opcode #{qry.header.opcode} != #{rsp.header.opcode}")

        false

      rsp.header.opcode == :FORMERROR ->
        true

      # REVIEW: are there other RCODEs that might have qry.questions == []?
      length(qry.question) != length(rsp.question) ->
        Log.warning("ignoring reply: question sections do not match")
        Log.debug("- qry msg: #{inspect(qry)}")
        Log.debug("- rsp msg: #{inspect(rsp)}")

        false

      true ->
        # can't compare directly using question.wdata since:
        # - there *could* be more than one question (unlikely though)
        # - in which case name compression might be used in response
        # - and character case might be different as well (also unlikely)
        # - lastly, order of individual qtn's in question section may differ
        ql =
          qry.question
          |> Enum.map(fn q -> {elem(dname_normalize(q.name), 1), q.type, q.class} end)
          |> Enum.sort()

        rl =
          rsp.question
          |> Enum.map(fn r -> {elem(dname_normalize(r.name), 1), r.type, r.class} end)
          |> Enum.sort()

        if ql == rl do
          true
        else
          Log.warning("ignoring reply: question sections do not match")
          Log.debug("- qry msg: #{inspect(qry)}")
          Log.debug("- rsp msg: #{inspect(rsp)}")
          false
        end
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
  # later on, when `unwrap`ing, we'll wait the remaining time
  @spec wrap(ns, non_neg_integer) :: {ns, integer}
  defp wrap(ns, timeout),
    do: {ns, time(timeout)}
end
