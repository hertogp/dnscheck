defmodule DNS do
  @moduledoc """
  DNS resolving functions

  """

  # TODO:
  # [ ] dname_normalize should handle escaped chars, see RFC4343
  # [ ] add an option for IPv4 only (may resolver is on an ipv4 only network)
  #     or maybe check interfaces on machine we're running on
  # [ ] change iana.update hints -> store hints as [{:inet.ip_address, 53}], and
  #     use Code.eval_file("priv/root.nss") here (so priv/root.nss is readable)
  # [ ] sort the root hints fastest to slowest RTT
  # [ ] add time spent to result of resolve (plus last NS seen?),
  #     stats: qtime = total, qrtt = last NS, qtstamp = timestamp, ns, port, rxsize (bytes received)
  # [ ] add check when recursing to see if delegated NSs are closer to QNAME
  #     if not, ignore them as bogus
  # [ ] store IP addresses as tuples in Msg components, right now there is lot
  #     of needless conversions between binary & tuples.
  # [ ] likewise, there is a lot of dname_normalize'ing for the same name going on
  # [x] add spec to resolve, detailing all possible error reasons
  # [x] resolve must try to answer from cache first and make_response
  # [ ] detect when a referral omits required glue records -> drop the NS
  #     referred to (avoid getting in a loop!)
  # [ ] detect when a NS refers to an alias instead of a canonical name
  #     warn (!). BIND drops the NS, PowerDNS/Knot simple resolve it.
  # [ ] if qname is ip address, convert it to reverse ptr name
  # [x] query for NS names in aut section (ex. tourdewadden.nl)
  # [x] detect NS loops
  # [ ] detect CNAME loops
  # [ ] responses must be better evaluated in query_nss
  #     - including extra validation rules for msg's (e.g. max 1 :OPT in additional, TSIG
  #       at the end, etc...)
  # [ ] dname encoding/decoding etc.. should support escaped dots like \\. in a label
  # [ ] randomize each nss set upon resolving/recursing (less predictable)
  # [ ] NSS storage/retrieval -> donot query for all new NSS, just the first
  #     one and later, when trying others, query for their address
  # [ ] add resolve/1 for resolve("name") and resolve("10.10.10.10") and resolve({1,1,1,1})
  #     it will always ask for A & AAAA or PTR RR's
  # BEHAVIOUR:
  # - NODATA -> msg w/ aa=1, anc=0, rcode NOERROR (name exists without data: empty non-terminal)
  # - NXDOMAIN -> name does exist, nor anything below it.
  # - CACHEing negative answers (NXDOMAIN) is done by qname, qclass (i.e. for any type apparently)
  # - cdn.cloudflare.net :NS -> respons has only a SOA

  @priv :code.priv_dir(:dnscheck)
  @fname_nss Path.join([@priv, "root.nss"])
  @root_nss Code.eval_file(@fname_nss) |> elem(0)

  alias DNS.Msg
  import DNS.Utils
  alias DNS.Cache
  alias DNS.Msg.Terms

  @typedoc "Type of RR, as atom or non negative integer"
  @type type :: atom | non_neg_integer
  @typedoc "Nameserver is tuple of IPv4/6 address-tuple and port number"
  @type ns :: {:inet.ip_address(), non_neg_integer}
  @typedoc "A struct representing a nameserver message"
  @type msg :: DNS.Msg.t()
  @typedoc "Reasons why resolving may fail"
  @type reason ::
          :timeout | :badarg | :system_limit | :not_owner | DNS.MsgError.t() | :inet.posix()
  @typedoc "A counter is shorthand for non negative integer"
  @type counter :: non_neg_integer
  @typedoc "timeT is a, possibly future, absolute point in monolithic time"
  @type timeT :: integer

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
  @spec resolve(binary, type, Keyword.t()) :: {:ok, msg} | {:error, reason}
  def resolve(name, type, opts \\ []) do
    # TODO:
    # [ ] probably move this to dnscheck.ex at some point
    Cache.init(clear: false)

    with {:ok, opts} <- make_options(opts),
         {:ok, qry} <- make_query(name, type, opts),
         qname <- hd(qry.question).name,
         cached <- Cache.get(qname, :IN, type) do
      log(true, "resolving #{qname}, #{type}")

      case cached do
        [] ->
          # if opts.recurse is false -> use caller's explicitly provided opts.nameservers
          nss = (opts.recurse && Cache.nss(qname)) || opts.nameservers
          IO.inspect(nss, label: :cached_nss)
          tstop = time(opts.maxtime)

          case query_nss(nss, qry, opts, tstop, 0, _failed = []) do
            {:ok, msg} ->
              Cache.put(msg)
              xrcode = xrcode(msg)
              anc = msg.header.anc
              nsc = msg.header.nsc
              arc = msg.header.arc

              log(
                true,
                "- server replied: #{xrcode}, #{anc} answers, #{nsc} authority, #{arc} additional"
              )

              # RECURSE when:
              # [ ] anc is 0, nsc > 0
              # [ ] answer is :CNAME and qtype != :CNAME -> recurse with new name
              #     retain CNAME and include that in the answer

              res_response_type(msg) |> IO.inspect(label: :rsp_type)
              # is this always sound?
              if anc == 0 and opts.recurse and nsc > 0 and :NOERROR == xrcode,
                do: res_recurse(qry, msg, opts, tstop, %{}),
                else: {:ok, msg}

            {:error, reason} ->
              IO.inspect({:error, reason}, label: :cached)
          end

        rrs ->
          log(true, "- using cached answer with #{length(rrs)} answer(s)")
          make_response(qry, rrs)
      end
    else
      e -> e
    end
  end

  def res_recurse(qry, msg, opts, tstop, seen) do
    # https://www.rfc-editor.org/rfc/rfc1035#section-7     - resolver implementation
    # https://www.rfc-editor.org/rfc/rfc1035#section-7.4   - using the cache
    # https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2 - handle CNAMEs
    # https://datatracker.ietf.org/doc/html/rfc1123#section-6
    # NOTES
    # - same qry, different nameservers due to redirection

    qtn = hd(qry.question)
    log(true, "- recursing for #{qtn.name} #{qtn.type}")
    # TODO: Cache.put(qry, msg) so msg can be better sanity checked
    Cache.put(msg)

    # always move forward, never circle back hence filtering seen
    nss =
      msg.authority
      |> Enum.filter(fn rr -> rr.type == :NS end)
      |> Enum.map(fn rr -> rr.rdmap.name end)
      |> res_recurse_nss()
      |> Enum.filter(fn ns -> not Map.has_key?(seen, ns) end)

    zone =
      if length(msg.authority) > 0,
        do: hd(msg.authority).name,
        else: "no ns found"

    log(true, "- referral to #{zone}, found #{length(nss)} nss")

    # keep track of where we've been
    seen = Enum.reduce(nss, seen, fn ns, acc -> Map.put(acc, ns, []) end)

    # TODO: report an error when all ns were seen before
    log(opts.verbose, "- new nss: #{inspect(nss)}")

    with {:ok, msg} <- query_nss(nss, qry, opts, tstop, 0, []),
         xrcode <- xrcode(msg),
         anc <- msg.header.anc,
         nsc <- msg.header.nsc do
      case xrcode do
        :NOERROR when anc == 0 and nsc > 0 ->
          Cache.put(msg)
          res_recurse(qry, msg, opts, tstop, seen)

        :NOERROR when anc > 0 ->
          Cache.put(msg)
          {:ok, msg}

        other ->
          {:error, {other, msg}}
      end
    else
      {:error, reason} -> {:error, {reason, msg}}
      other -> {:error, other}
    end
  end

  @spec res_recurse_nss([binary]) :: [{:inet.ip_address(), integer}]
  def res_recurse_nss(nsnames) do
    # given a list of names of :NS namerservers taken from authority,
    # get their IP addresses.  Consult the cache first, then resolve
    # any that are not yet in the cache.  Note that the msg on whose
    # authority we're recursing on will have been cached already, so
    # any glue records for nameservers that were in the additional
    # section, can be retrieved from the cache.
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

    log(true, "- resolving new ns: #{Enum.join(new, ",")}")

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
  rescue
    _ -> []
  end

  @spec query_nss([ns], DNS.Msg.t(), map, integer, non_neg_integer, [ns]) ::
          {:ok, DNS.Msg.t()} | {:error, any}
  def query_nss([] = _nss, _qry, _opts, _tstop, _nth, [] = _failed),
    do: {:error, :nxdomain}

  def query_nss([] = _nss, qry, opts, tstop, nth, failed),
    do: query_nss(Enum.reverse(failed), qry, opts, tstop, nth + 1, [])

  def query_nss([ns | nss], qry, opts, tstop, nth, failed) do
    # query_nss only queries the list of NSS for an acceptable response
    # resolve decides to continue with a new NSS list or not
    cond do
      timeout(tstop) == 0 ->
        {:error, :timeout}

      opts.retry < nth ->
        {:error, :timeout}

      true ->
        ns = unwrap(ns)

        case query_ns(ns, qry, opts, tstop, nth) do
          {:error, :timeout} ->
            log(opts.verbose, "- pushing #{inspect(ns)} onto failed list (:timeout)")
            query_nss(nss, qry, opts, tstop, nth, [wrap(ns, opts.srvfail_wait) | failed])

          {:error, reason} ->
            # :system_limit | :not_owner | :inet.posix() do not bode well for this ns
            log(opts.verbose, "- dropping #{inspect(ns)}, due to error: #{inspect(reason)}")
            query_nss(nss, qry, opts, tstop, nth, failed)

          {:ok, msg} ->
            # https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1
            # https://github.com/erlang/otp/blob/c55dc0d0a4a72fc59642aff186adde4621891cde/lib/kernel/src/inet_res.erl#L921
            case xrcode(msg) do
              rcode
              when rcode in [:FORMERROR, :NOTIMP, :REFUSED, :BADVERS] ->
                # ns either spoke in tongues or gave a somewhat hostile response, f^hskip it
                log(opts.verbose, "- dropping #{inspect(ns)}, due to error: #{rcode}")
                query_nss(nss, qry, opts, tstop, nth, failed)

              _ ->
                {:ok, msg}
            end
        end
    end
  end

  @spec query_ns(ns, msg, map, timeT, counter) :: {:ok, msg} | {:error, reason}
  def query_ns(ns, qry, opts, tstop, n) do
    # queries a single nameserver
    # [?] should we fallback to plain dns in case EDNS leads to BADVERS?
    bufsize = opts.bufsize
    timeout = opts.timeout
    payload = byte_size(qry.wdata)

    if payload > bufsize or opts.tcp do
      query_tcp(ns, qry, timeout, tstop)
    else
      udp_timeout = udp_timeout(timeout, opts.retry, n, tstop)

      case query_udp(ns, qry, udp_timeout, bufsize) do
        {:ok, rsp} when rsp.header.tc == 1 ->
          log(true, "- response truncated, switching to tcp")
          query_tcp(ns, qry, timeout, tstop)

        result ->
          result
      end
    end
  end

  @spec query_udp(ns, msg, timeout, non_neg_integer) :: {:ok, msg} | {:error, reason}
  def query_udp(_ns, _qry, 0, _bufsize),
    do: {:error, :timeout}

  def query_udp({ip, port}, qry, timeout, bufsize) do
    # query_udp_open protects against a process *exit* with :badarg
    {:ok, sock} = query_udp_open(ip, port, bufsize)

    with :ok <- :gen_udp.connect(sock, ip, port),
         :ok <- :gen_udp.send(sock, qry.wdata),
         {:ok, msg} <- query_udp_recv(sock, qry, timeout) do
      # note that:
      # - query_udp_open uses random src port for each query
      # - :gen_udp.connect ensure incoming data arrived at our src IP & port
      # - query_udp_recv ensures qry/msg ID's are equal and msg's qr=1
      # the higher ups will need to deal with how to handle the response
      :gen_udp.close(sock)
      {:ok, msg}
    else
      error ->
        :gen_udp.close(sock)
        log(true, "- udp socket error #{inspect(ip)}, #{inspect(error)}")
        error
    end
  rescue
    # when query_udp_open returns {:error, :badarg} (i.e. the term in e)
    e in MatchError -> e.term
  end

  @spec query_udp_open(:inet.ip_address(), non_neg_integer, non_neg_integer) ::
          {:ok, :gen_udp.socket()} | {:error, :system_limit | :badarg | :inet.posix()}
  def query_udp_open(ip, port, bufsize) do
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
      opts = [:binary, iptype, active: false, recbuf: bufsize]
      :gen_udp.open(0, opts)
    else
      false -> {:error, :badarg}
    end
  end

  @spec query_udp_recv(:inet.socket(), msg, timeout) :: {:ok, msg} | {:error, reason}
  def query_udp_recv(_sock, _qry, 0),
    do: {:error, :timeout}

  def query_udp_recv(sock, qry, timeout) do
    # - if it's no answer to the question, try again until timeout has passed
    # - sock is connected, so addr,port *should* be ok
    {:ok, {ip, p}} = :inet.peername(sock)
    ns = "#{Pfx.new(ip)}:#{p}/udp"
    log(true, "- resolving against #{ns}, timeout #{timeout} ms")
    tstart = now()
    tstop = time(timeout)

    with {:ok, {_addr, _p, rsp}} <- :gen_udp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- msg.header.id == qry.header.id,
         true <- msg.header.qr == 1 do
      t = now() - tstart
      b = byte_size(msg.wdata)
      log(true, "- received #{b} bytes in #{t} ms, from #{ns}")

      IO.inspect(valid?(qry, msg), label: :valid)
      {:ok, msg}
    else
      false -> query_udp_recv(sock, qry, timeout(tstop))
      other -> other
    end
  end

  @spec query_tcp(ns, msg, timeout, timeT) :: {:ok, msg} | {:error, reason}
  def query_tcp(_ns, _qry, 0, _tstop),
    do: {:error, :timeout}

  def query_tcp({ip, port}, qry, timeout, tstop) do
    # connect outside with block, so we can always close the socket
    {:ok, sock} = query_tcp_connect({ip, port}, timeout, tstop)
    t0 = now()

    with :ok <- :gen_tcp.send(sock, qry.wdata),
         {:ok, rsp} <- :gen_tcp.recv(sock, 0, timeout),
         {:ok, msg} <- Msg.decode(rsp),
         true <- msg.header.id == qry.header.id,
         true <- msg.header.qr == 1 do
      :gen_tcp.close(sock)
      t = now() - t0
      log(true, "- received #{byte_size(rsp)} bytes from #{Pfx.new(ip)}:#{port}/tcp in #{t} ms")
      {:ok, msg}
    else
      false ->
        {:error, :noreply}

      {:error, e} ->
        log(true, "- query_tcp error #{inspect(e)}")
        :gen_tcp.close(sock)
        {:error, e}
    end
  rescue
    # when query_tcp_connect returns {:error, any}
    e in MatchError -> e.term
  end

  @spec query_tcp_connect(ns, timeout, timeT) :: {:ok, :inet.socket()} | {:error, reason}
  def query_tcp_connect({ip, port}, timeout, tstop) do
    # avoid *exit* badarg by checking ip/port's validity
    log(true, "- query tcp: #{inspect(ip)}, #{port}/tcp, timeout #{timeout}")

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

  @spec make_response(msg, [DNS.Msg.RR.t()]) :: {:ok, msg}
  def make_response(qry, rrs) do
    # a synthesized answer:
    # - is created by copying & updating the vanilla qry msg
    # - has no wdata and id of 0
    # - aa=0, since we're not an authoritative source
    # - ra=1, since we're answering and recursion is available
    # Note: individual RR's *will* have wdata if they are raw RR's
    hdr = %{qry.header | anc: length(rrs), aa: 0, ra: 1, qr: 1, id: 0, wdata: ""}
    qtn = %{hd(qry.question) | wdata: ""}

    rsp = %{qry | header: hdr, question: [qtn], answer: rrs, wdata: ""}
    {:ok, rsp}
  end

  @spec make_query(binary, type, map) :: {:ok, msg} | {:error, any}
  def make_query(name, type, opts) do
    # assumes opts is safe (made by make_options)
    # https://community.cloudflare.com/t/servfail-from-1-1-1-1/578704/9
    # [ ] support class is CHAOS
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

    # TODO
    # [ ] hdr should take opcode as parameter that defaults to QUERY
    qtn_opts = [[name: name, type: type]]
    hdr_opts = [rd: opts.rd, cd: opts.cd, opcode: opts.opcode, id: Enum.random(0..65535)]

    case Msg.new(hdr: hdr_opts, qtn: qtn_opts, add: edns_opts) do
      {:ok, qry} -> Msg.encode(qry)
      {:error, e} -> {:error, e.data}
    end
  end

  # [[ OPTIONS ]]

  @spec make_options(Keyword.t()) :: {:ok, map} | {:error, binary}
  def make_options(opts \\ []) do
    opts2 = %{
      bufsize: Keyword.get(opts, :bufsize, 1280),
      cd: Keyword.get(opts, :cd, 0),
      do: Keyword.get(opts, :do, 0),
      edns: opts[:do] == 1 or opts[:bufsize] != nil,
      maxtime: Keyword.get(opts, :maxtime, 20_000),
      nameservers: Keyword.get(opts, :nameservers, @root_nss),
      opcode: Keyword.get(opts, :opcode, :QUERY) |> Terms.encode_dns_opcode(),
      rd: Keyword.get(opts, :rd, 0),
      recurse: opts[:nameservers] == nil,
      retry: Keyword.get(opts, :retry, 3),
      srvfail_wait: Keyword.get(opts, :srvfail_wait, 1500),
      tcp: Keyword.get(opts, :tcp, false),
      timeout: Keyword.get(opts, :timeout, 2000),
      verbose: Keyword.get(opts, :verbose, false)
    }

    cond do
      !check_nss(opts2.nameservers) -> {:error, "bad nameservers #{inspect(opts2.nameservers)}"}
      !(opts2.opcode in 0..15) -> {:error, "opcode not in 0..15"}
      !(opts2.srvfail_wait in 0..5000) -> {:error, "srvfail_wait not in 0..5000"}
      !is_boolean(opts2.verbose) -> {:error, "verbose should be true of false"}
      !is_u16(opts2.bufsize) -> {:error, "bufsize out of u16 range"}
      !(opts2.timeout in 0..5000) -> {:error, "timeout not in 0..5000"}
      !is_integer(opts2.maxtime) -> {:error, "maxtime should be positive integer"}
      !(opts2.maxtime > 0) -> {:error, "maxtime should be positive integer"}
      !(opts2.retry in 0..5) -> {:error, "retry not in range 0..5"}
      !is_boolean(opts2.tcp) -> {:error, "tcp should be true of false"}
      !(opts2.rd in 0..1) -> {:error, "rd bit should be 0 or 1"}
      !(opts2.do in 0..1) -> {:error, "do bit should be 0 or 1"}
      !(opts2.cd in 0..1) -> {:error, "cd bit should be 0 or 1"}
      true -> {:ok, opts2}
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

  @spec valid?(msg, msg) :: boolean
  def valid?(qry, rsp) do
    # See also https://datatracker.ietf.org/doc/html/rfc5452.html, section 9.1
    # - query_udp_open lets OS pick a random port
    # - query_udp connect ensures incoming data is from "connected" name server
    # - so here, check: ID, QR and compare question section
    # note: this says nothing about the contents of ans/aut/add sections
    cond do
      qry.header.id != rsp.header.id ->
        false

      rsp.header.qr != 1 ->
        false

      length(qry.question) != length(rsp.question) ->
        false

      true ->
        # can't compare wiredata directly.  Question section *could* contain
        # more than one question, in which case possible name compression would
        # make the wdata fields different.  Names in qry question already
        # normalized.  rsp's names MUST be normalized so sorting should equal
        # that of qry.
        ql =
          Enum.map(qry.question, fn q -> {q.name, q.type, q.class} end)
          |> Enum.sort()

        rl =
          Enum.map(rsp.question, fn r -> {elem(dname_normalize(r.name), 1), r.type, r.class} end)
          |> Enum.sort()

        Enum.zip(ql, rl)
        |> Enum.all?(fn {q, r} -> q == r end)
    end
  end

  @spec res_response_type(msg) :: :referral | :cname | :answer | :lame | :nodata
  def res_response_type(%{
        header: %{anc: 0, nsc: nsc, rcode: :NOERROR},
        question: [%{name: qname}],
        answer: [],
        authority: aut
      })
      when nsc > 0 do
    # see also
    # - https://datatracker.ietf.org/doc/html/rfc2308#section-2.1 (NAME ERROR)
    # - https://datatracker.ietf.org/doc/html/rfc2308#section-2.2 (NODATA)
    # note that by now, the msg's question is same as that of the query and a
    # proper referral has no SOA and relevant NS's in aut.
    match = fn zone -> dname_subdomain?(qname, zone) or dname_equal?(qname, zone) end

    case aut do
      [] ->
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

  def res_response_type(%{
        header: %{anc: anc, qdc: 1, rcode: :NOERROR},
        question: [%{type: qtype}],
        answer: ans
      })
      when anc > 0 do
    # see also
    # - https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2
    # - https://www.rfc-editor.org/rfc/rfc1034#section-4.3.2
    # - https://datatracker.ietf.org/doc/html/rfc2308#section-1
    # - https://datatracker.ietf.org/doc/html/rfc2181#section-10.1
    # * if query was for :CNAME, always qualify response as :answer
    # * if answer includes a :CNAME and some RR's of qtype, then we assume:
    #   - that ns is also authoritative for the cname, and
    #   - that the RR's with qtype are for the cname given
    #   otherwise the :answer would actually be :lame. For now that is
    #   up to the caller to detect/decide
    #   => TODO: should we check those RR's of qtype are for the cname?
    # * if answer includes a :CNAME and no RR's of qtype, then
    #   nameserver is not authoritative for zone of canonical name
    #   and `resolve` will have to follow up on the canonical name
    cname = Enum.any?(ans, fn rr -> rr.type == :CNAME end)
    wants = Enum.any?(ans, fn rr -> rr.type == qtype end)

    cond do
      qtype == :CNAME -> :answer
      wants -> :answer
      cname -> :cname
      true -> :lame
    end
  end

  def res_response_type(_),
    do: :answer

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
