defmodule MsgRR do
  # used in Answer, Authority, and Additional sections
  # Each RR (resource record) has the following format:
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                                               /
  #     /                      NAME                     /
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     CLASS                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      TTL                      |
  #     |                                               |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     RDLEN                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  #     /                     RDATA                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  # where:
  # - NAME     a length encoded owner domain name
  # - TYPE     16b, an RR TYPE code
  # - CLASS    16b, an RR CLASS code
  # - TTL      32b *signed* integer indicating max cache time
  #            TTL=0 means no caching: i.e. use RR only in current transaction
  # - RDLEN    16b, unsigned integer, is length in octets of the RDATA field.
  # - RDATA    depends on the TYPE/CLASS

  import DNS.Terms
  import DNS.Fields

  defstruct name: "",
            type: :A,
            class: :IN,
            ttl: 0,
            rdlen: 0,
            rdmap: %{},
            rdata: <<>>,
            wdata: <<>>

  @type class :: atom | non_neg_integer
  @type type :: atom
  @type offset :: non_neg_integer
  @type length :: non_neg_integer

  @typedoc """
  A `t:MsgRR.t/0` represents a single DNS RR (resource record).

  It's fields are:
  - `name`, the owner's domain name
  - `type`, the RR type, e.g. 1 to denote an A RR
  - `class`, the DNS class, usually 1 (for the `IN` class)
  - `ttl`, the time-to-live for this RR
  - `rdmap`, contains the decoded fields of `rdata`
  - `rdlen`, the number of octets in the `rdata` field
  - `rdata`, part of the RR's wireformat binary that contains the `rdata`
  - `wdata`, the RR's wireformat binary

  The `rdlen`, `rdata` and `wdata` fields are calculated and cannot be
  set via `put/1`, rather they are either taken from the wireformat binary
  when decoding or calculated from the other fields when encoding an RR.

  """
  @type t :: %__MODULE__{
          name: binary,
          type: type,
          class: class,
          ttl: non_neg_integer,
          rdlen: non_neg_integer,
          rdmap: map,
          rdata: binary,
          wdata: binary
        }

  # [[ HELPERS ]]
  defp error(reason, data),
    do: raise(MsgError.exception(reason: reason, data: data))

  defp to_num(_, <<>>, _, acc),
    do: acc |> Enum.reverse()

  defp to_num(w, <<0::1, rest::bitstring>>, n, acc),
    do: to_num(w, rest, n + 1, acc)

  defp to_num(w, <<1::1, rest::bitstring>>, n, acc),
    do: to_num(w, rest, n + 1, [decode_rr_type(w * 256 + n) | acc])

  # convert NSEC(3) bitmap to rr types covered
  defp bitmap_to_rrs(bin) do
    for <<w::8, len::8, bmap::binary-size(len) <- bin>> do
      to_num(w, bmap, 0, [])
    end
    |> List.flatten()
  end

  # [[ NEW ]]

  @spec new(Keyword.t()) :: t
  def new(opts \\ []),
    do: put(%__MODULE__{}, opts)

  # [[ PUT ]]
  @spec put(t(), Keyword.t()) :: t
  def put(rr, opts)

  def put(%__MODULE__{} = rr, opts) do
    {class, opts} = Keyword.pop(opts, :class, rr.class)
    {type, opts} = Keyword.pop(opts, :type, rr.type)
    type = decode_rr_type(type)

    rr = %{rr | class: class, type: type}

    # class might already be set to requestor's udp buffer size
    # so check only type (kinda obsoletes all NON-IN protocol families)
    if type == :OPT,
      do: do_edns(opts),
      else: Enum.reduce(opts, %{rr | rdata: <<>>, wdata: <<>>, rdlen: 0}, &do_put/2)
  end

  # skip calculated fields
  defp do_put({k, _v}, rr) when k in [:__struct__, :rdlen, :rdata, :wdata],
    do: rr

  # bypass for OPT RR whose dname="" and class=bufsize, ttl=coded flags
  defp do_put({k, v}, %__MODULE__{type: 41} = rr),
    do: Map.put(rr, k, v)

  defp do_put({k, v}, rr) when k == :name do
    # TODO: make & use dname_valid?(v)
    # - OPT RR has root name (either "" or "."), so need to accomodate that
    if [] != dname_to_labels(v),
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :type,
    do: Map.put(rr, k, decode_rr_type(v))

  defp do_put({k, v}, rr) when k == :class,
    do: Map.put(rr, k, v)

  # signed 32 bit range is -2**31..2**31
  defp do_put({k, v}, rr) when k == :ttl do
    if v in -2_147_483_648..2_147_483_648,
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :rdlen do
    if v in 0..65535,
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :rdmap and is_map(v),
    do: Map.put(rr, k, v)

  defp do_put({k, _v}, _rr),
    do: error(:field, "MsgRR has no #{inspect(k)} field")

  # [[ EDNS PSEUDO-RR ]]
  # https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  # IANA registries: EDNS OPTION CODEs, Header Flags, VERSION
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
  @doc """
  Creates a pseudo-RR for EDNS0 using the given `opts`.

  EDNS0 `opts` include:
  - `xrcode`, extended rcode, defaults to 0
  - `version`, defaults to 0 (the only valid value at the moment)
  - `do`, set or clear the DO-bit (DNSSEC OK bit)
  - `z`, defaults to 0 (currently the only defined value)
  - `bufsize`, the requestor's udp buffer size (default 1410, sets the RR's class)
  - `opts`, a list of EDNS0 options (`[{code, data}]`) to include (defaults to [])

  The first 4 options are encoded into the RR's `ttl` field, `bufsize` is used
  to set the `class` field.  Which is why this is a pseudo-RR.  The list of
  `opt` (if any) should contain `[{code, data}]`, see:
    [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
    for EDNS0 OPT codes of which currently only:
  - `3`, [NSID](https://www.rfc-editor.org/rfc/rfc5001#section-2.3)
  - `9`, [Expiry](https://www.rfc-editor.org/rfc/rfc7314.html#section-2)
  - `10`, [Cookie](https://www.rfc-editor.org/rfc/rfc7873.html#section-4)

  are implemented.
  """
  @spec do_edns(Keyword.t()) :: t
  def do_edns(opts) do
    type = :OPT
    class = Keyword.get(opts, :bufsize, 1410)

    # construct EDNS(0) TTL
    xrcode = Keyword.get(opts, :xrcode, 0)
    version = Keyword.get(opts, :version, 0)
    do_bit = Keyword.get(opts, :do, 1)
    z = Keyword.get(opts, :z, 0)
    <<ttl::32>> = <<xrcode::8, version::8, do_bit::1, z::15>>

    rdmap = Keyword.get(opts, :rdmap, %{})
    rdata = <<>>
    rdlen = 0
    wdata = <<>>

    # pseudo-rr: add information encoded in class & ttl to rdmap as well
    # even though it's not encoded in this rr's rdata
    rdmap =
      rdmap
      |> Map.put(:bufsize, class)
      |> Map.put(:xrcode, xrcode)
      |> Map.put(:do, do_bit)
      |> Map.put(:version, version)
      |> Map.put(:z, z)
      |> Map.put_new(:opts, [])

    %__MODULE__{
      name: "",
      type: type,
      class: class,
      ttl: ttl,
      rdlen: rdlen,
      rdmap: rdmap,
      rdata: rdata,
      wdata: wdata
    }
  end

  # [[ ENCODE RR ]]

  @spec encode(t) :: t
  def encode(%__MODULE__{} = rr) do
    name = encode_dname(rr.name)
    class = encode_dns_class(rr.class)
    type = encode_rr_type(rr.type)
    rdata = encode_rdata(rr.type, rr.rdmap)
    rdlen = byte_size(rdata)

    wdata = <<
      name::binary,
      type::16,
      class::16,
      rr.ttl::32,
      rdlen::16,
      rdata::binary
    >>

    %{rr | rdlen: rdlen, rdata: rdata, wdata: wdata}
  end

  # [[ ENCODE RDATA ]]
  @spec encode_rdata(type, map) :: binary
  def encode_rdata(type, rdmap)

  # empty rdmap means a query is being encoded
  def encode_rdata(_, rdmap) when map_size(rdmap) == 0,
    do: <<>>

  # IN A (1)
  def encode_rdata(:A, %{ip: {a, b, c, d}}),
    do: <<a::8, b::8, c::8, d::8>>

  # IN NS (2)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11
  def encode_rdata(:NS, %{name: name}),
    do: encode_dname(name)

  # IN CNAME (5)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1
  def encode_rdata(:CNAME, %{name: name}),
    do: encode_dname(name)

  # IN SOA (6)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
  def encode_rdata(:SOA, %{mname: mname, rname: rname, serial: serial} = rdmap) do
    rdmap =
      rdmap
      |> Map.put_new(:refresh, 14400)
      |> Map.put_new(:retry, 7200)
      |> Map.put_new(:expire, 1_209_600)
      |> Map.put_new(:minimum, 86400)

    mname = encode_dname(mname)
    rname = encode_dname(rname)

    <<mname::binary, rname::binary, serial::32, rdmap.refresh::32, rdmap.retry::32,
      rdmap.expire::32, rdmap.minimum::32>>
  end

  # IN PTR (12)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12
  def encode_rdata(:PTR, %{name: name}),
    do: encode_dname(name)

  # IN MX (15)
  def encode_rdata(:MX, %{name: name, pref: pref}),
    do: <<pref::16>> <> encode_dname(name)

  # IN TXT (16)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14
  def encode_rdata(:TXT, %{txt: data}) when is_list(data) do
    data
    |> Enum.map(fn txt -> to_string(txt) end)
    |> Enum.map(fn txt -> <<String.length(txt)::8, txt::binary>> end)
    |> Enum.join()
  end

  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14

  # IN AAAA (28)
  def encode_rdata(:AAAA, %{ip: {a, b, c, d, e, f, g, h}}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

  # IN OPT (41)
  # https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  def encode_rdata(:OPT, rdmap) do
    opts = Map.get(rdmap, :opts, [])
    for {code, data} <- opts, into: "", do: encode_edns_opt(code, data)
  end

  # IN DS (43)
  # https://www.rfc-editor.org/rfc/rfc4034#section-5
  def encode_rdata(:DS, %{keytag: k, algo: a, type: t, digest: d}),
    do: <<k::16, a::8, t::8, d::binary>>

  # IN RRSIG (46)
  # https://www.rfc-editor.org/rfc/rfc4034#section-3
  def encode_rdata(:RRSIG, rdmap) do
    type = encode_rr_type(rdmap.type)
    algo = rdmap.algo
    labels = rdmap.labels
    ttl = rdmap.ttl
    expire = rdmap.expiration
    incept = rdmap.inception
    keytag = rdmap.keytag
    name = encode_dname(rdmap.name)
    sig = rdmap.signature

    <<type::16, algo::8, labels::8, ttl::32, expire::32, incept::32, keytag::16, name::binary,
      sig::binary>>
  end

  # IN NSEC (47)
  # https://www.rfc-editor.org/rfc/rfc4034#section-4
  def encode_rdata(:NSEC, %{name: name, bitmap: bitmap}) do
    name = encode_dname(name)
    <<name::binary, bitmap::bitstring>>
  end

  # IN DNSKEY (48)
  # https://www.rfc-editor.org/rfc/rfc4034#section-2
  def encode_rdata(:DNSKEY, %{flags: flags, proto: proto, algo: algo, pubkey: key}),
    do: <<flags::16, proto::8, algo::8, key::binary>>

  # IN NSEC3 (50)
  # https://www.rfc-editor.org/rfc/rfc5155#section-3.2
  def encode_rdata(:NSEC3, %{
        algo: algo,
        flags: flags,
        iterations: iter,
        salt: salt,
        nxt_name: nxt,
        bitmap: bmap
      }) do
    <<algo::8, flags::8, iter::16, byte_size(salt), salt::binary, byte_size(nxt)::8, nxt::binary,
      bmap::binary>>
  end

  # IN NSEC3PARAM (51)
  # https://www.rfc-editor.org/rfc/rfc5155#section-4.1
  def encode_rdata(:NSEC3PARAM, %{
        algo: algo,
        flags: flags,
        iterations: iter,
        salt: salt
      }) do
    <<algo::8, flags::8, iter::16, byte_size(salt)::8, salt::binary>>
  end

  # IN TLSA (52)
  # https://www.rfc-editor.org/rfc/rfc6698#section-2
  def encode_rdata(:TLSA, %{usage: usage, selector: selector, type: type, data: data}),
    do: <<usage::8, selector::8, type::8, data::binary>>

  # IN CDS (59)
  # https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1
  # e.g. is dnsimple.zone
  def encode_rdata(:CDS, %{keytag: k, algo: a, type: t, digest: d}),
    do: <<k::16, a::8, t::8, d::binary>>

  # IN CDNSKEY (60)
  # https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2
  def encode_rdata(:CDNSKEY, %{flags: flags, proto: proto, algo: algo, pubkey: key}),
    do: <<flags::16, proto::8, algo::8, key::binary>>

  # IN HTTPS (65)
  # IN SPF (99)
  # IN ANY/* (255)

  # IN CAA (257)
  # https://www.rfc-editor.org/rfc/rfc8659#section-4
  def encode_rdata(:CAA, %{flags: flags, tag: tag, value: val}),
    do: <<flags::8, byte_size(tag)::8, tag::binary, val::binary>>

  ## [[ catch all ]]
  def encode_rdata(type, rdmap) do
    error(:notimp, "cannot encode #{type}: #{inspect(rdmap)}")
  end

  # [[ ENCODE EDNS0 opts (todo) ]]
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  @doc """
  Encodes an EDNS0 option to a binary.

  """
  @spec encode_edns_opt(non_neg_integer, any) :: binary
  def encode_edns_opt(code, data)

  def encode_edns_opt(3, data) when is_binary(data) do
    # https://www.rfc-editor.org/rfc/rfc5001
    # In a query, data is supposed to be ""
    len = byte_size(data)
    <<3::16, len::16, data::binary>>
  end

  def encode_edns_opt(9, data) do
    # https://www.rfc-editor.org/rfc/rfc7314.html#section-2
    <<9::16, 4::16, data::integer-size(32)>>
  end

  def encode_edns_opt(10, {client, server}) do
    # https://www.rfc-editor.org/rfc/rfc7873.html#section-4
    clen = byte_size(client)
    slen = byte_size(server)

    if clen == 8 and (slen == 0 or slen in 8..32) do
      len = clen + slen
      <<10::16, len::16, client::binary-size(clen), server::binary-size(slen)>>
    else
      if clen != 8,
        do: error(:eedns, "optcode 10, invalid client cookie #{inspect(client)}"),
        else: error(:eedns, "optcode 10, invalid server cookie #{inspect(server)}")
    end
  end

  # [[ DECODE RR ]]

  @spec decode(offset, binary) :: {offset, t}
  def decode(offset, msg) do
    {offset, name} = decode_dname(offset, msg)

    <<_::binary-size(offset), type::16, class::16, ttl::32, rdlen::16, rdata::binary-size(rdlen),
      _::binary>> = msg

    type = decode_rr_type(type)
    rr = MsgRR.new(name: name, type: type, class: class, ttl: ttl, rdlen: rdlen)
    # need to pass in rdlen as well, since some RR's may have rdlen of 0
    rdmap = decode_rdata(type, offset + 10, rdlen, msg)
    offset = offset + 10 + rdlen
    rr = %{rr | rdlen: rdlen, rdmap: rdmap, rdata: rdata, wdata: msg}

    {offset, rr}
  end

  # [[ DECODE RDATA ]]
  # note: decode_rdata always takes class, type, offset, rdlen and msg:
  # - class, type define RR-type whose rdata is to be decoded
  # - rdlen is needed since some RR's have rdlen of 0
  # - offset, msg is needed since rdata may contain compressed domain names

  @spec decode_rdata(type, offset, length, binary) :: map
  def decode_rdata(type, offset, rdlen, msg)

  # IN A (1)
  def decode_rdata(:A, offset, 4, msg) do
    <<_::binary-size(offset), a::8, b::8, c::8, d::8, _::binary>> = msg
    %{ip: {a, b, c, d}}
  end

  # IN NS (2)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11
  def decode_rdata(:NS, offset, _rdlen, msg) do
    {_, name} = decode_dname(offset, msg)
    %{name: name}
  end

  # IN CNAME (5)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1
  def decode_rdata(:CNAME, offset, _rdlen, msg) do
    {_, name} = decode_dname(offset, msg)
    %{name: name}
  end

  # IN SOA (6)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
  def decode_rdata(:SOA, offset, _rdlen, msg) do
    {offset, mname} = decode_dname(offset, msg)
    {offset, rname} = decode_dname(offset, msg)

    <<_::binary-size(offset), serial::32, refresh::32, retry::32, expire::32, minimum::32,
      _::binary>> = msg

    %{
      mname: mname,
      rname: rname,
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum
    }
  end

  # IN PTR (12)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12
  def decode_rdata(:PTR, offset, _rdlen, msg) do
    {_, name} = decode_dname(offset, msg)
    %{name: name}
  end

  # IN MX (15)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9
  def decode_rdata(:MX, offset, _rdlen, msg) do
    <<_::binary-size(offset), pref::16, _::binary>> = msg
    {_offset, name} = decode_dname(offset + 2, msg)
    %{name: name, pref: pref}
  end

  # IN TXT (16)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14
  def decode_rdata(:TXT, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    lines =
      for <<len::8, txt::binary-size(len) <- rdata>>,
        do: txt

    %{txt: lines}
  end

  # IN AAAA (28)
  def decode_rdata(:AAAA, offset, 16, msg) do
    <<_::binary-size(offset), a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, _::binary>> =
      msg

    %{ip: {a, b, c, d, e, f, g, h}}
  end

  # IN OPT (41) pseudo-rr
  # https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  def decode_rdata(:OPT, offset, _rdlen, msg) do
    # OPT RR's class is requestor's bufsize, so ignore it.
    # backup 8 bytes to the start of RR's class and ttl and decode those
    # and the rdlen & rdata fields as well
    offset_class = offset - 8

    <<_::binary-size(offset_class), bufsize::16, xrcode::8, version::8, do_bit::1, z::15,
      rdlen::16, rdata::binary-size(rdlen), _::binary>> = msg

    opts =
      for <<code::16, len::16, data::binary-size(len) <- rdata>>,
        do: decode_edns_opt(code, len, data)

    %{
      bufsize: bufsize,
      xrcode: xrcode,
      version: version,
      do: do_bit,
      z: z,
      opts: opts
    }
  end

  # IN DS (43)
  # https://www.rfc-editor.org/rfc/rfc4034#section-5
  def decode_rdata(:DS, offset, rdlen, msg) do
    # digest MUST be presented as case-insensitive hex digits
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<keytag::16, algo::8, type::8, digest::binary>> = rdata

    %{
      keytag: keytag,
      algo: algo,
      type: type,
      digest: digest
    }
  end

  # IN RRSIG (46)
  # https://www.rfc-editor.org/rfc/rfc4034#section-3
  def decode_rdata(:RRSIG, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<type::16, algo::8, labels::8, ttl::32, notafter::32, notbefore::32, keytag::16,
      rest::binary>> = rdata

    # no name compression allowed in RRSIG, so we stay within `rest`
    {offset, name} = decode_dname(0, rest)
    <<_::binary-size(offset), signature::binary>> = rest

    {:ok, notafter} = DateTime.from_unix(notafter, :second)
    {:ok, notbefore} = DateTime.from_unix(notbefore, :second)

    %{
      type: type,
      algo: algo,
      labels: labels,
      ttl: ttl,
      notafter: notafter,
      notbefore: notbefore,
      keytag: keytag,
      name: name,
      signature: signature
    }
  end

  # IN NSEC (47)
  # https://www.rfc-editor.org/rfc/rfc4034#section-4
  def decode_rdata(:NSEC, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    {offset, name} = decode_dname(0, rdata)
    <<_::binary-size(offset), bitmap::binary>> = rdata
    covers = bitmap_to_rrs(bitmap)
    %{name: name, bitmap: bitmap, covers: covers}
  end

  # IN DNSKEY (48)
  # https://www.rfc-editor.org/rfc/rfc4034#section-2
  def decode_rdata(:DNSKEY, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<flags::16, proto::8, algo::8, pubkey::binary>> = rdata

    keytype =
      case flags do
        256 -> "zsk"
        257 -> "ksk"
        _ -> "other"
      end

    keytag =
      rdata
      |> :binary.bin_to_list()
      |> Enum.with_index()
      |> Enum.map(fn {n, idx} -> if Bitwise.band(idx, 1) == 1, do: n, else: Bitwise.bsl(n, 8) end)
      |> Enum.sum()
      |> then(fn acc -> [acc, Bitwise.bsr(acc, 16) |> Bitwise.band(0xFFFF)] end)
      |> Enum.sum()
      |> Bitwise.band(0xFFFF)

    %{
      flags: flags,
      proto: proto,
      algo: algo,
      type: keytype,
      keytag: keytag,
      pubkey: pubkey
    }
  end

  # IN NSEC3 (50)
  # https://www.rfc-editor.org/rfc/rfc5155#section-3.2
  def decode_rdata(:NSEC3, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<algo::8, flags::8, iter::16, slen::8, salt::binary-size(slen), hlen::8,
      nxt_name::binary-size(hlen), bitmap::binary>> = rdata

    covers = bitmap_to_rrs(bitmap)

    %{
      algo: algo,
      flags: flags,
      iterations: iter,
      salt_len: slen,
      salt: salt,
      hash_len: hlen,
      next_name: nxt_name,
      bitmap: bitmap,
      covers: covers
    }
  end

  # IN NSEC3PARAM (51)
  # https://www.rfc-editor.org/rfc/rfc5155#section-4.1
  def decode_rdata(:NSEC3PARAM, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<algo::8, flags::8, iter::16, slen::8, salt::binary-size(slen)>> = rdata

    %{
      algo: algo,
      flags: flags,
      iterations: iter,
      salt_len: slen,
      salt: salt
    }
  end

  # IN TLSA (52)
  # https://www.rfc-editor.org/rfc/rfc6698#section-2
  def decode_rdata(:TLSA, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<usage::8, selector::8, type::8, data::binary>> = rdata

    %{
      usage: usage,
      selector: selector,
      type: type,
      data: data
    }
  end

  # IN CDS (59)
  # https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1
  # e.g. is dnsimple.zone
  def decode_rdata(:CDS, offset, rdlen, msg) do
    # digest MUST be presented as case-insensitive hex digits
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<keytag::16, algo::8, type::8, digest::binary>> = rdata

    %{
      keytag: keytag,
      algo: algo,
      type: type,
      digest: digest
    }
  end

  # IN CDNSKEY (60)
  # https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2
  def decode_rdata(:CDNSKEY, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<flags::16, proto::8, algo::8, pubkey::binary>> = rdata

    keytype =
      case flags do
        256 -> "zsk"
        257 -> "ksk"
        _ -> "other"
      end

    keytag =
      rdata
      |> :binary.bin_to_list()
      |> Enum.with_index()
      |> Enum.map(fn {n, idx} -> if Bitwise.band(idx, 1) == 1, do: n, else: Bitwise.bsl(n, 8) end)
      |> Enum.sum()
      |> then(fn acc -> [acc, Bitwise.bsr(acc, 16) |> Bitwise.band(0xFFFF)] end)
      |> Enum.sum()
      |> Bitwise.band(0xFFFF)

    %{
      flags: flags,
      proto: proto,
      algo: algo,
      type: keytype,
      keytag: keytag,
      pubkey: pubkey
    }
  end

  # IN HTTPS (65)
  # IN ANY/* (255)

  # IN CAA (257)
  # https://www.rfc-editor.org/rfc/rfc8659#section-4
  def decode_rdata(:CAA, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<flags::8, len::8, tag::binary-size(len), value::binary>> = rdata
    <<b0::1, _::bitstring>> = <<flags::8>>

    %{
      flags: flags,
      len: len,
      tag: tag,
      value: value,
      critical: b0 == 1
    }
  end

  ## [[ catch all ]]
  # we donot have a decoder, so simply return an empty map
  # caller has the chance to do their own decoding
  def decode_rdata(_, _, _, _),
    do: %{}

  # [[ DECODE ENDS0 opts ]]
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  @doc """
  Decode an EDNS option if we can, keep raw otherwise.

  """
  @spec decode_edns_opt(non_neg_integer, non_neg_integer, binary) :: {non_neg_integer, any}
  def decode_edns_opt(code, len, data)
  # Note: not sure if decode_ends_opt should get an offset & org msg binary
  # since some options might refer to other parts of the msg (e.g. name
  # compression)?  For now -> we simply decode based on (code, len, data)

  # NSID (3)
  # https://www.rfc-editor.org/rfc/rfc5001#section-2.3
  # could leave it up to the catch all, but hey! we're here aren't we
  def decode_edns_opt(3, _len, data),
    do: {3, data}

  # DAU (5), DHU (6), N3U (7)
  # https://www.rfc-editor.org/rfc/rfc6975.html#section-3

  # Expire (9)
  # https://www.rfc-editor.org/rfc/rfc7314.html#section-2
  def decode_edns_opt(9, len, data) do
    <<expiry::binary-size(4)>> = data

    if len != 4,
      do: IO.puts("EDNS Expiry option illegal len #{inspect(len)}")

    {9, expiry}
  end

  # Cookie (10)
  # https://www.rfc-editor.org/rfc/rfc7873.html#section-4
  def decode_edns_opt(10, len, data) do
    if len in 8..40 do
      <<client::binary-size(8), server::binary>> = data
      {10, {client, server}}
    else
      error(:eedns, "optcode 10, invalid DNS cookies in #{inspect(data)}")
    end
  end

  # catch all: keep what we donot understand as raw values
  def decode_edns_opt(code, _, data),
    do: {code, data}
end

defimpl Inspect, for: MsgRR do
  import DNS.Terms

  def inspect(rr, opts) do
    syntax_colors = IO.ANSI.syntax_colors()
    opts = Map.put(opts, :syntax_colors, syntax_colors)
    class = if rr.type == :OPT, do: "requestor's bufsize", else: :IN

    # presentation of some rdmap's values
    rr =
      case rr.type do
        # follow drill's example of lower-cased hex digits
        :DS -> put_in(rr.rdmap.digest, Base.encode16(rr.rdmap.digest, case: :lower))
        :CDS -> put_in(rr.rdmap.digest, Base.encode16(rr.rdmap.digest, case: :lower))
        :RRSIG -> put_in(rr.rdmap.signature, Base.encode64(rr.rdmap.signature))
        :TLSA -> put_in(rr.rdmap.data, Base.encode16(rr.rdmap.data, case: :lower))
        _ -> rr
      end

    rr
    |> Map.put(:type, "#{encode_rr_type(rr.type)} (#{rr.type})")
    |> Map.put(:class, "#{rr.class} (#{class})")
    |> Inspect.Any.inspect(opts)
  end
end
