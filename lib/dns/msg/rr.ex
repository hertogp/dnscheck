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

  # defaults A (type=1), IN (class=1), ttl 0, rdlen=0, rdata="", rdmap=empty
  defstruct dname: "",
            type: 1,
            class: 1,
            ttl: 0,
            rdlen: 0,
            rdmap: %{},
            rdata: <<>>,
            wdata: <<>>

  @type class :: non_neg_integer
  @type type :: non_neg_integer
  @type offset :: non_neg_integer
  @type length :: non_neg_integer

  @typedoc """
  A `t:MsgRR.t/0` represents a single DNS RR (resource record).

  It's fields are:
  - `dname`, the owner's domain name
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
          dname: binary,
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

  # [[ new ]]

  @spec new(Keyword.t()) :: t
  def new(opts \\ []) do
    case Keyword.get(opts, :type) do
      41 -> encode_edns(opts)
      _ -> put(%__MODULE__{}, opts)
    end
  end

  # [[ put ]]
  @spec put(t(), Keyword.t()) :: t
  def put(rr, opts)

  def put(%__MODULE__{} = rr, opts),
    do: Enum.reduce(opts, %{rr | rdata: <<>>, wdata: <<>>, rdlen: 0}, &do_put/2)

  # skip calculated fields
  defp do_put({k, _v}, rr) when k in [:__struct__, :rdlen, :rdata, :wdata],
    do: rr

  defp do_put({k, v}, rr) when k == :dname do
    # TODO: make & use dname_valid?(v)
    if [] != dname_to_labels(v),
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :type do
    if encode_dns_type(v),
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :class do
    if encode_dns_class(v) != nil,
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

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

  # [[ ENCODE RR ]]

  @spec encode(t) :: t
  def encode(%__MODULE__{} = rr) do
    dname = encode_dname(rr.dname)
    rdata = encode_rdata(rr.type, rr.class, rr.rdmap)
    rdlen = byte_size(rdata)

    wdata = <<
      dname::binary,
      rr.type::16,
      rr.class::16,
      rr.ttl::32,
      rdlen::16,
      rdata::binary
    >>

    %{rr | rdata: rdata, wdata: wdata}
  end

  # [[ ENCODE RDATA ]]
  @spec encode_rdata(class, type, map) :: binary
  def encode_rdata(class, type, rdmap)

  # IN A (1)
  def encode_rdata(1, 1, %{ip: {a, b, c, d}}),
    do: <<a::8, b::8, c::8, d::8>>

  # IN NS (2)
  def encode_rdata(1, 2, %{nsname: name}),
    do: encode_dname(name)

  # IN CNAME (5)
  def encode_rdata(1, 5, %{cname: dname}),
    do: encode_dname(dname)

  # IN SOA (6)
  # IN PTR (12)
  # IN MX (15)
  # IN TXT (16)

  # IN AAAA (28)
  def encode_rdata(1, 28, %{ip: {a, b, c, d, e, f, g, h}}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

  # IN OPT (41)
  def encode_rdata(1, 41, rdmap) do
    opts = Map.get(rdmap, :opts, [])

    for {optcode, optlen, optdta} <- opts do
      <<optcode::16, optlen::16, optdta::binary>>
    end
    |> Enum.join()
  end

  # EDNS0 Options:
  #               +0 (MSB)                            +1 (LSB)
  #    +---+---+---+---+---+---+---+---|---+---+---+---+---+---+---+---+
  # 0: |                          OPTION-CODE                          |
  #    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  # 2: |                         OPTION-LENGTH                         |
  #    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  # 4: |                                                               |
  #    /                          OPTION-DATA                          /
  #    /                                                               /
  #    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  # Placed anywhere in the Additional section, MUST be the only one
  # DNS msg with 2 or more OPT RR MUST result in FORMERR
  # 0 or more of:
  # - 16b, option code
  # - 16b, optlen (octets), i.e. option length
  # - nnb, optdta bytes
  # ordering of options is irrelevant to their meaning/interaction
  # an option code's not understood MUST be ignored

  # IN RRSIG (46)
  # IN NSEC (47)
  # IN DNSKEY (48)
  # IN NSEC3 (50)
  # IN NSEC3PARAM (51)
  # IN TLSA (52)
  # IN CDS (59)
  # IN CDNSKEY (60)
  # IN HTTPS (65)
  # IN SPF (99)
  # IN ANY/* (255)

  ## [[ catch all ]]
  # we donot have an encoder, so simply return empty binary
  # caller may have the chance to do their own encoding
  def encode_rdata(_, _, _),
    do: <<>>

  # [[ DECODE RR ]]

  @spec decode(offset, binary) :: {offset, t}
  def decode(offset, msg) do
    {offset, dname} = decode_dname(offset, msg)

    <<_::binary-size(offset), type::16, class::16, ttl::32, rdlen::16, rdata::binary-size(rdlen),
      _::binary>> = msg

    rr = MsgRR.new(dname: dname, type: type, class: class, ttl: ttl, rdlen: rdlen)
    # need to pass in rdlen as well, since some RR's may have rdlen of 0
    rdmap = decode_rdata(class, type, offset + 10, rdlen, msg)
    offset = offset + 10 + rdlen
    rr = %{rr | rdlen: rdlen, rdmap: rdmap, rdata: rdata, wdata: msg}

    case rr.type do
      41 -> {offset, decode_edns(rr)}
      _ -> {offset, rr}
    end
  end

  # [[ DECODE RDATA ]]
  # note: decode_rdata always takes class, type, offset and msg, since the
  #       rdata may contain a domain name that uses dname compression.
  #       e.g. www.domain.tld  IN CNAME  domain.tld
  @spec decode_rdata(class, type, offset, length, binary) :: map
  def decode_rdata(class, type, offset, rdlen, msg)

  # IN A
  def decode_rdata(1, 1, offset, 4, msg) do
    <<_::binary-size(offset), a::8, b::8, c::8, d::8, _::binary>> = msg
    %{ip: {a, b, c, d}}
  end

  # IN NS (2)
  def decode_rdata(1, 2, offset, _rdlen, msg) do
    {_, name} = decode_dname(offset, msg)
    %{nsname: name}
  end

  # IN CNAME (5)
  def decode_rdata(1, 5, offset, _rdlen, msg) do
    {_, name} = decode_dname(offset, msg)
    %{cname: name}
  end

  # IN SOA (6)
  def decode_rdata(1, 6, offset, _rdlen, msg) do
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
  # IN MX (15)
  # IN TXT (16)

  # IN AAAA (28)
  def decode_rdata(1, 28, offset, 16, msg) do
    <<_::binary-size(offset), a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, _::binary>> =
      msg

    %{ip: {a, b, c, d, e, f, g, h}}
  end

  # IN OPT (41)
  # IN RRSIG (46)
  # IN NSEC (47)
  # IN DNSKEY (48)
  # IN NSEC3 (50)
  # IN NSEC3PARAM (51)
  # IN TLSA (52)
  # IN CDS (59)
  # IN CDNSKEY (60)
  # IN HTTPS (65)
  # IN SPF (99)
  # IN ANY/* (255)

  ## [[ catch all ]]
  # we donot have a decoder, so simply return an empty map
  # caller has the chance to do their own decoding
  def decode_rdata(_, _, _, _, _),
    do: %{}

  # [[ ENDS PSEUDO-RR ]]
  # https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  #
  # NAME  domain name   MUST be root
  # TYPE  16b unsigned  41
  # CLASS 16b unsigned  requestor's UDP payload size
  # TTL   32b unsigned  extended RCODE, version and flags (DO, Z)
  # RDLEN 16b unsigned  length of all RDATA
  # RDATA octs stream   see below
  #
  # IANA registries: EDNS OPTION CODEs, Header Flags, VERSION
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
  #
  # TTL = The extended RCODE and flags, which OPT stores in the RR Time to Live
  # (TTL) field, are structured as follows:
  #
  #                +0 (MSB)                            +1 (LSB)
  #     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #  0: |         EXTENDED-RCODE        |            VERSION            |
  #     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #  2: | DO|                           Z                               |
  #     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  # EXTENDED-RCODE (upper) 8b, of a 12b RCODE, lower 4b is regular RCODE
  #                a value of 0 means unextended RCODE is being used.
  # VERSION 8b, 0 means fully supported, otherwise n = level of support of
  #             requestor.  If responder does not support VERSION level of
  #             requestor, it MUST respond with RCODE=BADVERS
  # DO 1b, DNSSEC OK bit, 1=OK, 0=NOK (RFC3225)
  # Z 15b, MUST be 0 at the moment
  #
  @spec encode_edns(Keyword.t()) :: t
  def encode_edns(opts \\ []) do
    type = 41
    # https://www.rfc-editor.org/rfc/rfc6891#section-6.2.3
    class = Keyword.get(opts, :bufsize, 1410)

    # construct EDNS(0) TTL
    # TODO: enforce that version & z MUST be zero
    ext_rcode = Keyword.get(opts, :ext_rcode, 0)
    version = Keyword.get(opts, :version, 0)
    do_bit = Keyword.get(opts, :do, 1)
    z = Keyword.get(opts, :z, 0)
    <<ttl::32>> = <<ext_rcode::8, version::8, do_bit::1, z::15>>

    rdmap = Keyword.get(opts, :rdmap, %{})
    rdata = encode_rdata(1, 41, rdmap)
    rdlen = byte_size(rdata)

    # pseudo-rr: add information encoded in class & ttl to rdmap as well
    # even though its not encoded in this rr's rdata
    rdmap =
      rdmap
      |> Map.put(:bufsize, class)
      |> Map.put(:ext_rcode, ext_rcode)
      |> Map.put(:do, do_bit)
      |> Map.put(:version, version)
      |> Map.put(:z, z)
      |> Map.put_new(:opts, [])

    wdata = <<
      0,
      type::16,
      class::16,
      ttl::32,
      rdlen::16,
      rdata::binary
    >>

    %__MODULE__{
      dname: "",
      type: type,
      class: class,
      ttl: ttl,
      rdlen: rdlen,
      rdmap: rdmap,
      rdata: rdata,
      wdata: wdata
    }
  end

  @spec decode_edns(t) :: t
  def decode_edns(%__MODULE__{type: 41} = rr) do
    bufsize = rr.class
    <<ext_rcode::8, version::8, do_bit::1, z::15>> = <<rr.ttl::32>>

    rdmap =
      Map.get(rr, :rdmap, %{})
      |> Map.put(:bufsize, bufsize)
      |> Map.put(:ext_rcode, ext_rcode)
      |> Map.put(:version, version)
      |> Map.put(:do, do_bit)
      |> Map.put(:z, z)
      |> Map.put_new(:opts, [])

    %{rr | rdmap: rdmap}
  end
end
