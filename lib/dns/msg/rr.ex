defmodule DNS.Msg.RR do
  @moduledoc """
  Low level functions to create, encode or decode an `RR` `t:t/0` struct.

  Resource Records (RRs) are found in the Answer, Authority, and Additional
  sections of a DNS message.

  Each RR has the following format:

  ```
         0  1  2  3  4  5  6  7  8  9  0 11 12 13 14 15
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       /                      NAME                     /
       /                                               /
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                      TYPE                     |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                     CLASS                     |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                      TTL                      |
       |                                               |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                     RDLEN                     |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
       /                     RDATA                     /
       /                                               /
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ```
  where:
  - `NAME`,     is a length encoded owner domain name
  - `TYPE`,     is a 16 bit unsigned integer, an RR TYPE code
  - `CLASS`,    is a 16 bit unsigned integer, usually an RR CLASS code
  - `TTL`,      is a 32 bit unsigned integer, range 0..214748364, see [rfc2181](https://www.rfc-editor.org/rfc/rfc2181#section-8)
  - `RDLEN`,    is a 16 bit unsigned integer, the length in octets of the RDATA field.
  - `RDATA`,    interpretation depends on the RR TYPE and CLASS

  """

  # TODO:
  # - add rfc references
  # - https://www.rfc-editor.org/rfc/rfc5890 (Internationlized Domain Names for
  #   Applications (IDNA)
  # - https://www.rfc-editor.org/rfc/rfc2181 (clarifications)
  # - https://www.rfc-editor.org/rfc/rfc2673 (binary labels)
  # - https://www.rfc-editor.org/rfc/rfc6891 (EDNS0)
  #
  #   <<0xb2,0x7f,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x77,0x77,0x77,0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x1c,0x00,0x01>>

  import DNS.Msg.Terms
  import DNS.Msg.Fields
  alias DNS.Msg.Error

  @user DNS.Msg.RR.User

  defstruct name: "",
            type: :A,
            class: :IN,
            ttl: 0,
            rdlen: 0,
            rdmap: %{},
            rdata: <<>>,
            wdata: <<>>

  @typedoc "The DNS RR's class, either a number or a [known name](`DNS.Msg.Terms.encode_dns_class/1`)"
  @type class :: atom | non_neg_integer

  @typedoc "The DNS RR's type, either a number or a [known name](`DNS.Msg.Terms.encode_rr_type/1`)"
  @type type :: atom | non_neg_integer

  @typedoc "A non negative offset into a DNS message."
  @type offset :: non_neg_integer

  @typedoc "a non negative number indicating the length of `rdata`"
  @type length :: non_neg_integer

  @typedoc """
  A `RR` `t:t/0` struct represents a single DNS RR (resource record).

  It's fields are:
  - `name`, the owner's domain name (default "")
  - `type`, the RR type (default `:A`)
  - `class`, the DNS class (default `:IN`)
  - `ttl`, the time-to-live for this RR (default 0)
  - `rdmap`, contains the (decoded) key,value-pairs of `rdata` (default `%{}`)
  - `rdlen`, the number of octets in the `rdata` field (default 0)
  - `rdata`, RR's rdata in wireformat (default `<<>>`)
  - `wdata`, the RR's wireformat binary (default `<<>>`)

  """
  @type t :: %__MODULE__{
          name: binary,
          type: type,
          class: class,
          ttl: non_neg_integer,
          rdmap: map,
          rdlen: non_neg_integer,
          rdata: binary,
          wdata: binary
        }

  # [[ GUARDS ]]

  import DNS.Guards

  # [[ HELPERS ]]
  defp error(reason, data),
    do: raise(Error.exception(reason: reason, data: data))

  # NSEC (3) bitmap conversion to list of RR type numbers
  defp bitmap_2_nrs(_, <<>>, _, acc),
    do: acc |> Enum.reverse()

  defp bitmap_2_nrs(w, <<0::1, rest::bitstring>>, n, acc),
    do: bitmap_2_nrs(w, rest, n + 1, acc)

  defp bitmap_2_nrs(w, <<1::1, rest::bitstring>>, n, acc),
    do: bitmap_2_nrs(w, rest, n + 1, [w * 256 + n | acc])

  def bitmap_to_rrs(bin) do
    for <<w::8, len::8, bmap::binary-size(len) <- bin>> do
      bitmap_2_nrs(w, bmap, 0, [])
    end
    |> List.flatten()
    |> Enum.map(fn n -> decode_rr_type(n) end)
  end

  # convert NSEC(3) bitmap to rr types covered
  # - https://www.rfc-editor.org/rfc/rfc4034#section-4.1.2
  # RR type = u16

  # The RR type space is split into 256 window blocks, each representing
  # the low-order 8 bits of the 16-bit RR type space.
  # Each block that has at least one active RR type is encoded using
  # a. a single octet window number (from 0 to 255),
  # b. a single octet bitmap length (from 1 to 32)
  #    indicating the number of octets used for the window block's bitmap,
  # c. a bitmap of up to 32 octets (256 bits).

  # 1. Each bitmap encodes the low-order 8 bits of RR types within the
  #    window block, in network bit order. The first bit is bit 0 (ie msb)
  # 2. For window block 0,
  #    - bit 0 corresponds to RR type 0 (RESERVED)
  #    - bit 1 corresponds to RR type 1 (A),
  #    - bit 2 corresponds to RR type 2 (NS), and so forth.
  # 3. For window block 1,
  #    - bit 0 corresponds to RR type 256 (URI)
  #    - bit 1 corresponds to RR type 257, and
  #    - bit 2 to RR type 258.
  # 4. If a bit is set, it indicates that an RRset of that type is present
  #    for the NSEC RR's owner name.
  # 5. If a bit is clear, it indicates that no RRset of that type is present
  #    for the NSEC RR's owner name.
  # 6. Bits representing pseudo-types MUST be clear, as they do not appear
  #    in zone data.  If encountered, they MUST be ignored upon being read.
  # 7. Blocks with no types present MUST NOT be included.
  # 8. Trailing zero octets in the bitmap MUST be omitted.
  # 9. The length of each block's bitmap is determined by the type code with
  #    the largest numerical value, within that block, among the set of RR
  #    types present at the NSEC RR's owner name.
  # 10.Trailing zero octets not specified MUST be interpreted as zero octets.

  def bitmap_expand(bits, n) do
    fill = n - bit_size(bits)
    <<bits::bitstring, 0::size(fill), 1::1>>
  end

  def bitmap_pad(bmap) when rem(bit_size(bmap), 8) == 0,
    do: bmap

  def bitmap_pad(bmap),
    do: bitmap_pad(<<bmap::bitstring, 0::1>>)

  def bitmap_block(w, nrs) do
    bmap =
      nrs
      |> Enum.map(fn n -> n - w * 256 end)
      |> Enum.reduce(<<>>, fn n, acc -> bitmap_expand(acc, n) end)
      |> bitmap_pad()

    {w, byte_size(bmap), bmap}
  end

  def bitmap_4_rrs(rrs) do
    # TODO: maybe filter out pseudo-RR's: ANY (255), AXFR (252), IXFR (251), OPT (41)
    # or leave that up to the caller so experimentation remains possible
    Enum.map(rrs, fn n -> encode_rr_type(n) end)
    |> Enum.sort(:asc)
    |> Enum.group_by(fn n -> div(n, 256) end)
    |> Enum.map(fn {w, nrs} -> bitmap_block(w, nrs) end)
    |> Enum.map(fn {w, l, b} -> <<w::8, l::8, b::binary>> end)
    |> Enum.join()
  end

  # used to check rdmap for mandatory fields when encoding an RR
  # convencience func that also gives consistent, clear error messages
  defp required(type, map, field, check \\ fn _ -> true end) do
    v = Map.get(map, field) || error(:erdmap, "#{type} RR missing #{field}, got: #{inspect(map)}")

    if check.(v),
      do: v,
      else: error(:erdmap, "#{type} RR, field #{inspect(field)} has invalid value: #{inspect(v)}")
  end

  # [[ NEW ]]

  @doc """
  Creates an `RR` `t:t/0` struct for given `opts`.

  Known options include:
  - `:name`, must be a binary (default `""`)
  - `:type`, an [atom](`DNS.Msg.Terms.encode_rr_type/1`) or an unsigned 16 bit number (default `:A`)
  - `:class`, an [atom](`DNS.Msg.Terms.encode_dns_class/1`) or an unsigned 16 bit number (default `:IN`)
  - `:ttl`, a unsigned 32 bit integer (default `0`)
  - `:rdmap`, a map with `key,value`-pairs (to be encoded later, default `%{}`)

  Anything else is silently ignored, including `:rdlen`, `:rdata` and `:wdata`
  since those fields are set when decoding a DNS message or encoding an RR
  struct.  The `:rdmap`, if provided, is set as-is.  Its `key,value`-pairs
  are checked upon invoking `encode/1`.

  The `:type` option takes either a number or a known [name](`DNS.Msg.Terms.encode_rr_type/1`).
  A number will be replaced by its known name (if possible), which makes it
  easier when inspecting an RR. The same holds true for `:class`
  [names](`DNS.Msg.Terms.encode_dns_class/1`).

  ## [EDNS0](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2)

  The EDNS0 pseudo-RR (type: :OPT (41)) is a little bit different and
  recognizes only these options:

  - `:xrcode`, an 8 bit unsigned integer (or known [name](`DNS.Msg.Terms.encode_dns_rcode/1`), default 0)
  - `:version`, an 8 bit unsigned integer (default 0)
  - `:do`, EDNS0's DNSSEC OK bit, either 0 or 1 (default 1).
  - `:z`, a 15 bit unsigned integer (default 0)
  - `:bufsize`, 16 bit unsigned integer denoting requestor's udp recv buffer size (default 1410)
  - `:opts`, a list of `[{code, rdata}]` options.

  The first 4 options are encoded in the pseudo-RR's `:ttl`-field.
  The `:bufsize` option is stored in the pseudo-RR's `:class`-field.

  Some [EDNS0
  options](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
  can also be specified by [name](`DNS.Msg.Terms.encode_rropt_code/1`) but only
  a small set is currently supported by this library: `:NSID`, `COOKIE` and `EXPIRE`.

  These options are also listed in the RR's `rdmap`, even though they're not part
  of the pseudo-RR's `rdata`.


  ## Examples

      # default values, while ignoring some fields
      iex> new(rdata: "ignored", wdata: "ignored", unknown: "ignored")
      %DNS.Msg.RR{
        name: "",
        type: :A,
        class: :IN,
        ttl: 0,
        rdlen: 0,
        rdmap: %{},
        rdata: "",
        wdata: ""
      }

      iex> new(type: :AAAA, name: "example.com", rdmap: %{ip: "acdc:1971::1"})
      %DNS.Msg.RR{
        name: "example.com",
        type: :AAAA,
        class: :IN,
        ttl: 0,
        rdlen: 0,
        rdmap: %{ip: "acdc:1971::1"},
        rdata: "",
        wdata: ""
      }

      # EDNS0 pseudo-RR
      iex> new(type: :OPT, bufsize: 1410, xrcode: 16, do: 1)
      %DNS.Msg.RR{
        name: "",
        type: :OPT,
        class: 1410,
        ttl: 268468224,
        rdlen: 0,
        rdmap: %{bufsize: 1410, do: 1, opts: [], version: 0, xrcode: :BADVERS, z: 0},
        rdata: "",
        wdata: ""
      }

      iex> new(name: 123)
      ** (DNS.Msg.Error) [invalid dname] "123"

  """
  @spec new(Keyword.t()) :: t
  def new(opts \\ []),
    do: put(%__MODULE__{}, opts)

  # [[ PUT ]]

  @doc """
  Sets `RR` `t:t/0` fields for given `opts`, if the key refers to a field.

  Ignores unknown options as well as the `rdlen`, `rdata` and `wdata` options.
  Those fields are set upon decoding a DNS message binary or when encoding an
  RR struct.  Note that whenever `put/2` is used, the `rdlen`, `rdata` and
  `wdata` fields are cleared.

  Raises `DNS.Msg.Error` if a value is out of bounds.

  See `new/1` for possible options and when using `type: 41` as an option.

  ## Examples

      iex> new() |> put(name: "example.com", type: :NS)
      %DNS.Msg.RR{
        name: "example.com",
        type: :NS,
        class: :IN,
        ttl: 0,
        rdlen: 0,
        rdmap: %{},
        rdata: "",
        wdata: ""
      }

      iex> new() |> put(type: 65536)
      ** (DNS.Msg.Error) [invalid RR type] "valid range is 0..65535, got: 65536"

  """
  @spec put(t(), Keyword.t()) :: t
  def put(rr, opts)

  def put(%__MODULE__{} = rr, opts) do
    # ensure (native) decode_rdata func's can match on type as an atom
    {type, opts} = Keyword.pop(opts, :type, rr.type)
    type = decode_rr_type(type)

    rr = %{rr | type: type}

    # class might already be set to requestor's udp buffer size
    # so check only type (kinda obsoletes all NON-IN protocol families)
    if type == :OPT,
      do: do_edns(opts),
      else: Enum.reduce(opts, %{rr | rdata: <<>>, wdata: <<>>, rdlen: 0}, &do_put/2)
  end

  # skip calculated fields, note: :type is popped in put/2
  defp do_put({k, _v}, rr) when k in [:__struct__, :rdlen, :rdata, :wdata],
    do: rr

  defp do_put({k, v}, rr) when k == :name do
    if dname_valid?(v),
      do: Map.put(rr, k, v),
      else: error(:edname, "#{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :class do
    if is_u16(encode_dns_class(v)),
      do: Map.put(rr, k, decode_dns_class(v)),
      else: error(:evalue, "#{k}, got: #{inspect(v)}")
  end

  # signed 32 bit range is -(2**31)..(2**31-1)
  # rfc1035, 3.2.1 says its a 32 bit signed integer, and erlang seems to agree:
  # - https://github.com/dnsimple/dns_erlang/blob/main/src/dns.erl#L236C48-L236C61
  defp do_put({k, v}, rr) when k == :ttl do
    if is_u32(v),
      do: Map.put(rr, k, v),
      else: error(:evalue, "#{k}, got #{inspect(v)}")
  end

  defp do_put({k, v}, rr) when k == :rdmap do
    if is_map(v),
      do: Map.put(rr, k, v),
      else: error(:erdmap, "expected a map, got: #{inspect(v)}")
  end

  # ignore unknown options
  defp do_put(_, rr),
    do: rr

  # [[ EDNS PSEUDO-RR ]]
  # https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  # IANA registries: EDNS OPTION CODEs, Header Flags, VERSION
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
  # @doc """
  # Creates a pseudo-RR for EDNS0 using the given `opts`.
  #
  # EDNS0 `opts` include:
  # - `xrcode`, extended rcode, defaults to 0
  # - `version`, defaults to 0 (the only valid value at the moment)
  # - `do`, set or clear the DO-bit (DNSSEC OK bit)
  # - `z`, defaults to 0 (currently the only defined value)
  # - `bufsize`, the requestor's udp buffer size (default 1410, sets the RR's class)
  # - `opts`, a list of EDNS0 options (`[{code, data}]`) to include (defaults to [])
  #
  # The first 4 options are encoded into the RR's `ttl` field, `bufsize` is used
  # to set the `class` field.  Which is why this is a pseudo-RR.  The list of
  # `opt` (if any) should contain `[{code, data}]`, see:
  #   [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
  #   for EDNS0 OPT codes of which currently only:
  # - `3`, [NSID](https://www.rfc-editor.org/rfc/rfc5001#section-2.3)
  # - `9`, [Expiry](https://www.rfc-editor.org/rfc/rfc7314.html#section-2)
  # - `10`, [Cookie](https://www.rfc-editor.org/rfc/rfc7873.html#section-4)
  #
  # are implemented.
  # """
  @spec do_edns(Keyword.t()) :: t
  defp do_edns(opts) do
    type = :OPT
    class = Keyword.get(opts, :bufsize, 1410)

    unless is_u16(class),
      do: error(:erdmap, "bufsize range is 0..65535, got: #{inspect(class)}")

    # construct EDNS(0) TTL
    xrcode = Keyword.get(opts, :xrcode, 0) |> encode_dns_rcode()
    version = Keyword.get(opts, :version, 0)
    do_bit = Keyword.get(opts, :do, 1)
    z = Keyword.get(opts, :z, 0)

    ttl =
      with true <- is_u8(xrcode),
           true <- is_u8(version),
           true <- do_bit in 0..1,
           true <- z in 0..32767 do
        <<ttl::32>> = <<xrcode::8, version::8, do_bit::1, z::15>>
        ttl
      else
        _ -> error(:erdmap, "invalid value(s) in #{inspect(opts)}")
      end

    # get opts options
    edns_opts = Keyword.get(opts, :opts, [])

    unless Keyword.keyword?(edns_opts),
      do: error(:erdmap, "ENDS0 opts should be list of {CODE, DATA}, got: %#{inspect(edns_opts)}")

    edns_opts = edns_opts |> Enum.map(fn {opt, dta} -> {decode_rropt_code(opt), dta} end)

    # pseudo-rr: add information encoded in class & ttl to rdmap as well
    # even though it's not encoded in this rr's rdata
    rdmap =
      Keyword.get(opts, :rdmap, %{})
      |> Map.put(:bufsize, class)
      |> Map.put(:xrcode, decode_dns_rcode(xrcode))
      |> Map.put(:do, do_bit)
      |> Map.put(:version, version)
      |> Map.put(:z, z)
      |> Map.put_new(:opts, edns_opts)

    %__MODULE__{
      name: "",
      type: type,
      class: class,
      ttl: ttl,
      rdlen: 0,
      rdmap: rdmap,
      rdata: <<>>,
      wdata: <<>>
    }
  end

  # [[ ENCODE RR ]]
  # https://www.rfc-editor.org/rfc/rfc2181#section-8  (ttl is 32bit, 0..2**31 - 1)

  @doc ~S"""
  Sets the `:rdata` (resource data), `:rdlen` and `:wdata` (wire data) fields of the `RR` `t:t/0` struct.

  This requires the `:rdmap` to have the correct `key,value`-pairs for given
  `RR` `:type`. Missing `key,value`-pairs or invalid values will cause a
  `DNS.Msg.Error` to be raised.

  The following table lists the RR type's and their rdmap fields.

      RR TYPE (num)    RDMAP
      ---------------- ------------------------------------------------------------------
      :A (1)           %{ip: str | {u8, u8, u8, u8}
      :NS (2)          %{name: str}
      :CNAME (5)       %{name: str}
      :SOA (6)         %{mname: str, rname: str, serial: number, refresh: u32 (14400)
                       retry: u32 (7200), expire: u32 (1209600), minimum: u32 (86400)}
      :PTR (12)        %{name: str}
      :HINFO (13)      %{cpu: str, os: str}
      :MX (15)         %{name: str, pref: number}
      :TXT (16)        %{txt: [str]}
      :AAAA (28)       %{ip: str | {u16, u16, u16, u16, u16, u16, u16, u16}}
      :SRV (33)        %{prio: u16, weight: u16, port: u16, target: str}
      :CERT (37)       %{type: u16, keytag: u16, algo: u8, cert: str}
      :DNAME (39)      %{dname: str}
      :OPT (41)        %{xrcode: u8, version: u8, do: 0|1, z: n15, opts: []}
      :DS (43)         %{keytag: u16, algo: u8, type: u8, digest: str}
      :SSHFP (44)      %{algo: u8, type: u8, fp: str}
      :IPSECKEY (45)   %{pref: u8, algo: u8, gw_type: u8, gateway: str, pubkey: str}
      :RRSIG (46)      %{type: atom | u16, algo: u8, labels: u8, ttl: u32, expiration: 32
                       inception: u32, keytag: u16, name: str, signature: str}
      :NSEC (47)       %{name: str, bitmap: bitstring}
      :DNSKEY (48)     %{flags: u16, proto: u8, algo: u8, pubkey: str}
      :NSEC3 (50)      %{algo: u8, flags: u8, iterations: u16, salt: str,
                       next_name: str, bitmap: str}
      :NSECPARAM3 (51) %{algo: u8, flags: u8, iterations: u16, salt: str}
      :TLSA (52)       %{usage: u8, selector: u8, type: u8, data: str}
      :CDS (59)        %{keytag: u16, algo: u8, type: u8, digest: str}
      :CDNSKEY (60)    %{flags: u16, proto: u8, algo: u8, pubkey: str}
      :ZONEMD (63)     %{serial: u32, scheme: u8, algo: u8, digest: str}
      :CSYNC (62)      %{soa_serial: u32, flags: u16, bitmap: str}
      :URI (256)       %{prio: u16, weight: u16, target: str}
      :CAA (257)       %{flags: u8, tag: str, value: str}
      ---------------- ------------------------------------------------------------------

  where:
  - str, denotes a binary
  - u<x>, denotes an unsigned number of <x> bits
  - optional fields have their (default value) listed as well
  - some `bitmap` fields may generate an extra, informational, `covers` list of RR's

  When your favorite `RR` type is missing from the table above, you can still encode
  it by creating a module named `DNS.Msg.RR.User` and provide your own encoder and
  maybe raise a somewhat more helpful exception.

  ```
  defmodule DNS.Msg.RR.User do

    @spec encode_rdata(non_neg_integer, map) :: binary
    def encode(type, rdmap)

    # Example: howto encode RR type 1 (:A) if it were missing
    def encode(1, rdmap) do
      ip = Map.get(rdmap, :ip) || raise DNS.Msg.Error.Exception(reason: :erdmap, data: "missing ip")

      with {:ok, pfx} <- Pfx.parse(ip),
           :ip4 <- Pfx.type(pfx),
           {a, b, c, d} <- Pfx.to_tuple(pfx, mask: false) do
        <<a::8, b::8, c::8, d::8>>
      else
        _ ->
          raise DNS.Msg.Error.Exception(reason: :erdmap, data: "invalid IPv4 #{inspect(ip)}")
      end
    end
  end
  ```

  If no encoder is available, neither natively nor in DNS.Msg.RR.User), a
  `DNS.Msg.Error` is raised. Note that if DNS.Msg.RR.User's `encode_rdata`
  exists, gets called but fails to match given (numeric) RR type a
  `FunctionClauseError` will be raised instead.


  ## Examples

      iex> rr = new(type: :A, name: "example.com", rdmap: %{ip: {127, 0, 0, 1}})
      iex> encode(rr)
      %DNS.Msg.RR{
        name: "example.com",
        type: :A,
        class: :IN,
        ttl: 0,
        rdlen: 4,
        rdmap: %{ip: {127, 0, 0, 1}},
        rdata: <<127, 0, 0, 1>>,
        wdata: <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109,
        0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1>>
      }

  """
  @spec encode(t) :: t
  def encode(%__MODULE__{} = rr) do
    name = dname_encode(rr.name)
    class = encode_dns_class(rr.class)
    type = encode_rr_type(rr.type)
    rdata = encode_rdata(rr.type, rr.rdmap)
    rdlen = byte_size(rdata)

    wdata =
      with true <- is_u16(type),
           true <- is_u16(class),
           true <- is_u16(rdlen),
           true <- is_u32(rr.ttl) do
        <<name::binary, type::16, class::16, rr.ttl::signed-size(32), rdlen::16, rdata::binary>>
      else
        _ -> error(:eencode, "RR #{rr.type} could not be encoded: #{inspect(rr)}")
      end

    %{rr | rdlen: rdlen, rdata: rdata, wdata: wdata}
  end

  # [[ ENCODE RDATA ]]

  @spec encode_rdata(type, map) :: binary
  defp encode_rdata(type, rdmap)

  # IN A (1)
  defp encode_rdata(:A, m) do
    ip = required(:A, m, :ip)

    with {:ok, pfx} <- Pfx.parse(ip),
         :ip4 <- Pfx.type(pfx),
         {a, b, c, d} <- Pfx.to_tuple(pfx, mask: false) do
      <<a::8, b::8, c::8, d::8>>
    else
      _ ->
        error(:erdmap, "A RR, got: #{inspect(m)}")
    end
  end

  # IN NS (2)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11
  defp encode_rdata(:NS, m) do
    required(:NS, m, :name, &is_binary/1) |> dname_encode()
  end

  # IN CNAME (5)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1
  defp encode_rdata(:CNAME, m) do
    name = required(:CNAME, m, :name, &is_binary/1)
    dname_encode(name)
  end

  # IN SOA (6)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
  defp encode_rdata(:SOA, m) do
    # supply defaults where needed
    m =
      m
      |> Map.put_new(:refresh, 14400)
      |> Map.put_new(:retry, 7200)
      |> Map.put_new(:expire, 1_209_600)
      |> Map.put_new(:minimum, 86400)

    # check values
    mname = required(:SOA, m, :mname, &is_binary/1) |> dname_encode()
    rname = required(:SOA, m, :rname, &is_binary/1) |> dname_encode()
    serial = required(:SOA, m, :serial, &is_u32/1)
    refresh = required(:SOA, m, :refresh, &is_u32/1)
    retry = required(:SOA, m, :retry, &is_u32/1)
    expire = required(:SOA, m, :expire, &is_u32/1)
    minimum = required(:SOA, m, :minimum, &is_u32/1)

    <<mname::binary, rname::binary, serial::32, refresh::32, retry::32, expire::32, minimum::32>>
  end

  # IN PTR (12)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12
  defp encode_rdata(:PTR, m) do
    name = required(:PTR, m, :name, &is_binary/1)
    dname_encode(name)
  end

  # IN HINFO (13)
  # https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.2
  # revived by RFC8482
  defp encode_rdata(:HINFO, m) do
    cpu = required(:HINFO, m, :cpu, &is_binary/1)
    os = required(:HINFO, m, :os, &is_binary/1)
    clen = String.length(cpu)
    olen = String.length(os)
    <<clen::8, cpu::binary, olen::8, os::binary>>
  end

  # IN MX (15)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9
  defp encode_rdata(:MX, m) do
    pref = required(:MX, m, :pref, &is_u16/1)
    name = required(:MX, m, :name, &is_binary/1) |> dname_encode()
    <<pref::16, name::binary>>
  end

  # IN TXT (16)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3
  # - a list of character-strings
  # - a character-string is <len>characters, whose length <= 256 (incl. len)
  defp encode_rdata(:TXT, m) do
    data = required(:TXT, m, :txt, &is_list/1)

    with true <- length(data) > 0,
         true <- Enum.all?(fn txt -> is_binary(txt) end),
         true <- Enum.all?(fn txt -> String.length(txt) < 256 end) do
      data
      |> Enum.map(fn txt -> <<String.length(txt)::8, txt::binary>> end)
      |> Enum.join()
    else
      _ -> error(:erdmap, "TXT RR, got: #{inspect(m)}")
    end
  end

  # IN AAAA (28)
  defp encode_rdata(:AAAA, m) do
    ip = required(:AAAA, m, :ip)

    with {:ok, pfx} <- Pfx.parse(ip),
         :ip6 <- Pfx.type(pfx),
         {a, b, c, d, e, f, g, h} <- Pfx.to_tuple(pfx, mask: false) do
      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    else
      _ ->
        error(:erdmap, "AAAA RR, got: #{inspect(m)}")
    end
  end

  # IN SRV (33)
  # - https://www.rfc-editor.org/rfc/rfc2782
  # - https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
  defp encode_rdata(:SRV, m) do
    prio = required(:SRV, m, :prio, &is_u16/1)
    weight = required(:SRV, m, :weight, &is_u16/1)
    port = required(:SRV, m, :port, &is_u16/1)
    target = required(:SRV, m, :target, &is_binary/1) |> dname_encode()

    <<prio::16, weight::16, port::16, target::binary>>
  end

  # CERT (37)
  # - https://www.rfc-editor.org/rfc/rfc4398.html#section-2
  defp encode_rdata(:CERT, m) do
    type = required(:CERT, m, :type, &is_u16/1)
    keytag = required(:CERT, m, :keytag, &is_u16/1)
    algo = required(:CERT, m, :algo, &is_u8/1)
    cert = required(:CERT, m, :cert, &is_binary/1)

    <<type::16, keytag::16, algo::8, cert::binary>>
  end

  # - DNAME (39)
  #   - https://www.rfc-editor.org/rfc/rfc6672.html#section-2.1
  defp encode_rdata(:DNAME, m) do
    dname = required(:DNAME, m, :dname, &is_binary/1)
    dname_encode(dname)
  end

  # IN OPT (41)
  # https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  defp encode_rdata(:OPT, m) do
    m = Map.put_new(m, :opts, [])
    opts = required(:OPT, m, :opts, &is_list/1)

    for {code, data} <- opts, into: "", do: encode_edns_opt(code, data)
  end

  # IN DS (43)
  # https://www.rfc-editor.org/rfc/rfc4034#section-5
  defp encode_rdata(:DS, m) do
    k = required(:DS, m, :keytag, &is_u16/1)
    a = required(:DS, m, :algo, &is_u8/1)
    t = required(:DS, m, :type, &is_u8/1)
    d = required(:DS, m, :digest, &is_binary/1)
    <<k::16, a::8, t::8, d::binary>>
  end

  # IN SSHFP (44)
  # - https://www.rfc-editor.org/rfc/rfc4255.html#section-3.1
  defp encode_rdata(:SSHFP, m) do
    algo = required(:SSHFP, m, :algo, &is_u8/1)
    type = required(:SSHFP, m, :type, &is_u8/1)
    fp = required(:SSHFP, m, :fp, &is_binary/1)
    <<algo::8, type::8, fp::binary>>
  end

  # IN IPSECKEY (45)
  # - https://www.rfc-editor.org/rfc/rfc4025.html#section-2
  defp encode_rdata(:IPSECKEY, m) do
    gtype = required(:IPSECKEY, m, :gw_type, &is_u8/1)
    gwstr = required(:IPSECKEY, m, :gateway, &is_binary/1)
    pref = required(:IPSECKEY, m, :pref, &is_u8/1)
    algo = required(:IPSECKEY, m, :algo, &is_u8/1)
    pubkey = required(:IPSECKEY, m, :pubkey, &is_binary/1)

    gateway =
      case gtype do
        0 ->
          ""

        1 ->
          {a, b, c, d} = Pfx.to_tuple(gwstr)
          <<a::8, b::8, c::8, d::8>>

        2 ->
          {a, b, c, d, e, f, g, h} = Pfx.to_tuple(gwstr)
          <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

        3 ->
          dname_encode(gwstr)

        n ->
          error(:eformat, "IPSECKEY gateway type unknown: #{inspect(n)}")
      end

    <<pref::8, gtype::8, algo::8, gateway::binary, pubkey::binary>>
  end

  # IN RRSIG (46)
  # https://www.rfc-editor.org/rfc/rfc4034#section-3
  defp encode_rdata(:RRSIG, m) do
    type = required(:RRSIG, m, :type, fn t -> encode_rr_type(t) |> is_u16 end)
    algo = required(:RRSIG, m, :algo, &is_u8/1)
    labels = required(:RRSIG, m, :labels, &is_u8/1)
    ttl = required(:RRSIG, m, :ttl, &is_u32/1)
    expire = required(:RRSIG, m, :expiration, &is_u32/1)
    incept = required(:RRSIG, m, :inception, &is_u32/1)
    keytag = required(:RRSIG, m, :keytag, &is_u16/1)
    name = required(:RRSIG, m, :name, &is_binary/1) |> dname_encode()
    sig = required(:RRSIG, m, :signature, &is_binary/1)

    <<type::16, algo::8, labels::8, ttl::32, expire::32, incept::32, keytag::16, name::binary,
      sig::binary>>
  end

  # IN NSEC (47)
  # https://www.rfc-editor.org/rfc/rfc4034#section-4
  defp encode_rdata(:NSEC, m) do
    name = required(:NSEC, m, :name, &is_binary/1) |> dname_encode()
    bitmap = required(:NSEC, m, :bitmap, &is_binary/1)
    <<name::binary, bitmap::binary>>
  end

  # IN DNSKEY (48)
  # https://www.rfc-editor.org/rfc/rfc4034#section-2
  defp encode_rdata(:DNSKEY, m) do
    flags = required(:DNSKEY, m, :flags, &is_u16/1)
    proto = required(:DNSKEY, m, :proto, &is_u8/1)
    algo = required(:DNSKEY, m, :algo, &is_u8/1)
    pubkey = required(:DNSKEY, m, :pubkey, &is_binary/1)
    <<flags::16, proto::8, algo::8, pubkey::binary>>
  end

  # IN NSEC3 (50)
  # https://www.rfc-editor.org/rfc/rfc5155#section-3.2
  defp encode_rdata(:NSEC3, m) do
    algo = required(:NSEC3, m, :algo, &is_u8/1)
    flags = required(:NSEC3, m, :flags, &is_u8/1)
    iterations = required(:NSEC3, m, :iterations, &is_u16/1)
    salt = required(:NSEC3, m, :salt, &is_binary/1)
    nxt_name = required(:NSEC3, m, :nxt_name, &is_binary/1)
    bitmap = required(:NSEC3, m, :bitmap, &is_binary/1)

    <<algo::8, flags::8, iterations::16, byte_size(salt), salt::binary, byte_size(nxt_name)::8,
      nxt_name::binary, bitmap::binary>>
  end

  # IN NSEC3PARAM (51)
  # https://www.rfc-editor.org/rfc/rfc5155#section-4.1
  defp encode_rdata(:NSEC3PARAM, m) do
    algo = required(:NSEC3, m, :algo, &is_u8/1)
    flags = required(:NSEC3, m, :flags, &is_u8/1)
    iterations = required(:NSEC3, m, :iterations, &is_u16/1)
    salt = required(:NSEC3, m, :salt, &is_binary/1)
    <<algo::8, flags::8, iterations::16, byte_size(salt)::8, salt::binary>>
  end

  # IN TLSA (52)
  # https://www.rfc-editor.org/rfc/rfc6698#section-2
  defp encode_rdata(:TLSA, m) do
    usage = required(:TLSA, m, :usage, &is_u8/1)
    selector = required(:TSLA, m, :selector, &is_u8/1)
    type = required(:TSLA, m, :type, &is_u8/1)
    data = required(:TSLA, m, :data, &is_binary/1)
    <<usage::8, selector::8, type::8, data::binary>>
  end

  # IN CDS (59)
  # https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1
  # e.g. is dnsimple.zone
  defp encode_rdata(:CDS, m) do
    keytag = required(:CDS, m, :keytag, &is_u16/1)
    algo = required(:CDS, m, :algo, &is_u8/1)
    type = required(:CDS, m, :type, &is_u8/1)
    digest = required(:CDS, m, :digest, &is_binary/1)
    <<keytag::16, algo::8, type::8, digest::binary>>
  end

  # IN CDNSKEY (60)
  # https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2
  defp encode_rdata(:CDNSKEY, m) do
    flags = required(:CDNSKEY, m, :flags, &is_u16/1)
    proto = required(:CDNSKEY, m, :proto, &is_u8/1)
    algo = required(:CDNSKEY, m, :algo, &is_u8/1)
    pubkey = required(:CDNSKEY, m, :pubkey, &is_binary/1)
    <<flags::16, proto::8, algo::8, pubkey::binary>>
  end

  # CSYNC (62)
  # - https://www.rfc-editor.org/rfc/rfc7477.html#section-2
  defp encode_rdata(:CSYNC, m) do
    soa_serial = required(:CSYNC, m, :soa_serial, &is_u32/1)
    flags = required(:CSYNC, m, :flags, &is_u16/1)
    bitmap = required(:CSYNC, m, :bitmap, &is_binary/1)
    <<soa_serial::32, flags::16, bitmap::binary>>
  end

  # IN ZONEMD (63)
  # - https://datatracker.ietf.org/doc/html/rfc8976#section-2
  defp encode_rdata(:ZONEMD, m) do
    serial = required(:ZONEMD, m, :serial, &is_u32/1)
    scheme = required(:ZONEMD, m, :scheme, &is_u8/1)
    algo = required(:ZONEMD, m, :algo, &is_u8/1)
    digest = required(:ZONEMD, m, :digest, &is_binary/1)
    <<serial::32, scheme::8, algo::8, digest::binary>>
  end

  # IN ANY/* (255)

  # IN URI (256)
  # - https://www.rfc-editor.org/rfc/rfc7553.html#section-4.5
  defp encode_rdata(:URI, m) do
    prio = required(:URI, m, :prio, &is_u16/1)
    weight = required(:URI, m, :weight, &is_u16/1)
    target = required(:URI, m, :target, &is_binary/1)
    <<prio::16, weight::16, target::binary>>
  end

  # IN CAA (257)
  # https://www.rfc-editor.org/rfc/rfc8659#section-4
  defp encode_rdata(:CAA, m) do
    flags = required(:CAA, m, :flags, &is_u8/1)
    tag = required(:CAA, m, :tag, &is_binary/1)
    value = required(:CAA, m, :value, &is_binary/1)
    <<flags::8, byte_size(tag)::8, tag::binary, value::binary>>
  end

  ## [[ catch all ]]
  defp encode_rdata(type, rdmap) do
    # ensure we use the RR TYPE number, not a mnemonic
    with type <- encode_rr_type(type),
         true <- Code.ensure_loaded?(@user),
         true <- function_exported?(@user, :encode_rdata, 2),
         rdata when is_binary(rdata) <- apply(@user, :encode_rdata, [type, rdmap]) do
      rdata
    else
      _ -> error(:erdmap, "RR #{type}, cannot encode rdmap: #{inspect(rdmap)}")
    end
  end

  # [[ ENCODE EDNS0 opts ]]
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  # @doc """
  # Encodes an EDNS0 option to a binary.
  #
  # """
  @spec encode_edns_opt(atom | non_neg_integer, any) :: binary
  defp encode_edns_opt(code, data)

  defp encode_edns_opt(:NSID, data) when is_binary(data) do
    # https://www.rfc-editor.org/rfc/rfc5001
    # In a query, data is supposed to be ""
    len = byte_size(data)

    if is_u16(len),
      do: <<3::16, len::16, data::binary>>,
      else: error(:eedns, "EDNS NSID too long")
  end

  defp encode_edns_opt(:EXPIRE, seconds) when is_u32(seconds) do
    # https://www.rfc-editor.org/rfc/rfc7314.html#section-2
    <<9::16, 4::16, seconds::integer-size(32)>>
  end

  defp encode_edns_opt(:COOKIE, {client, server}) do
    # https://www.rfc-editor.org/rfc/rfc7873.html#section-4
    clen = byte_size(client)
    slen = byte_size(server)

    if clen == 8 and (slen == 0 or slen in 8..32) do
      len = clen + slen
      <<10::16, len::16, client::binary-size(clen), server::binary-size(slen)>>
    else
      if clen != 8,
        do: error(:eedns, "EDNS COOKIE: invalid client cookie #{inspect(client)}"),
        else: error(:eedns, "EDNS COOKIE: invalid server cookie #{inspect(server)}")
    end
  end

  # [[ catch all - todo ]]
  # defer to DNS.Msg.RR.User.encode_edns_opt/2 if available
  defp encode_edns_opt(code, data),
    do: error(:eedns, "EDNS0 option #{inspect(code)} unknown or data illegal #{inspect(data)}")

  # [[ DECODE RR ]]

  @doc """
  Decodes an `RR` `t:t/0` struct at given `offset` in `msg`.

  Upon success, returns {`new_offset`, `t:t/0`}, where `new_offset` can be used
  to read the rest of the message (if any).  The `rdlen`, `rdata` and `wdata`-fields
  are set based on the octets read during decoding.

  See `encode/1` for the list of RR's that can be decoded.  If a decoder is missing,
  you can provide your own in a #{Module.split(@user) |> Enum.join(".")} module.

  ```
  defmodule #{Module.split(@user) |> Enum.join(".")}

  @spec decode_rdata(non_neg_integer, non_neg_integer, non_neg_integer, binary) :: map
  def decode_rdata(type, offset, rdlen, msg)

  def decode_rdata(99, offset, rdlen, msg) do
    ...
  end

  # more decoders

  # catch all
  def decode_rdata(_, _, _, _),
    do: %{}
  ```

  The `decode_rdata` is called with:
  - `type`, the numeric value of type for given RR
  - `offset`, the start of the `RR` in the DNS `msg`
  - `rdlen`, as read from the start of the `RR`
  - `msg`, the entire wire format of the DNS `msg` being decoded.

  Sometimes it's necessary to jump around in the DNS `msg` while decoding
  a single RR. The `decode_rdata` function should return an `rdmap` with
  `key,value`-pairs based on the RR being decoded.

  Not being able to decode a specific RR is not a fatal error in which an empty
  map is returned.  Make sure you have a catch all that simply returns an empty
  map.

  ## Example

      iex> decode(5, <<"stuff", 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109,
      ...>   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1, "more stuff">>)
      {32,
       %DNS.Msg.RR{
         name: "example.com",
         type: :A,
         class: :IN,
         ttl: 0,
         rdlen: 4,
         rdmap: %{ip: "127.0.0.1"},
         rdata: <<127, 0, 0, 1>>,
         wdata: <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109,
                  0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1>>
       }}
  """
  @spec decode(offset, binary) :: {offset, t}
  def decode(offset, msg) do
    {offset2, name} = dname_decode(offset, msg)

    <<_::binary-size(offset2), type::16, class::16, ttl::32, rdlen::16, rdata::binary-size(rdlen),
      _::binary>> = msg

    # new will put symbolic name for :type, :class numbers if possible
    rr = new(name: name, type: type, class: class, ttl: ttl, rdlen: rdlen)
    # need to pass in rdlen as well, since some RR's may have rdlen of 0
    rdmap = decode_rdata(rr.type, offset2 + 10, rdlen, msg)
    wdata = :binary.part(msg, {offset, offset2 - offset + 10 + rdlen})
    rr = %{rr | rdlen: rdlen, rdmap: rdmap, rdata: rdata, wdata: wdata}
    offset = offset2 + 10 + rdlen

    {offset, rr}
  end

  # [[ DECODE RDATA ]]
  # note: decode_rdata always takes type, offset, rdlen and msg:
  # - type define RR-type whose rdata is to be decoded
  # - rdlen is needed since some RR's have rdlen of 0
  # - offset, msg is needed since rdata may contain compressed domain names
  # TODO-RRs: Maybe add these (check out <type>.dns.netmeister.org
  # - RP dnslab.org tcp53.ch
  # - TYPE65 www.google.com  (for some reason HTTPS doesn't work)
  # - SIG (24)
  # - KEY (25)
  # - PX (26)
  # - GPOS (27)
  # - LOC (29)
  # - NAPTR (35) sip2sip.info
  # - KX (36)
  # - TKEY (249)
  # - TSIG (250)
  # - URI (256)

  @spec decode_rdata(type, offset, length, binary) :: map
  defp decode_rdata(type, offset, rdlen, msg)

  # IN A (1)
  defp decode_rdata(:A, offset, 4, msg) do
    <<_::binary-size(offset), a::8, b::8, c::8, d::8, _::binary>> = msg
    %{ip: "#{Pfx.new({a, b, c, d})}"}
  end

  # IN NS (2)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11
  defp decode_rdata(:NS, offset, _rdlen, msg) do
    {_, name} = dname_decode(offset, msg)
    %{name: name}
  end

  # IN CNAME (5)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1
  defp decode_rdata(:CNAME, offset, _rdlen, msg) do
    {_, name} = dname_decode(offset, msg)
    %{name: name}
  end

  # CSYNC (62)
  # - https://www.rfc-editor.org/rfc/rfc7477.html#section-2
  defp decode_rdata(:CSYNC, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<soa_serial::32, flags::16, bitmap::binary>> = rdata
    covers = bitmap_to_rrs(bitmap)
    %{soa_serial: soa_serial, flags: flags, bitmap: bitmap, covers: covers}
  end

  # IN SOA (6)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13
  defp decode_rdata(:SOA, offset, _rdlen, msg) do
    {offset, mname} = dname_decode(offset, msg)
    {offset, rname} = dname_decode(offset, msg)

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
  defp decode_rdata(:PTR, offset, _rdlen, msg) do
    {_, name} = dname_decode(offset, msg)
    %{name: name}
  end

  # IN HINFO (13)
  # https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.2
  defp decode_rdata(:HINFO, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<clen::8, cpu::binary-size(clen), olen::8, os::binary-size(olen)>> = rdata

    %{cpu: cpu, os: os}
  end

  # IN MX (15)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9
  defp decode_rdata(:MX, offset, _rdlen, msg) do
    <<_::binary-size(offset), pref::16, _::binary>> = msg
    {_offset, name} = dname_decode(offset + 2, msg)
    %{name: name, pref: pref}
  end

  # IN TXT (16)
  # https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14
  defp decode_rdata(:TXT, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    lines =
      for <<len::8, txt::binary-size(len) <- rdata>>,
        do: txt

    %{txt: lines}
  end

  # IN AAAA (28)
  defp decode_rdata(:AAAA, offset, 16, msg) do
    <<_::binary-size(offset), a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, _::binary>> =
      msg

    %{ip: "#{Pfx.new({a, b, c, d, e, f, g, h})}"}
  end

  # IN SRV (33)
  # - https://www.rfc-editor.org/rfc/rfc2782
  # - https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
  defp decode_rdata(:SRV, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<prio::16, weight::16, port::16, _::binary>> = rdata
    # just in case name compression is used.
    {_, target} = dname_decode(offset + 6, msg)
    %{prio: prio, weight: weight, port: port, target: target}
  end

  # CERT (37)
  # - https://www.rfc-editor.org/rfc/rfc4398.html#section-2
  defp decode_rdata(:CERT, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<type::16, keytag::16, algo::8, cert::binary>> = rdata

    %{
      type: type,
      keytag: keytag,
      algo: algo,
      cert: cert
    }
  end

  # - DNAME (39)
  #   - https://www.rfc-editor.org/rfc/rfc6672.html#section-2.1
  defp decode_rdata(:DNAME, offset, _rdlen, msg) do
    {_offset, dname} = dname_decode(offset, msg)
    %{dname: dname}
  end

  # IN OPT (41) pseudo-rr
  # - https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  defp decode_rdata(:OPT, offset, _rdlen, msg) do
    # OPT RR's class is requestor's bufsize, so read it as such.
    # backup 8 bytes to the start of RR's class and ttl and decode those
    # and the rdlen & rdata fields as well
    offset_class = offset - 8

    <<_::binary-size(offset_class), bufsize::16, xrcode::8, version::8, do_bit::1, z::15,
      rdlen::16, rdata::binary-size(rdlen), _::binary>> = msg

    opts =
      for <<code::16, len::16, data::binary-size(len) <- rdata>>,
        do: decode_rropt_code(code) |> decode_edns_opt(len, data)

    %{
      bufsize: bufsize,
      xrcode: decode_dns_rcode(xrcode),
      version: version,
      do: do_bit,
      z: z,
      opts: opts
    }
  end

  # IN DS (43)
  # https://www.rfc-editor.org/rfc/rfc4034#section-5
  defp decode_rdata(:DS, offset, rdlen, msg) do
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

  # SSHFP (44)
  # - https://www.rfc-editor.org/rfc/rfc4255.html#section-3.1
  defp decode_rdata(:SSHFP, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<algo::8, type::8, fp::binary>> = rdata

    %{
      algo: algo,
      type: type,
      fp: fp
    }
  end

  # IPSECKEY (45)
  # - https://www.rfc-editor.org/rfc/rfc4025.html#section-2
  defp decode_rdata(:IPSECKEY, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<pref::8, gw_type::8, algo::8, rest::binary>> = rdata

    {gateway, pubkey} =
      case gw_type do
        0 ->
          {<<>>, rest}

        1 ->
          <<a::8, b::8, c::8, d::8, pkey::binary>> = rest
          {"#{Pfx.new({a, b, c, d})}", pkey}

        2 ->
          <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, pkey::binary>> = rest
          {"#{Pfx.new({a, b, c, d, e, f, g, h})}", pkey}

        3 ->
          {offset, name} = dname_decode(0, rest)
          <<_::binary-size(offset), pkey::binary>> = rest
          {name, pkey}

        n ->
          error(:eformat, "IPSECKEY gateway type unknown: #{inspect(n)}")
      end

    %{
      pref: pref,
      algo: algo,
      gw_type: gw_type,
      gateway: gateway,
      pubkey: pubkey
    }
  end

  # IN RRSIG (46)
  # https://www.rfc-editor.org/rfc/rfc4034#section-3
  defp decode_rdata(:RRSIG, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<type::16, algo::8, labels::8, ttl::32, notafter::32, notbefore::32, keytag::16,
      rest::binary>> = rdata

    # no name compression allowed in RRSIG, so we stay within `rest`
    {offset, name} = dname_decode(0, rest)
    <<_::binary-size(offset), signature::binary>> = rest

    {:ok, notafter} = DateTime.from_unix(notafter, :second)
    {:ok, notbefore} = DateTime.from_unix(notbefore, :second)

    %{
      type: decode_rr_type(type),
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
  defp decode_rdata(:NSEC, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    {offset, name} = dname_decode(0, rdata)
    <<_::binary-size(offset), bitmap::binary>> = rdata
    covers = bitmap_to_rrs(bitmap)
    %{name: name, bitmap: bitmap, covers: covers}
  end

  # IN DNSKEY (48)
  # https://www.rfc-editor.org/rfc/rfc4034#section-2
  defp decode_rdata(:DNSKEY, offset, rdlen, msg) do
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
  defp decode_rdata(:NSEC3, offset, rdlen, msg) do
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
  defp decode_rdata(:NSEC3PARAM, offset, rdlen, msg) do
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
  defp decode_rdata(:TLSA, offset, rdlen, msg) do
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
  defp decode_rdata(:CDS, offset, rdlen, msg) do
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
  defp decode_rdata(:CDNSKEY, offset, rdlen, msg) do
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

  # IN ZONEMD (63)
  # - https://datatracker.ietf.org/doc/html/rfc8976#section-2
  defp decode_rdata(:ZONEMD, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<serial::32, scheme::8, algo::8, digest::binary>> = rdata
    %{serial: serial, scheme: scheme, algo: algo, digest: digest}
  end

  # IN HTTPS (65)
  # - https://www.rfc-editor.org/rfc/rfc9460.html#name-rdata-wire-format

  # IN ANY/* (255)

  # IN URI (256)
  # - https://www.rfc-editor.org/rfc/rfc7553.html#section-4.5
  defp decode_rdata(:URI, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<prio::16, weight::16, target::binary>> = rdata
    %{prio: prio, weight: weight, target: target}
  end

  # IN CAA (257)
  # https://www.rfc-editor.org/rfc/rfc8659#section-4
  defp decode_rdata(:CAA, offset, rdlen, msg) do
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
  # no decoder available: try a user supplied one (if any)
  # if all fails, simply return an empty map
  # in which case caller needs to deal with an undecoded RR.
  defp decode_rdata(type, offset, rdlen, msg) do
    with type <- encode_rr_type(type),
         true <- Code.ensure_loaded?(@user),
         true <- function_exported?(@user, :decode_rdata, 4),
         rdmap when is_map(rdmap) <- apply(@user, :decode_rdata, [type, offset, rdlen, msg]) do
      rdmap
    else
      _ -> %{}
    end
  end

  # [[ DECODE ENDS0 opts ]]
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  # @doc """
  # Decode an EDNS option if we can, keep raw otherwise.
  #
  # """
  @spec decode_edns_opt(non_neg_integer, non_neg_integer, binary) :: {non_neg_integer, any}
  defp decode_edns_opt(code, len, data)
  # Note: not sure if decode_ends_opt should get an offset & org msg binary
  # since some options might refer to other parts of the msg (e.g. name
  # compression)?  For now -> we simply decode based on (code, len, data)

  # NSID (3)
  # https://www.rfc-editor.org/rfc/rfc5001#section-2.3
  # could leave it up to the catch all, but hey! we're here aren't we
  defp decode_edns_opt(:NSID, _len, data),
    do: {:NSID, data}

  # DAU (5), DHU (6), N3U (7)
  # https://www.rfc-editor.org/rfc/rfc6975.html#section-3

  # Expire (9)
  # https://www.rfc-editor.org/rfc/rfc7314.html#section-2
  defp decode_edns_opt(:EXPIRE, len, data) do
    if len != 4,
      do: IO.puts("EDNS0 EXPIRE option illegal len #{inspect(len)}")

    <<expiry::32>> = data

    {:EXPIRE, expiry}
  end

  # Cookie (10)
  # https://www.rfc-editor.org/rfc/rfc7873.html#section-4
  defp decode_edns_opt(:COOKIE, len, data) do
    if len in 8..40 do
      <<client::binary-size(8), server::binary>> = data
      {:COOKIE, {client, server}}
    else
      error(:eedns, "EDNS0 COOKIE, invalid DNS cookies in #{inspect(data)}")
    end
  end

  # catch all: keep what we donot understand as raw values
  # TODO: defer to DNS.Msg.RR.decode_edns_opt/2 if available
  defp decode_edns_opt(code, _, data),
    do: {code, data}
end

defimpl Inspect, for: DNS.Msg.RR do
  # import DNS.Msg.Terms

  def inspect(rr, opts) do
    syntax_colors = IO.ANSI.syntax_colors()
    opts = Map.put(opts, :syntax_colors, syntax_colors)
    # class = if rr.type == :OPT, do: "requestor's bufsize", else: :IN

    # presentation of some rdmap's values
    rr =
      case rr.type do
        # follow drill's example of lower-cased hex digits
        :DS -> put_in(rr.rdmap.digest, Base.encode16(rr.rdmap.digest, case: :lower))
        :CDS -> put_in(rr.rdmap.digest, Base.encode16(rr.rdmap.digest, case: :lower))
        :RRSIG -> put_in(rr.rdmap.signature, Base.encode64(rr.rdmap.signature))
        :DNSKEY -> put_in(rr.rdmap.pubkey, Base.encode64(rr.rdmap.pubkey))
        :CDNSKEY -> put_in(rr.rdmap.pubkey, Base.encode64(rr.rdmap.pubkey))
        :TLSA -> put_in(rr.rdmap.data, Base.encode16(rr.rdmap.data, case: :lower))
        _ -> rr
      end

    rr
    # |> Map.put(:type, "#{rr.type} (#{encode_rr_type(rr.type)})")
    # |> Map.put(:class, "#{class} (#{rr.class})")
    |> Map.put(:rdata, "#{Kernel.inspect(rr.rdata, limit: 10)}")
    |> Map.put(:wdata, "#{Kernel.inspect(rr.wdata, limit: 10)}")
    |> Inspect.Any.inspect(opts)
  end
end
