defmodule DNS.Msg.RR do
  @moduledoc """
  Low level functions to create, encode or decode an `RR` `t:t/0` struct.

  Resource Records (RRs) are found in the Answer, Authority, and Additional
  sections of a DNS message.

  Each RR has the following [format](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1):

  ```
    0  1  2  3  4  5  6  7  8  9  0 11 12 13 14 15
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  /                      NAME                     / length encoded owner domain name
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TYPE                     | unsigned 16 bit integer
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     CLASS                     | unsigned 16 bit integer
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                      TTL                      | unsigned 32 bit integer in 0..2**31 -1
  |                                               |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     RDLEN                     | unsigned 16 bit integer, the length or RDATA
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
  /                     RDATA                     / variable length binary
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ```

  The `TTL` range is clarified in [rfc2181](https://www.rfc-editor.org/rfc/rfc2181#section-8).


  ## Encoding/decoding

  The information in `RDATA` is represented by a map `rdmap`, since
  the contents of RDATA depends (mostly) on the RR's `TYPE` and differs wildly
  among the various RR types out there.

  In the List of RR's, rdmap fields are listed with their 'type':
  - `str`, String.t through conversion
  - `bin`, binary as found on the wire
  - `u<n>`, an unsigned integer that fits in `n` bits
  - `s<n>`, a signed integer that fits in `n` bits

  When encoding, the rdmap fields are validated before being used for constructing
  the `RDATA` portion of the RR's wireformat data and vice versa for decoding.

  Also, when encoding, some rdmap fields are optional in the sense that they'll
  be given default values if missing.  In the list below, those fields have a
  (value) listed in brackets.  Any other fields present in `rdmap` are ignored
  when encoding an RR, since some fields are informational (like `keytag` in an
  `:RRSIG` which is computed during decoding, but not used for encoding)


  *List of RRs*

  * [`:A` (1)](https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1)
    ```
   %{ip: str | {u8, u8, u8, u8}}
    ```
  * [`:AAAA` (28)](https://www.rfc-editor.org/rfc/rfc3596#section-2.2)
    ```
    rdmap: %{ip: str | {u16, u16, u16, u16, u16, u16, u16, u16}}
    ```
  * [`:AFSDB` (18)](https://www.rfc-editor.org/rfc/rfc1183.html#section-1)
    ```
    rdmap: %{type: u16, name: str}
    ```
  * [`:AMTRELAY` (260)](https://datatracker.ietf.org/doc/html/rfc8777#section-4)
    ```
   %{pref: u8, d: 0|1, type: u7, relay: str}
    ```
  * [`:CAA` (257)](https://www.rfc-editor.org/rfc/rfc8659#section-4)
    ```
    rdmap: %{flags: u8, tag: str, value: str}
    ```
  * [`:CDNSKEY` (60)](https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2)
    ```
    rdmap: %{flags: u16, proto: u8, algo: u8, pubkey: bin}
    ```
  * [`:CDS` (59)](https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1)
    ```
    rdmap: %{keytag: u16, algo: u8, type: u8, digest: str}
    ```
  * [`:CERT` (37)](https://www.rfc-editor.org/rfc/rfc4398.html#section-2)
    ```
    rdmap: %{type: u16, keytag: u16, algo: u8, cert: str}
    ```
  * [`:CNAME` (5)](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1)
    ```
    rdmap: %{name: str}
    ```
  * [`:CSYNC` (62)](https://www.rfc-editor.org/rfc/rfc7477.html#section-2)
    ```
    rdmap: %{soa_serial: u32, flags: u16, covers: [atom|u32]}
    ```
  * [`:DNAME` (39)](https://www.rfc-editor.org/rfc/rfc6672.html#section-2.1)
    ```
    rdmap: %{dname: str}
    ```
  * [`:DNSKEY` (48)](https://www.rfc-editor.org/rfc/rfc4034#section-2)
    ```
    rdmap: %{flags: u16, proto: u8, algo: u8, pubkey: bin, _keytype: str}
    ```
  * [`:DS` (43)](https://www.rfc-editor.org/rfc/rfc4034#section-5)
    ```
    rdmap: %{keytag: u16, algo: u8, type: u8, digest: str}
    ```
  * [`:HINFO` (13)](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.3.2)
    ```
    rdmap: %{cpu: str, os: str} # revived by rfc8482
    ```
  * [`:IPSECKEY` (45)](https://www.rfc-editor.org/rfc/rfc4025.html#section-2)
    ```
    rdmap: %{pref: u8, algo: u8, gw_type: u8, gateway: str, pubkey: bin}
    ```
  * [`:ISDN` (20)](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2)
    ```
    rdmap: %{address: str, sa: str}
    ```
  * [`:KX` (36)](https://datatracker.ietf.org/doc/html/rfc2230#section-3)
    ```
    rdmap: %{pref: u16, name: str}
    ```
  * [`:MB` (7)](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.3)
    ```
    rdmap: %{name: str}
    ```
  * [`:MG` (8)](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.6)
    ```
    rdmap: %{name: str}
    ```
  * [`:MINFO` (14)](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.7)
    ```
    rdmap: %{rmailbx: str, emailbx: str}
    ```
  * [`:MR` (9)](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.8)
    ```
    rdmap: %{name: str}
    ```
  * [`:MX` (15)](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9)
    ```
    rdmap: %{name: str, pref: u16}
    ```
  * [`:NSEC3` (50)](https://www.rfc-editor.org/rfc/rfc5155#section-3.2)
    ```
    rdmap: %{algo: u8, flags: u8, iterations: u16, salt: str, next_name: str, covers: [atom|u16]}
    ```
  * [`:NSECPARAM3` (51)](https://www.rfc-editor.org/rfc/rfc5155#section-4.1)
    ```
    rdmap: %{algo: u8, flags: u8, iterations: u16, salt: str}
    ```
  * [`:NSEC` (47)](https://www.rfc-editor.org/rfc/rfc4034#section-4)
    ```
    rdmap %{name: str, covers: [atom|u16]}
    ```
  * [`:NS` (2)](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11)
    ```
    rdmap: %{name: str}
    ```
  * [`:NULL` (10)](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.10)
    ```
    rdmap: %{data: str}
    ```
  * [`:OPENPGPKEY` (61)](https://www.rfc-editor.org/rfc/rfc4880#section-3)
    ```
    rdmap: %{}, no en/decoding provided, rr.raw is true, use rr.rdata as-is
    ```
  * [`:OPT` (41)](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2)
    ```
    rdmap: %{xrcode: u8, version: u8, do: 0|1, z: n15, opts: []}
    ```
  * [`:PTR` (12)](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12)
    ```
    rdmap: %{name: str}
    ```
  * [`:RP` (17)](https://www.rfc-editor.org/rfc/rfc1183.html#section-2.2)
    ```
    rdmap: %{mail: str, txt: str}
    ```
  * [`:RRSIG` (46)](https://www.rfc-editor.org/rfc/rfc4034#section-3)
    ```
    rdmap: %{type: atom | u16, algo: u8, labels: u8, ttl: u32, notafter: u32,
             notbefore: u32, keytag: u16, name: str, signature: bin} # TODO: fix field qualifiers
    ```
  * [`:RT` (21)](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.3)
    ```
    rdmap: %{pref: u16, name: str}
    ```
  * [`:SOA` (6)](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13)
    ```
    rdmap: %{mname: str, rname: str, serial: number, refresh: u32 (14400) retry: u32 (7200),
             expire: u32 (1209600), minimum: u32 (86400)}
    ```
  * [`:SRV` (33)](https://www.rfc-editor.org/rfc/rfc2782)
    ```
    rdmap: %{prio: u16, weight: u16, port: u16, target: str}
    ```
  * [`:SSHFP` (44)](https://www.rfc-editor.org/rfc/rfc4255.html#section-3.1)
    ```
    rdmap: %{algo: u8, type: u8, fp: str}
    ```
  * [`:TLSA` (52)](https://www.rfc-editor.org/rfc/rfc6698#section-2)
    ```
    rdmap: %{usage: u8, selector: u8, type: u8, data: str}
    ```
  * [`:TXT` (16)](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14)
    ```
    rdmap: %{txt: [str]}
    ```
  * [`:URI` (256)](https://www.rfc-editor.org/rfc/rfc7553.html#section-4.5)
    ```
    rdmap: %{prio: u16, weight: u16, target: str}
    ```
  * [`:WKS` (11)](https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.2)
    ```
    rdmap: %{ip: str | {u8, u8, u8, u8}, proto: u8, services: [u16]}
    ```
  * [`:X25` (19)](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.1)
    ```
    rdmap: %{address: str}
    ```
  * [`:ZONEMD` (63)](https://datatracker.ietf.org/doc/html/rfc8976#section-2)
    ```
    rdmap: %{serial: u32, scheme: u8, algo: u8, digest: str}
    ```

  """

  # TODOs:
  # - https://www.rfc-editor.org/rfc/rfc5890 (Internationlized Domain Names for Applications (IDNA)
  # - https://www.rfc-editor.org/rfc/rfc2181 (clarifications)
  # - https://www.rfc-editor.org/rfc/rfc2673 (binary labels)
  # - https://www.rfc-editor.org/rfc/rfc6891 (EDNS0)
  # - https://www.netmeister.org/blog/dns-rrs.html (shout out!)
  # [ ] add guard is_qtype - https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
  #     AXFR, IXFR, MAILB, MAILA, *, ANY, OPT (41) etc (more QTYPEs exist ...)
  # [ ] add encode/decode_ip_proto
  # [x] add guard is_ttl (u32 with range 0..2**31-1
  # [ ] add section RR's to module doc with explanation & examples & rfc ref(s)
  # [ ] rename DNS.Msg.Terms to DNS.Msg.Names
  # [ ] add all/more names
  # [c] accept TYPEnnn as mnemonic -> not needed, a bind ns sends numeric anyway
  # [c] move the only func in DNS.Msg.Utils into Names module (only place it'll be used)
  #     impossible, used at compile time to expand module attributes
  # [ ] maybe only use nrs in Hdr, Qtn and RR's and use name maps for presentation only?
  # [ ] rename DNS.Msg.Fields to ...(DNS.Msg.Utils?)
  #     dname_decode/encode, ip4_decode/encode, ip6_decode/encode,
  #     bitmap_decode/encode etc...
  # [x] move error func into DNS.Msg.Error, and use import DNS.Msg.Error, only: [error: 2]
  # [ ] add logging (Logger?)
  # [ ] ad RRs: Maybe add these (check out <type>.dns.netmeister.org
  #     [ ] NSEC3PARAM hash, see
  #         - https://www.netmeister.org/blog/dns-rrs.html
  #         - https://github.com/shuque/nsec3hash
  #     [x] AMTRELAY, https://datatracker.ietf.org/doc/html/rfc8777#section-4
  #     [x] RP dnslab.org tcp53.ch
  #     [o] TYPE65 www.google.com  (for some reason HTTPS doesn't work)
  #     [o] LOC (29)
  #     [?] NAPTR (35) sip2sip.info
  #     [x] KX (36)
  #     [ ] TKEY (249) (?)
  #     [ ] TSIG (250) (?)
  #     [o] OPENPGPKEY () would be raw type anyway, since we won't decode rdata!
  #     [ ] KEY (25) https://www.rfc-editor.org/rfc/rfc3445.html
  #     [x] WKS (11) https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.2

  import DNS.Msg.Error, only: [error: 2]
  import DNS.Msg.Fields
  import DNS.Guards
  import DNS.Msg.Terms

  defstruct name: "",
            type: :A,
            class: :IN,
            ttl: 0,
            raw: false,
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
  - `raw`, indicates `rdata` could be encoded/decoded (default false)
  - `rdmap`, contains the (decoded) key,value-pairs of `rdata` (default `%{}`)
  - `rdlen`, the number of octets in the `rdata` field (default 0)
  - `rdata`, RR's rdata in wireformat (default `<<>>`)
  - `wdata`, the RR's wireformat binary (default `<<>>`)

  """
  @type t :: %__MODULE__{
          name: binary,
          type: type,
          class: class,
          raw: boolean,
          ttl: non_neg_integer,
          rdmap: map,
          rdlen: non_neg_integer,
          rdata: binary,
          wdata: binary
        }

  # [[ NEW ]]

  @doc """
  Creates an `RR` `t:t/0` struct for given `opts`.

  Known options include:
  - `:name`, must be a binary (default `""`)
  - `:type`, an [atom](`DNS.Msg.Terms.encode_rr_type/1`) or an unsigned 16 bit number (default `:A`)
  - `:class`, an [atom](`DNS.Msg.Terms.encode_dns_class/1`) or an unsigned 16 bit number (default `:IN`)
  - `:ttl`, a unsigned 32 bit integer (default `0`)
  - `:rdmap`, a map with `key,value`-pairs (to be encoded later, default `%{}`)

  Anything else is silently ignored, including `:raw`, `:rdlen`, `:rdata` and `:wdata`
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

      # create a raw RR, ignoring :wdata and unknown fields
      iex> new(rdata: "not ignored", wdata: "ignored", unknown: "ignored")
      %DNS.Msg.RR{
        name: "",
        type: :A,
        class: :IN,
        ttl: 0,
        raw: true,
        rdlen: 11,
        rdmap: %{},
        rdata: "not ignored",
        wdata: ""
      }

      iex> new(type: :AAAA, name: "example.com", rdmap: %{ip: "acdc:1971::1"})
      %DNS.Msg.RR{
        name: "example.com",
        type: :AAAA,
        class: :IN,
        ttl: 0,
        raw: false,
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
        raw: false,
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
        raw: false,
        rdlen: 0,
        rdmap: %{},
        rdata: "",
        wdata: ""
      }

      iex> new() |> put(type: 65536)
      ** (DNS.Msg.Error) [unknown RR type] "valid range is 0..65535, got: 65536"

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

  defp do_put({k, v}, rr) when k == :rdata do
    # creating a raw RR, user is in control of RR here
    if is_binary(v) do
      rr
      |> Map.put(:rdata, v)
      |> Map.put(:rdlen, byte_size(v))
      |> Map.put(:raw, true)
    else
      error(:erdata, "expected a binary, got: #{inspect(v)}")
    end
  end

  # ignore other (or unknown) options
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
      raw: false,
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
  `DNS.Msg.Error` to be raised. See the list of RR's in
  [Encoding/decoding](#module-encoding-decoding).

  ## Examples

      iex> rr = new(type: :A, name: "example.com", rdmap: %{ip: {127, 0, 0, 1}})
      iex> encode(rr)
      %DNS.Msg.RR{
        name: "example.com",
        type: :A,
        class: :IN,
        ttl: 0,
        raw: false,
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
    rdata = if rr.raw, do: rr.rdata, else: encode_rdata(rr.type, rr.rdmap)
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
    required(:A, m, :ip)
    |> ip_encode(:ip4)
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

  # IN MB (7), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.3
  defp encode_rdata(:MB, m) do
    name =
      required(:MB, m, :name, &is_binary/1)
      |> dname_encode()

    <<name::binary>>
  end

  # IN MG (8), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.6
  defp encode_rdata(:MG, m) do
    name =
      required(:MG, m, :name, &is_binary/1)
      |> dname_encode()

    <<name::binary>>
  end

  # IN MR (9), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.8
  defp encode_rdata(:MR, m) do
    name =
      required(:MR, m, :name, &is_binary/1)
      |> dname_encode()

    <<name::binary>>
  end

  # IN NULL (10), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.10
  # data is simply rdata, since interpretation is upto caller
  defp encode_rdata(:NULL, m) do
    data = required(:NULL, m, :data, &is_binary/1)
    <<data::binary>>
  end

  # IN WKS (11), https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.2
  defp encode_rdata(:WKS, m) do
    ip = required(:WKS, m, :ip, &is_binary/1)
    proto = required(:WKS, m, :proto, &is_u8/1)
    services = required(:WKS, m, :services, &is_list/1)
    bitmap = bitmap_4_nrs(services)
    ip4 = ip_encode(ip, :ip4)
    <<ip4::binary, proto::8, bitmap::binary>>
  end

  # IN PTR (12), https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12
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

  # IN MINFO (14), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.7
  defp encode_rdata(:MINFO, m) do
    rmailbx =
      required(:MINFO, m, :rmailbx, &is_binary/1)
      |> dname_encode()

    emailbx =
      required(:MINFO, m, :emailbx, &is_binary/1)
      |> dname_encode()

    <<rmailbx::binary, emailbx::binary>>
  end

  # IN MX (15), https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9
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

  # IN RP (17), https://www.rfc-editor.org/rfc/rfc1183.html#section-2.2
  defp encode_rdata(:RP, m) do
    mail = required(:RP, m, :mail, &is_binary/1) |> dname_encode()
    txt = required(:RP, m, :txt, &is_binary/1) |> dname_encode()
    <<mail::binary, txt::binary>>
  end

  # IN AFSDB (18), https://www.rfc-editor.org/rfc/rfc1183.html#section-1
  defp encode_rdata(:AFSDB, m) do
    type = required(:AFSDB, m, :type, &is_u16/1)
    name = required(:AFSDB, m, :name, &is_binary/1) |> dname_encode()
    <<type::16, name::binary>>
  end

  # IN X25 (19), https://www.rfc-editor.org/rfc/rfc1183.html#section-3.1
  defp encode_rdata(:X25, m) do
    address = required(:X25, m, :address, &is_binary/1)
    len = String.length(address)
    <<len::8, address::binary>>
  end

  # IN ISDN (20), https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2
  defp encode_rdata(:ISDN, m) do
    address = required(:ISDN, m, :address, &is_binary/1)
    sa = required(:ISDN, m, :sa, &is_binary/1)
    lena = String.length(address)
    lens = String.length(sa)

    if lens > 0,
      do: <<lena::8, address::binary, lens::8, sa::binary>>,
      else: <<lena::8, address::binary>>
  end

  # IN RT (21), https://www.rfc-editor.org/rfc/rfc1183.html#section-3.3
  defp encode_rdata(:RT, m) do
    name = required(:RT, m, :name, &is_binary/1) |> dname_encode()
    pref = required(:RT, m, :pref, &is_u16/1)
    <<pref::16, name::binary>>
  end

  # IN AAAA (28)
  defp encode_rdata(:AAAA, m),
    do: required(:AAAA, m, :ip) |> ip_encode(:ip6)

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

  # IN KX (36), https://datatracker.ietf.org/doc/html/rfc2230#section-3
  defp encode_rdata(:KX, m) do
    pref = required(:KX, m, :pref, &is_u16/1)
    name = required(:KX, m, :name, &is_binary/1) |> dname_encode()
    <<pref::16, name::binary>>
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
        0 -> ""
        1 -> ip_encode(gwstr, :ip4)
        2 -> ip_encode(gwstr, :ip6)
        3 -> dname_encode(gwstr)
        n -> error(:eformat, "IPSECKEY gateway type unknown: #{inspect(n)}")
      end

    <<pref::8, gtype::8, algo::8, gateway::binary, pubkey::binary>>
  end

  # IN RRSIG (46), https://www.rfc-editor.org/rfc/rfc4034#section-3
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

  # IN NSEC (47), https://www.rfc-editor.org/rfc/rfc4034#section-4
  defp encode_rdata(:NSEC, m) do
    name = required(:NSEC, m, :name, &is_binary/1) |> dname_encode()
    covers = required(:NSEC, m, :covers, &is_list/1)
    bitmap = bitmap_4_rrs(covers)
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
    next_name = required(:NSEC3, m, :next_name, &is_binary/1)
    covers = required(:NSEC, m, :covers, &is_list/1)
    bitmap = bitmap_4_rrs(covers)

    <<algo::8, flags::8, iterations::16, byte_size(salt), salt::binary, byte_size(next_name)::8,
      next_name::binary, bitmap::binary>>
  end

  # IN NSEC3PARAM (51)
  # https://www.rfc-editor.org/rfc/rfc5155#section-4.1
  defp encode_rdata(:NSEC3PARAM, m) do
    algo = required(:NSEC3PARAM, m, :algo, &is_u8/1)
    flags = required(:NSEC3PARAM, m, :flags, &is_u8/1)
    iterations = required(:NSEC3PARAM, m, :iterations, &is_u16/1)
    salt = required(:NSEC3PARAM, m, :salt, &is_binary/1)
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

  # CSYNC (62), https://www.rfc-editor.org/rfc/rfc7477.html#section-2
  defp encode_rdata(:CSYNC, m) do
    soa_serial = required(:CSYNC, m, :soa_serial, &is_u32/1)
    flags = required(:CSYNC, m, :flags, &is_u16/1)
    covers = required(:CSYNC, m, :covers, &is_list/1)
    bitmap = bitmap_4_rrs(covers)
    <<soa_serial::32, flags::16, bitmap::binary>>
  end

  # IN ZONEMD (63), https://datatracker.ietf.org/doc/html/rfc8976#section-2
  defp encode_rdata(:ZONEMD, m) do
    serial = required(:ZONEMD, m, :serial, &is_u32/1)
    scheme = required(:ZONEMD, m, :scheme, &is_u8/1)
    algo = required(:ZONEMD, m, :algo, &is_u8/1)
    digest = required(:ZONEMD, m, :digest, &is_binary/1)
    <<serial::32, scheme::8, algo::8, digest::binary>>
  end

  # IN ANY/* (255)
  # pseudo QTYPE, never an RRtype, see also RFC882 and RFC8482

  # IN URI (256), https://www.rfc-editor.org/rfc/rfc7553.html#section-4.5
  defp encode_rdata(:URI, m) do
    prio = required(:URI, m, :prio, &is_u16/1)
    weight = required(:URI, m, :weight, &is_u16/1)
    target = required(:URI, m, :target, &is_binary/1)
    <<prio::16, weight::16, target::binary>>
  end

  # IN CAA (257), https://www.rfc-editor.org/rfc/rfc8659#section-4
  defp encode_rdata(:CAA, m) do
    flags = required(:CAA, m, :flags, &is_u8/1)
    tag = required(:CAA, m, :tag, &is_binary/1)
    value = required(:CAA, m, :value, &is_binary/1)
    <<flags::8, byte_size(tag)::8, tag::binary, value::binary>>
  end

  # AMTRELAY (260), https://datatracker.ietf.org/doc/html/rfc8777#section-4
  defp encode_rdata(:AMTRELAY, m) do
    pref = required(:AMTRELAY, m, :pref, &is_u8/1)
    d = required(:AMTRELAY, m, :d, &is_bool/1) |> bool_encode()
    type = required(:AMTRELAY, m, :type, &is_u7/1)
    relay = required(:AMTRELAY, m, :relay, &is_binary/1)

    relay =
      case type do
        0 -> <<>>
        1 -> ip_encode(relay, :ip4)
        2 -> ip_encode(relay, :ip6)
        3 -> dname_encode(relay)
        n -> error(:eformat, "AMTRELAY relay type unknown: #{inspect(n)}")
      end

    <<pref::8, d::bitstring-size(1), type::7, relay::binary>>
  end

  ## [[ catch all ]]
  # we're here because rr.raw is false and hence we MUST be able to encode!
  defp encode_rdata(type, rdmap),
    do: error(:errtype, "RR #{type}, cannot encode rdmap: #{inspect(rdmap)}")

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

  # [[ catch all]]
  defp encode_edns_opt(code, data),
    do: error(:eedns, "EDNS0 option #{inspect(code)} unknown or data illegal #{inspect(data)}")

  # [[ DECODE RR ]]

  @doc """
  Decodes an `RR` `t:t/0` struct at given `offset` in `msg` in wireformat.

  Upon success, returns {`new_offset`, `t:t/0`}, where `new_offset` can be used
  to read the rest of the message (if any).  The `rdlen`, `rdata` and `wdata`-fields
  are set based on the octets read during decoding.

  Not being able to decode a specific RR's RDATA, is not a fatal error in which case
  `rdmap` will be empty and the RR's `raw` field is set to true.

  ## Example

      iex> decode(5, <<"stuff", 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109,
      ...>   0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1, "more stuff">>)
      {32,
       %DNS.Msg.RR{
         name: "example.com",
         type: :A,
         class: :IN,
         ttl: 0,
         raw: false,
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
    raw = map_size(rdmap) == 0 and byte_size(rdata) > 0
    rr = %{rr | raw: raw, rdlen: rdlen, rdmap: rdmap, rdata: rdata, wdata: wdata}
    offset = offset2 + 10 + rdlen

    {offset, rr}
  end

  # [[ DECODE RDATA ]]
  # note: decode_rdata always takes type, offset, rdlen and msg:
  # - type define RR-type whose rdata is to be decoded
  # - rdlen is needed since some RR's have rdlen of 0
  # - offset, msg is needed since rdata may contain compressed domain names

  @spec decode_rdata(type, offset, length, binary) :: map
  defp decode_rdata(type, offset, rdlen, msg)

  # IN A (1)
  defp decode_rdata(:A, offset, 4, msg) do
    {_, ip} = ip_decode(offset, :ip4, msg)
    %{ip: ip}
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
    covers = bitmap_2_rrs(bitmap)
    %{soa_serial: soa_serial, flags: flags, covers: covers}
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

  # IN MB (7), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.3
  defp decode_rdata(:MB, offset, _rdlen, msg) do
    {_, name} = dname_decode(offset, msg)
    %{name: name}
  end

  # IN MG (8), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.6
  defp decode_rdata(:MG, offset, _rdlen, msg) do
    {_, name} = dname_decode(offset, msg)
    %{name: name}
  end

  # IN MR (9), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.8
  defp decode_rdata(:MR, offset, _rdlen, msg) do
    {_, name} = dname_decode(offset, msg)
    %{name: name}
  end

  # IN NULL (10), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.10
  defp decode_rdata(:NULL, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    %{data: rdata}
  end

  # IN WKS (11), https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.2
  defp decode_rdata(:WKS, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    {offset, ip} = ip_decode(0, :ip4, rdata)
    <<_::binary-size(offset), proto::8, bitmap::binary>> = rdata
    services = bitmap_2_nrs(bitmap)
    %{ip: ip, proto: proto, services: services, _bitmap: bitmap}
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

  # IN MINFO (14), https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.70
  defp decode_rdata(:MINFO, offset, _rdlen, msg) do
    {offset, rmailbx} = dname_decode(offset, msg)
    {_, emailbx} = dname_decode(offset, msg)
    %{rmailbx: rmailbx, emailbx: emailbx}
  end

  # IN MX (15), https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9
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

  # IN RP (17), https://www.rfc-editor.org/rfc/rfc1183.html#section-2.2
  defp decode_rdata(:RP, offset, _rdlen, msg) do
    {offset, mail} = dname_decode(offset, msg)
    {_offset, txt} = dname_decode(offset, msg)

    %{mail: mail, txt: txt}
  end

  # IN AFSDB (18), https://www.rfc-editor.org/rfc/rfc1183.html#section-1
  defp decode_rdata(:AFSDB, offset, _rdlen, msg) do
    <<_::binary-size(offset), type::16, _::binary>> = msg
    {_offset, name} = dname_decode(offset + 2, msg)

    %{type: type, name: name}
  end

  # IN X25 (19), https://www.rfc-editor.org/rfc/rfc1183.html#section-3.1
  defp decode_rdata(:X25, offset, _rdlen, msg) do
    <<_::binary-size(offset), len::8, address::binary-size(len), _::binary>> = msg
    %{address: address}
  end

  # IN ISDN (20), https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2
  defp decode_rdata(:ISDN, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    dta = for <<len::8, txt::binary-size(len) <- rdata>>, do: txt

    {addr, sa} =
      case dta do
        [addr] -> {addr, ""}
        [addr, sa] -> {addr, sa}
        _ -> error(:eformat, "ISDN RR, unexpected data #{inspect(rdata)}")
      end

    %{address: addr, sa: sa}
  end

  # IN RT (21), https://www.rfc-editor.org/rfc/rfc1183.html#section-3.3
  defp decode_rdata(:RT, offset, _rdlen, msg) do
    <<_::binary-size(offset), pref::16, _::binary>> = msg
    {_, name} = dname_decode(offset + 2, msg)
    %{name: name, pref: pref}
  end

  # IN AAAA (28)
  defp decode_rdata(:AAAA, offset, 16, msg) do
    {_, ip} = ip_decode(offset, :ip6, msg)
    %{ip: ip}
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

  # IN KX (36), https://datatracker.ietf.org/doc/html/rfc2230#section-3
  defp decode_rdata(:KX, offset, _rdlen, msg) do
    <<_::binary-size(offset), pref::16, _::binary>> = msg
    {_offset, name} = dname_decode(offset + 2, msg)
    %{name: name, pref: pref}
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

  # DNAME (39), https://www.rfc-editor.org/rfc/rfc6672.html#section-2.1
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

  # IN DS (43), https://www.rfc-editor.org/rfc/rfc4034#section-5
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

  # SSHFP (44), https://www.rfc-editor.org/rfc/rfc4255.html#section-3.1
  defp decode_rdata(:SSHFP, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<algo::8, type::8, fp::binary>> = rdata

    %{
      algo: algo,
      type: type,
      fp: fp
    }
  end

  # IPSECKEY (45), https://www.rfc-editor.org/rfc/rfc4025.html#section-2
  defp decode_rdata(:IPSECKEY, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<pref::8, gw_type::8, algo::8, rest::binary>> = rdata

    {gateway, pubkey} =
      case gw_type do
        0 ->
          {<<>>, rest}

        1 ->
          {offset, ip} = ip_decode(0, :ip4, rest)
          <<_::binary-size(offset), pkey::binary>> = rest
          {ip, pkey}

        2 ->
          {offset, ip} = ip_decode(0, :ip6, rest)
          <<_::binary-size(offset), pkey::binary>> = rest
          {ip, pkey}

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

  # IN RRSIG (46), https://www.rfc-editor.org/rfc/rfc4034#section-3
  defp decode_rdata(:RRSIG, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<type::16, algo::8, labels::8, ttl::32, notafter::32, notbefore::32, keytag::16,
      rest::binary>> = rdata

    # no name compression allowed in RRSIG, so we stay within `rest`
    {offset, name} = dname_decode(0, rest)
    <<_::binary-size(offset), signature::binary>> = rest

    # {:ok, notafter} = DateTime.from_unix(notafter, :second)
    # {:ok, notbefore} = DateTime.from_unix(notbefore, :second)

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

  # IN NSEC (47), https://www.rfc-editor.org/rfc/rfc4034#section-4
  defp decode_rdata(:NSEC, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    {offset, name} = dname_decode(0, rdata)
    <<_::binary-size(offset), bitmap::binary>> = rdata
    covers = bitmap_2_rrs(bitmap)
    %{name: name, covers: covers}
  end

  # IN DNSKEY (48), https://www.rfc-editor.org/rfc/rfc4034#section-2
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

  # IN NSEC3 (50), https://www.rfc-editor.org/rfc/rfc5155#section-3.2
  defp decode_rdata(:NSEC3, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<algo::8, flags::8, iter::16, slen::8, salt::binary-size(slen), hlen::8,
      next_name::binary-size(hlen), bitmap::binary>> = rdata

    covers = bitmap_2_rrs(bitmap)

    %{
      algo: algo,
      flags: flags,
      iterations: iter,
      salt_len: slen,
      salt: salt,
      hash_len: hlen,
      next_name: next_name,
      covers: covers
    }
  end

  # IN NSEC3PARAM (51), https://www.rfc-editor.org/rfc/rfc5155#section-4.1
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

  # IN TLSA (52), https://www.rfc-editor.org/rfc/rfc6698#section-2
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

  # IN CDS (59), https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1
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

  # IN CDNSKEY (60), https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2
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

  # IN ZONEMD (63), https://datatracker.ietf.org/doc/html/rfc8976#section-2
  defp decode_rdata(:ZONEMD, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg
    <<serial::32, scheme::8, algo::8, digest::binary>> = rdata
    %{serial: serial, scheme: scheme, algo: algo, digest: digest}
  end

  # IN HTTPS (65), https://www.rfc-editor.org/rfc/rfc9460.html#name-rdata-wire-format

  # IN ANY/* (255)
  # pseudo QTYPE, never an RRtype, see also RFC882 and RFC8482

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

  # AMTRELAY (260), https://datatracker.ietf.org/doc/html/rfc8777#section-4
  defp decode_rdata(:AMTRELAY, offset, rdlen, msg) do
    <<_::binary-size(offset), rdata::binary-size(rdlen), _::binary>> = msg

    <<pref::8, d::1, type::7, rest::binary>> = rdata

    relay =
      case type do
        0 -> ""
        1 -> ip_decode(0, :ip4, rest) |> elem(1)
        2 -> ip_decode(0, :ip6, rest) |> elem(1)
        3 -> dname_decode(offset + 2, msg) |> elem(1)
        n -> error(:eformat, "AMTRELAY relay type unknown: #{inspect(n)}")
      end

    %{pref: pref, d: d, type: type, relay: relay}
  end

  ## [[ catch all ]]
  # no decoder available, so simply return empty rdmap
  # if rdata is non-empty, will cause the rr.raw to be set to true
  defp decode_rdata(_type, _offset, _rdlen, _msg),
    do: %{}

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
  defp decode_edns_opt(code, _, data),
    do: {code, data}

  # [[ HELPERS ]]

  @doc false
  # convert bitmap to list of bit numbers whose value is '1'
  # bit number 0 is left-most (msb) bit
  defp bitmap_2_nrs(bitmap) do
    bitmap_2_nrs(bitmap, 0, [])
  end

  defp bitmap_2_nrs(<<0::1, rest::bitstring>>, n, acc),
    do: bitmap_2_nrs(rest, n + 1, acc)

  defp bitmap_2_nrs(<<1::1, rest::bitstring>>, n, acc),
    do: bitmap_2_nrs(rest, n + 1, [n | acc])

  defp bitmap_2_nrs(<<>>, _n, acc),
    do: Enum.reverse(acc)

  defp bitmap_4_nrs(nrs) do
    nrs
    |> Enum.sort(:asc)
    |> Enum.reduce(<<>>, fn n, acc -> bitmap_expand(acc, n) end)
    |> bitmap_pad()
  end

  defp bitmap_expand(bits, n) do
    fill = n - bit_size(bits)
    <<bits::bitstring, 0::size(fill), 1::1>>
  end

  defp bitmap_pad(bmap, b \\ 0)

  defp bitmap_pad(bmap, _b) when rem(bit_size(bmap), 8) == 0,
    do: bmap

  defp bitmap_pad(bmap, b),
    do: bitmap_pad(<<bmap::bitstring, b::1>>)

  # NSEC (3) bitmap conversion to/from list of RR type numbers
  # - https://www.rfc-editor.org/rfc/rfc4034#section-4.1.2
  defp bitmap_2_rrs(bin) do
    for <<w::8, len::8, bmap::binary-size(len) <- bin>> do
      bitmap_2_nrs(bmap)
      |> Enum.map(fn n -> n + w * 256 end)
    end
    |> List.flatten()
    |> Enum.map(fn n -> decode_rr_type(n) end)
  end

  defp bitmap_block(w, nrs) do
    bmap =
      nrs
      |> Enum.map(fn n -> n - w * 256 end)
      |> bitmap_4_nrs()

    l = byte_size(bmap)
    <<w::8, l::8, bmap::binary>>
  end

  defp bitmap_4_rrs(rrs) do
    # TODO: maybe filter out QTYPEs like ANY (255), AXFR (252), IXFR (251), OPT (41)
    # or leave that up to the caller so experimentation remains possible
    Enum.map(rrs, fn n -> encode_rr_type(n) end)
    |> Enum.sort(:asc)
    |> Enum.group_by(fn n -> div(n, 256) end)
    |> Enum.map(fn {w, nrs} -> bitmap_block(w, nrs) end)
    |> Enum.join()
  end

  @spec bool_encode(boolean | 0 | 1) :: bitstring
  defp bool_encode(n) do
    # note the lack of bool_decode, since that's better done directly
    case n do
      true -> <<1::1>>
      false -> <<0::1>>
      0 -> <<0::1>>
      1 -> <<1::1>>
      n -> error(:evalue, "expected true,false,0 or 1, got: #{inspect(n)}")
    end
  end

  @spec ip_decode(offset, :ip4 | :ip6, binary) :: {offset, binary}
  defp ip_decode(offset, version, msg) do
    {bytes, bits} =
      case version do
        :ip4 -> {4, 32}
        :ip6 -> {8, 128}
      end

    <<_::binary-size(offset), ip::size(bits), _::binary>> = msg
    {offset + bytes, "#{Pfx.new(<<ip::size(bits)>>, bits)}"}
  end

  @spec ip_encode(any, :ip4 | :ip6) :: binary
  defp ip_encode(ip, version) do
    # uses padr to ensure `addr` is a full address, not just a prefix
    with {:ok, pfx} <- Pfx.parse(ip),
         ^version <- Pfx.type(pfx),
         addr <- Pfx.padr(pfx) do
      addr.bits
    else
      _ ->
        error(:erdmap, "invalid IP address, got: #{inspect(ip)}")
    end
  end

  # used to check rdmap for mandatory fields when encoding an RR
  # a convencience func that also gives consistent, clear error messages
  defp required(type, map, field, check \\ fn _ -> true end) do
    v = Map.get(map, field) || error(:erdmap, "#{type} RR missing #{field}, got: #{inspect(map)}")

    if check.(v),
      do: v,
      else: error(:erdmap, "#{type} RR, field #{inspect(field)} has invalid value: #{inspect(v)}")
  end
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
