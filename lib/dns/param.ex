defmodule DNS.Param do
  # @moduledoc """
  # Low level functions to convert between DNS Param numbers and atom (or strings)
  #
  # ## Examples
  #
  #     iex> class_encode(:IN)
  #     1
  #
  #     iex> class_encode("IN")
  #     1
  #
  #     iex> class_encode(1)
  #     1
  #
  #     iex> class_encode(:OOPS)
  #     ** (DNS.MsgError) [encode] class_encode: unknown parameter name ':OOPS'
  #
  #     iex> class_encode(42)
  #     ** (DNS.MsgError) [encode] class_encode: unknown parameter name '42'
  #
  #
  # """
  import DNS.MsgError, only: [error: 2]

  @typedoc "A parameter's name, either an uppercase atom or uppercase binary"
  @type name :: atom | binary

  @typedoc "A parameter's numeric value"
  @type value :: non_neg_integer

  @params %{
    :class => [
      {:RESERVED, 0},
      {:IN, 1},
      {:CH, 3},
      {:HS, 4},
      {:NONE, 254},
      {:ANY, 255}
    ],
    :opcode => [
      {:QUERY, 0},
      {:IQUERY, 1},
      {:STATUS, 2},
      {:NOTIFY, 4},
      {:UPDATE, 5},
      {:DSO, 6}
    ],
    :rcode => [
      {:NOERROR, 0},
      {:FORMERROR, 1},
      {:SERVFAIL, 2},
      {:NXDOMAIN, 3},
      {:NOTIMP, 4},
      {:REFUSED, 5},
      # YX<name> name exists when it shouldn't
      {:YXDOMAIN, 6},
      {:YXRRSET, 7},
      # NX<name> name should exist but does not
      {:NXRRSET, 8},
      {:NOTAUTH, 9},
      {:NOTZONE, 10},
      {:DSOTYPENI, 11},
      {:BADVERS, 16},
      {:BADKEY, 17},
      {:BADTIME, 18},
      {:BADMODE, 19},
      {:BADNAME, 20},
      {:BADALG, 21},
      {:BADTRUNC, 22},
      {:BADCOOKIE, 23}
    ],
    :rrtype => [
      {:RESERVED, 0},
      {:A, 1},
      {:NS, 2},
      {:CNAME, 5},
      {:SOA, 6},
      {:MB, 7},
      {:MG, 8},
      {:MR, 9},
      {:NULL, 10},
      {:WKS, 11},
      {:PTR, 12},
      {:HINFO, 13},
      {:MINFO, 14},
      {:MX, 15},
      {:TXT, 16},
      {:RP, 17},
      {:AFSDB, 18},
      {:X25, 19},
      {:ISDN, 20},
      {:RT, 21},
      {:AAAA, 28},
      {:SRV, 33},
      {:KX, 36},
      {:CERT, 37},
      {:DNAME, 39},
      {:OPT, 41},
      {:DS, 43},
      {:SSHFP, 44},
      {:IPSECKEY, 45},
      {:RRSIG, 46},
      {:NSEC, 47},
      {:DNSKEY, 48},
      {:NSEC3, 50},
      {:NSEC3PARAM, 51},
      {:TLSA, 52},
      {:CDS, 59},
      {:CDNSKEY, 60},
      {:OPENPGPKEY, 61},
      {:CSYNC, 62},
      {:ZONEMD, 63},
      {:HTTPS, 65},
      {:SPF, 99},
      {:IXFR, 251},
      {:AXFR, 252},
      {:MAILB, 253},
      {:MAILA, 254},
      {:ANY, 255},
      {:URI, 256},
      {:CAA, 257},
      {:AMTRELAY, 260}
    ],
    :edns_option => [
      {:RESERVED, 0},
      {:LLQ, 1},
      {:UL, 2},
      {:NSID, 3},
      {:DAU, 5},
      {:DHU, 6},
      {:N3U, 7},
      {:CLIENT_SUBNET, 8},
      {:EXPIRE, 9},
      {:COOKIE, 10},
      {:TCP_KEEPALIVE, 11},
      {:PADDING, 12},
      {:CHAIN, 13},
      {:KEY_TAG, 14},
      {:EXTENDED_DNS_ERROR, 15},
      {:CLIENT_TAG, 16},
      {:SERVER_TAG, 17},
      {:UMBRELLA_IDENT, 20292},
      {:DEVICEID, 26946}
    ],

    # EDNS Extended DNS Error codes
    # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes

    :edns_ede => [
      {:OTHER, 0},
      {:DNSKEY_ALGO, 1},
      {:DS_DIGEST, 2},
      {:STALE, 3},
      {:FORGED, 4},
      {:INDETERMINATE, 5},
      {:BOGUS, 6},
      {:SIG_EXPIRED, 7},
      {:SIG_NOTYET_VALID, 8},
      {:NO_DNSKEY, 9},
      {:NO_RRSIGS, 10},
      {:NO_ZONE_KEYBIT, 11},
      {:NO_NSEC, 12},
      {:CACHED_ERROR, 13},
      {:NOT_READY, 14},
      {:BLOCKED, 15},
      {:CENSORED, 16},
      {:FILTERED, 17},
      {:PROHIBITED, 18},
      {:STALE_NXDOMAIN, 19},
      {:NOT_AUTHORITATIVE, 20},
      {:NOT_SUPPORTED, 21},
      {:NO_REACHABLE_AUTHORITIES, 22},
      {:NETWORK_ERROR, 23},
      {:INVALID_DATA, 24},
      {:SIG_EXPIRED_BEFORE_VALID, 25},
      {:TOO_EARLY, 26},
      {:NSEC_ITER_VALUE, 27},
      {:POLICY, 28},
      {:SYNTHESIZED, 29}
    ],
    :dnssec_algo => [
      {:DELETE, 0},
      {:RSAMD5, 1},
      {:DH, 2},
      {:DSA, 3},
      {:RSASHA1, 5},
      {:DSA_NSEC3_SHA1, 6},
      {:RSASHA1_NSEC3_SHA1, 7},
      {:RSASHA256, 8},
      {:RSASHA512, 10},
      {:ECC_GOST, 12},
      {:ECDSAP256SHA256, 13},
      {:ECDSAP384SHA384, 14},
      {:ED25519, 15},
      {:ED448, 16},
      {:SM2SM3, 17},
      {:ECC_GOST12, 23},
      {:INDIRECT, 252},
      {:PRIVATEDNS, 253},
      {:PRIVATEOID, 254}
    ],
    :ds_digest => [
      {:RESERVED, 0},
      {:SHA1, 1},
      {:SHA256, 2},
      {:GOST, 3},
      {:SHA384, 4},
      {:GOST12, 5},
      {:SM3, 6}
    ]
  }

  defp params(param),
    do: @params[param] || []

  # [[ CODECs ]]

  for {name, parms} <- @params do
    encode = String.to_atom("#{name}_encode")
    decode = String.to_atom("#{name}_decode")
    list = String.to_atom("#{name}_list")
    valid = String.to_atom("#{name}_valid?")

    @spec unquote(encode)(name | value) :: value | DNS.MsgError.t()
    @spec unquote(decode)(name | value) :: name | DNS.MsgError.t()
    @spec unquote(list)() :: [{name, value}]
    @spec unquote(valid)(name | value) :: boolean

    for {k, v} <- parms do
      s = Atom.to_string(k)
      def unquote(encode)(unquote(k)), do: unquote(v)
      def unquote(encode)(unquote(v)), do: unquote(v)
      def unquote(encode)(unquote(s)), do: unquote(v)
      def unquote(decode)(unquote(v)), do: unquote(k)
      def unquote(decode)(unquote(k)), do: unquote(k)
      def unquote(decode)(unquote(s)), do: unquote(k)
    end

    def unquote(encode)(k),
      do: error(:eencode, "#{unquote(encode)}: unknown parameter name '#{inspect(k)}'")

    def unquote(decode)(v),
      do: error(:edecode, "#{unquote(decode)}: unknown parameter value '#{inspect(v)}'")

    def unquote(list)(),
      do: params(unquote(name))

    def unquote(valid)(parm) do
      unquote(encode)(parm)
      true
    rescue
      _ -> false
    end
  end

  @moduledoc """
  Functions to work with DNS Parameters

  The `.._encode/1` functions map a parameter name to its numeric value. The name is
  usually an uppercase atom (like `:A`), but can also be its uppercase string
  version (like "A").  If given a valid numeric value, it is simply returned.
  These functions raise `t:DNS.MsgError.t/0` on invalid or unknown names or values.

  The `.._decode/1` functions map a numeric value to its parameter name, which is
  always an uppercase atom.  If given a valid parameter name (uppercase atom or
  uppercase name) it is returned as an uppercase atom, if valid.  These
  functions raise `t:DNS.MsgError.t/0` on invalid or unknown names or values.

  The `.._valid?/1` functions take either a name (uppercase atom or binary) or a numeric
  value and return `true` if it is valid, `false` otherwise.

  The `.._list/0` functions simply return a list of `{name, value}`-pairs for the given
  type of parameter.

  ## Examples

      iex> class_encode(:IN)
      1

      iex> class_encode("IN")
      1

      iex> class_encode(1)
      1

      iex> class_encode(:OOPS)
      ** (DNS.MsgError) [encode] class_encode: unknown parameter name ':OOPS'

      iex> class_encode(42)
      ** (DNS.MsgError) [encode] class_encode: unknown parameter name '42'

  ## DNS classes

  Known [classes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2)
  include:

  ```
  #{inspect(@params[:class], pretty: true, width: 10)}
  ```

  ## DNS opcodes

  Known [opcodes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)
  include:

  ```
  #{inspect(@params[:opcode], pretty: true, width: 10)}
  ```

  ## DNS rcodes

  Known [rcodes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
  include:

  ```
  #{inspect(@params[:rcode], pretty: true, width: 10)}
  ```

  ## DNS rrtypes

  Known [rrtypes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
  include:

  ```
  #{inspect(@params[:rrtype], pretty: true, width: 10)}
  ```

  ## DNS edns_option

  Known [edns option codes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
  include:

  ```
  #{inspect(@params[:edns_option], pretty: true, width: 10)}
  ```

  ## EDNS Exteneded DNS Error (ede)

  Known [extended dns errors](https://www.iana.org/assignments/dns-parameters/dns-parameters.xml#extended-dns-error-codes)
  include:

  ```
  #{inspect(@params[:edns_ede], pretty: true, width: 10)}
  ```

  ## DNSSEC algorithm types

  Known [algo types](https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1)
  include:

  ```
  #{inspect(@params[:dnssec_algo], pretty: true, width: 10)}
  ```

  ## DS RR digest types

  Known [digest types](https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1)
  include:

  ```
  #{inspect(@params[:ds_digest], pretty: true, width: 10)}
  ```

  ## TODO
  - [ ] [xrcodes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
  - [ ] [nsec3 params](https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml)


  """
end
