defmodule DNS.Param do
  # beware, here be dragons

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
      {:NAPTR, 35},
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

    # [[ function heads with spec & doc string ]]

    @doc """
    Returns the numeric value for given `name` of the `#{name}` parameter.

    When given a valid numeric value, it is simply returned as-is.  \\
    Raises `DNS.MsgError` for unknown names or invalid values.

    """
    @spec unquote(encode)(name | value) :: value | DNS.MsgError.t()
    def unquote(encode)(name)

    @doc """
    Returns the name for given `value` of the `#{name}` parameter.

    When given a valid name instead, it is returned as-is.  \\
    Raises `DNS.MsgError` on invalid values or unknown names.

    """
    @spec unquote(decode)(name | value) :: name | DNS.MsgError.t()
    def unquote(decode)(value)

    @doc """
    Returns `true` if given `arg` is a valid value or name of the `#{name}` parameter,
    `false` otherwise.

    """
    @spec unquote(valid)(name | value) :: boolean
    def unquote(valid)(arg)

    @doc """
    Returns the list of known `{name, value}` pairs for the `#{name}` parameter.

    ```elixir
    # These are:
    #{inspect(@params[name], pretty: true, width: 10)}
    ```

    """
    @spec unquote(list)() :: [{name, value}]
    def unquote(list)()

    # [[ function definitions ]]

    for {k, v} <- parms do
      s = Atom.to_string(k)
      def unquote(encode)(unquote(k)), do: unquote(v)
      def unquote(encode)(unquote(v)), do: unquote(v)
      def unquote(encode)(unquote(s)), do: unquote(v)
      def unquote(decode)(unquote(v)), do: unquote(k)
      def unquote(decode)(unquote(k)), do: unquote(k)
      def unquote(decode)(unquote(s)), do: unquote(k)
    end

    # [[ simply return valid, but unnamed, values ]]

    case name do
      name when name in [:class, :rrtype, :edns_option, :edns_ede] ->
        def unquote(decode)(k) when k in 0..65535, do: k
        def unquote(encode)(k) when k in 0..65535, do: k

      name when name in [:opcode, :rcode] ->
        def unquote(decode)(k) when k in 0..15, do: k
        def unquote(encode)(k) when k in 0..15, do: k

      name when name in [:dnssec_algo, :ds_digest] ->
        def unquote(decode)(k) when k in 0..255, do: k
        def unquote(encode)(k) when k in 0..255, do: k

      _ ->
        nil
    end

    # [[ catch all's ]]

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

  # [[ MODULE DOC ]]

  @moduledoc """
  Functions to work with DNS Parameters

  The `.._encode/1` functions map a parameter name to its numeric value. The
  name is usually an uppercase atom (like `:A`), but can also be its uppercase
  string version (like "A").  If given a valid numeric value, it is simply
  returned. These functions raise `t:DNS.MsgError.t/0` on unknown names or
  invalid numerical values.

  The `.._decode/1` functions map a numeric value to its parameter name. The value
  is usually numeric and if known, an atom name is returned.  If the value is a
  valid atom name or string name, the atom name is returned.  If the value is numeric,
  not known but valid, it is simply returned as-is.  If the value is an unknown name
  or an invalid numeric value, a `t:DNS.MsgError.t/0` is raised.

  The `.._valid?/1` functions take either a name (uppercase atom or binary) or a numeric
  value and return `true` if it is valid, `false` otherwise.

  The `.._list/0` functions simply return a list of known `{name, value}`-pairs
  for the given type of parameter that can be mapped back and forth between
  symbolic name and its numeric value.

  ## Examples

      # LIST

      iex> class_list()
      [{:RESERVED, 0}, {:IN, 1}, {:CH, 3}, {:HS, 4}, {:NONE, 254}, {:ANY, 255}]

      # VALID?

      iex> class_valid?(:IN)
      true

      iex> class_valid?(1)
      true

      # unassigned, but valid class value
      iex> class_valid?(2)
      true

      iex> class_valid?(:OOPS)
      false

      iex> class_valid?(65536)
      false

      # ENCODING

      iex> class_encode(:IN)
      1

      iex> class_encode("IN")
      1

      iex> class_encode(1)
      1

      iex> class_encode(:OOPS)
      ** (DNS.MsgError) [encode] class_encode: unknown parameter name ':OOPS'

      # unknown but valid numeric values are returned as-is
      iex> class_encode(42)
      42

      iex> class_encode(65536)
      ** (DNS.MsgError) [encode] class_encode: unknown parameter name '65536'

      # DECODING

      iex> class_decode(1)
      :IN

      iex> class_decode(:IN)
      :IN

      iex> class_decode("IN")
      :IN

      iex> class_decode(42)
      42

      iex> class_decode(:OOPS)
      ** (DNS.MsgError) [decode] class_decode: unknown parameter value ':OOPS'

      iex> class_decode(65536)
      ** (DNS.MsgError) [decode] class_decode: unknown parameter value '65536'


  For lists of known `{name, value}`-mappings, see the `..list/0` functions for
  the parameter of interest.

  ## TODO
  - [ ] [nsec3 params](https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml)


  """
end
