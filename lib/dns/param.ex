defmodule DNS.Param do
  @moduledoc """
  Functions to map DNS parameter names to their values and vice versa.

  See
  [iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
  for more details on DNS parameters.

  """
  import DNS.MsgError, only: [error: 2]

  @typedoc "The name of a parameter's numeric value"
  @type name :: atom

  @typedoc "A parameter's numeric value"
  @type value :: non_neg_integer

  # DNS Parameter definitions for generating encode/decode/list/valid? functions
  # params = %{ {:name, range} => Keyword list of known name,value-pairs}.
  # - param type names (the keys) are atoms and used as prefix in function names
  # - the {name, value}-pairs as a list allows for ordering func defs by popularity
  # - each name and each value in the list must be unique due to pattern matching
  #   by the generated functions (compiler warns about redefining functions)
  # - generate encode/decode/list/valid? per parameter type instead of
  #   decode(:class, value) so you can use code completion instead of remembering
  #   the parameter type's atom.
  params = %{
    {:class, 0..65535} => [
      {:RESERVED, 0},
      {:IN, 1},
      {:CH, 3},
      {:HS, 4},
      {:NONE, 254},
      {:ANY, 255}
    ],
    {:opcode, 0..15} => [
      {:QUERY, 0},
      {:IQUERY, 1},
      {:STATUS, 2},
      {:NOTIFY, 4},
      {:UPDATE, 5},
      {:DSO, 6}
    ],
    {:rcode, 0..65535} => [
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
    {:rrtype, 0..65535} => [
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
    {:edns_option, 0..65535} => [
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
    {:edns_ede, 0..65535} => [
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
    {:dnssec_algo, 0..255} => [
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
    {:ds_digest, 0..255} => [
      {:RESERVED, 0},
      {:SHA1, 1},
      {:SHA256, 2},
      {:GOST, 3},
      {:SHA384, 4},
      {:GOST12, 5},
      {:SM3, 6}
    ]
  }

  @doc """
  Returns a list of parameter types and their valid ranges.

  ```
  #{inspect(Map.keys(params), pretty: true, limit: :infinity)}
  ```

  """
  @spec types() :: [{name, Range.t()}]
  def types do
    unquote(
      for {n, r} <- Map.keys(params),
          do: {n, Macro.escape(r)}
    )
  end

  for {{p, r}, l} <- params do
    range = Macro.escape(r)

    # [[ DECODE ]]

    name = String.to_atom("#{p}_decode")
    bang = String.to_atom("#{p}_decode!")

    @doc """
    Returns the name for given #{p} `value` in range #{inspect(r)}, or
    `value` itself if it has no name.

    When given a known name for a #{p} value (or a binary that can be
    converted to a known name) it returns that name.  Returns `nil` for unknown
    names or invalid values. See `#{p}_list/0` for known
    `{name, value}`-pairs.

    """
    @spec unquote(name)(value | name | binary) :: name | value | nil
    def unquote(name)(value)

    # map value -> name and vice versa
    for {k, v} <- l, do: def(unquote(name)(unquote(v)), do: unquote(k))
    for {k, _} <- l, do: def(unquote(name)(unquote(k)), do: unquote(k))

    # valid values without a name decode to themselves
    def unquote(name)(n) when n in unquote(range), do: n

    # given a binary, try it as an (existing) atom name
    def unquote(name)(str) when is_binary(str) do
      String.upcase(str) |> String.to_existing_atom() |> unquote(name)()
    rescue
      _ -> nil
    end

    def unquote(name)(_), do: nil

    @doc """
    Same as `#{name}/1`, but raises instead of returning `nil`

    """
    @spec unquote(bang)(value | name | binary) :: name | value | no_return
    def unquote(bang)(value) do
      case unquote(name)(value) do
        nil ->
          error(
            :eencode,
            "unknown #{unquote(p)} name or value not in #{inspect(unquote(range))}, got: '#{value}'"
          )

        value ->
          value
      end
    end

    # [[ ENCODE ]]

    name = String.to_atom("#{p}_encode")
    bang = String.to_atom("#{p}_encode!")

    @doc """
    Returns the value, in range #{inspect(r)}, for given #{p} `name`.

    When given a valid value, the value itself is returned. When given a binary
    that can be converted to a valid name, it returns the associated value.
    Returns `nil` for unknown names or invalid values.  See `#{p}_list/0` for
    known `{name, value}`-pairs.

    """
    @spec unquote(name)(name | value | binary) :: value | nil
    def unquote(name)(name)

    for {k, v} <- l, do: def(unquote(name)(unquote(k)), do: unquote(v))

    def unquote(name)(n) when n in unquote(range), do: n

    def unquote(name)(s) when is_binary(s) do
      String.upcase(s) |> String.to_existing_atom() |> unquote(name)()
    rescue
      _ -> nil
    end

    def unquote(name)(_), do: nil

    @doc """
    Same as `#{name}/1`, but raises on `nil`.

    """
    @spec unquote(bang)(name | value | binary) :: value | no_return
    def unquote(bang)(name) do
      case unquote(name)(name) do
        nil ->
          error(
            :eencode,
            "unknown #{unquote(p)} name or value not in #{inspect(unquote(range))}, got: '#{name}'"
          )

        value ->
          value
      end
    end

    # [[ VALID? ]]

    name = String.to_atom("#{p}_valid?")

    @doc """
    Returns `true` if given a known name or valid value (in #{inspect(r)})
    for the #{p} parameter, `false` otherwise.

    Also returns `true` when given a binary that can be converted to a known
    `t:name/0`.

    """
    @spec unquote(name)(name | value | binary) :: boolean
    def unquote(name)(name_or_value)

    # for {k, v} <- l, do: def(unquote(name)(unquote(v)), do: true)
    for {k, _} <- l, do: def(unquote(name)(unquote(k)), do: true)

    def unquote(name)(n) when n in unquote(range), do: true

    def unquote(name)(s) when is_binary(s) do
      String.upcase(s) |> String.to_existing_atom() |> unquote(name)()
    rescue
      _ -> nil
    end

    def unquote(name)(_), do: false

    # [[ LIST ]]

    name = String.to_atom("#{p}_list")

    @doc """
    Returns the known `t:name/0`,`t:value/0`-pairs for the #{p} parameter.

    These include:
    ```
    #{inspect(l, pretty: true, width: 10, limit: :infinity)}
    ```
    """
    @spec unquote(name)() :: [{name, value}]
    def unquote(name)(), do: unquote(l)
  end
end
