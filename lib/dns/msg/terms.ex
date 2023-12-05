defmodule DNS.Msg.Terms do
  @moduledoc """
  Low level functions to convert between field names (atoms) and their numeric values.

  In general:
  - encoders return a non negative number, while
  - decoders return a `:NAME`, if possible.

  Both encoders and decoders take either an atom (e.g. `:A`) or a non negative number (e.g. `1`).
  A given name must exist, otherwise an error is raised.  Likewise, a number must be in range for the
  given field, otherwise an error is raised.

  See [IANA - DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

  """

  alias DNS.Utils
  alias DNS.Msg.Error

  # [[ Helpers ]]

  defp error(reason, data),
    do: raise(Error.exception(reason: reason, data: data))

  @spec do_encode(map, atom | non_neg_integer, atom, Range.t()) :: non_neg_integer
  defp do_encode(_map, key, label, range) when is_integer(key) do
    if key in range,
      do: key,
      else: error(label, "valid range is #{inspect(range)}, got: #{key}")
  end

  defp do_encode(map, key, label, _range) when is_atom(key) do
    case Map.get(map, key) do
      nil -> error(label, "#{key} is unknown")
      num -> num
    end
  end

  defp do_encode(_map, key, label, _range),
    do: error(label, "Expected an atom or non neg number, got: #{inspect(key)}")

  @spec do_decode(map, atom | non_neg_integer, atom, Range.t()) :: atom | non_neg_integer
  defp do_decode(map, key, label, _range) when is_atom(key) do
    if Map.has_key?(map, key),
      do: key,
      else: error(label, "#{key} is unknown")
  end

  defp do_decode(map, key, label, range) when is_integer(key) do
    if key in range do
      case Map.get(map, key) do
        nil -> key
        name -> name
      end
    else
      error(label, "valid range is #{inspect(range)}, got: #{key}")
    end
  end

  defp do_decode(_map, key, label, _range),
    do: error(label, "Expected an atom or non neg number, got: #{inspect(key)}")

  # [[ DNS CLASS ]]
  @dns_classes %{
                 RESERVED: 0,
                 IN: 1,
                 CH: 3,
                 HS: 4,
                 NONE: 254,
                 ANY: 255
               }
               |> Utils.normalize_name_map()

  @doc """
  Encode a DNS class to its numeric value.

  Note that although the class is usually `:IN` (1), there are cases when the
  `class` field in an RR is used for other purposes, e.g. in a EDNS0 pseudo-RR
  where the class field is used to denote the requestor's acceptable buffer
  size for udp payloads.

  Known DNS classes include:
  ```
  #{inspect(Map.filter(@dns_classes, fn {k, _} -> is_atom(k) end), pretty: true, width: 10)}
  ```

  See [IANA - DNS CLASSes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2)

  ## Examples

      # Internet class
      iex> encode_dns_class(:IN)
      1

      # rfc2136
      iex> encode_dns_class(:NONE)
      254

      # rfc1035
      iex> encode_dns_class(:ANY)
      255

      # or just use the number, e.g. in an EDNS0 pseudo-RR
      iex> encode_dns_class(1410)
      1410

      # raises on unknown names
      iex> encode_dns_class(:ABBA)
      ** (DNS.Msg.Error) [invalid class] "ABBA is unknown"

      # raises on invalid values
      iex> encode_dns_class(65536)
      ** (DNS.Msg.Error) [invalid class] "valid range is 0..65535, got: 65536"


  """
  @spec encode_dns_class(atom | non_neg_integer) :: non_neg_integer
  def encode_dns_class(class),
    do: do_encode(@dns_classes, class, :eclass, 0..65535)

  @doc """
  Decode a DNS class to its name, if possible.

  See `encode_dns_class/1` for the names available .

  ## Examples

      iex> decode_dns_class(1)
      :IN

      iex> decode_dns_class(1410)
      1410

      iex> decode_dns_class(:IN)
      :IN

      # raises on unknown names
      iex> decode_dns_class(:ABBA)
      ** (DNS.Msg.Error) [invalid class] "ABBA is unknown"

      # raises on invalid values
      iex> decode_dns_class(65536)
      ** (DNS.Msg.Error) [invalid class] "valid range is 0..65535, got: 65536"

  """
  @spec decode_dns_class(atom | non_neg_integer) :: atom | non_neg_integer()
  def decode_dns_class(class),
    do: do_decode(@dns_classes, class, :eclass, 0..65535)

  # [[ DNS OPCODES ]]
  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5

  @dns_opcodes %{
                 :QUERY => 0,
                 :IQUERY => 1,
                 :STATUS => 2,
                 :NOTIFY => 4,
                 :UPDATE => 5,
                 :DSO => 6
               }
               |> Utils.normalize_name_map()

  @doc """
  Encode a DNS opcode to its numeric value.

  Known classes include:
  ```
  #{inspect(Map.filter(@dns_opcodes, fn {k, _} -> is_atom(k) end), pretty: true, width: 10)}
  ```

  See [IANA - DNS Opcodes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)

  ## Examples

      iex> encode_dns_opcode(:QUERY)
      0

      iex> encode_dns_opcode(0)
      0

      # keep it raw
      iex> encode_dns_opcode(7)
      7

      # raises on unknown names
      iex> encode_dns_opcode(:ABC)
      ** (DNS.Msg.Error) [invalid opcode] "ABC is unknown"

      # raises on invalid values
      iex> encode_dns_opcode(16)
      ** (DNS.Msg.Error) [invalid opcode] "valid range is 0..15, got: 16"

  """
  @spec encode_dns_opcode(atom | non_neg_integer) :: non_neg_integer
  def encode_dns_opcode(opcode),
    do: do_encode(@dns_opcodes, opcode, :eopcode, 0..15)

  @doc """
  Decode a DNS opcode to its name, if possible.

  See `encode_dns_opcode/1` for the names available.

  See [IANA - DNS Opcodes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)

  ## Examples

      iex> decode_dns_opcode(0)
      :QUERY

      iex> decode_dns_opcode(:UPDATE)
      :UPDATE

      # keep it raw
      iex> decode_dns_opcode(7)
      7

      # raises on unknown names
      iex> decode_dns_opcode(:FOO_BAR)
      ** (DNS.Msg.Error) [invalid opcode] "FOO_BAR is unknown"

      # raises on invalid values
      iex> decode_dns_opcode(16)
      ** (DNS.Msg.Error) [invalid opcode] "valid range is 0..15, got: 16"

  """
  @spec decode_dns_opcode(atom | non_neg_integer) :: atom | non_neg_integer
  def decode_dns_opcode(opcode),
    do: do_decode(@dns_opcodes, opcode, :eopcode, 0..15)

  # [[ DNS RCODE ]]
  # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
  # https://www.rfc-editor.org/rfc/rfc6895.html
  # - RCODEs may appear in various parts of a DNS msg, not just the header
  @dns_rcodes %{
                :NOERROR => 0,
                :FORMERROR => 1,
                :SERVFAIL => 2,
                :NXDOMAIN => 3,
                :NOTIMP => 4,
                :REFUSED => 5,
                # YX<name> name exists when it shouldn't
                :YXDOMAIN => 6,
                :YXRRSET => 7,
                # NX<name> name should exist but does not
                :NXRRSET => 8,
                :NOTAUTH => 9,
                :NOTZONE => 10,
                :DSOTYPENI => 11,
                :BADVERS => 16,
                :BADKEY => 17,
                :BADTIME => 18,
                :BADMODE => 19,
                :BADNAME => 20,
                :BADALG => 21,
                :BADTRUNC => 22,
                :BADCOOKIE => 23
              }
              |> Utils.normalize_name_map()

  @doc """
  Encode a DNS RCODE to its numeric value.

  Known rcodes include:
  ```
  #{inspect(Map.filter(@dns_rcodes, fn {k, _} -> is_atom(k) end), pretty: true, width: 10)}
  ```

  Note that DNS RCODEs occur not only in the DNS header, but also in TSIG RRs, TKEY RRs
  and the EDNS0 pseudo-RR provides an 8-bit extension.  So the actual range of values for
  an rcode is `0..65535`, i.e. an unsigned 16 bit integer.

  See
  - [IANA - DNS RCODEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
  - [RFC6895 2.3](https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3)

  ## Examples

      iex> encode_dns_rcode(:NOERROR)
      0

      iex> encode_dns_rcode(0)
      0

      # raises on unknown names
      iex> encode_dns_rcode(:ABC)
      ** (DNS.Msg.Error) [invalid (x)rcode] "ABC is unknown"

      # raises on invalid values
      iex> encode_dns_rcode(65536)
      ** (DNS.Msg.Error) [invalid (x)rcode] "valid range is 0..65535, got: 65536"


  """
  @spec encode_dns_rcode(atom | non_neg_integer) :: non_neg_integer()
  def encode_dns_rcode(rcode),
    do: do_encode(@dns_rcodes, rcode, :ercode, 0..65535)

  @doc """
  Decode an DNS RCODE to its name, if possible.

  See `encode_dns_rcode/1` for the names available .

  ## Examples

      iex> decode_dns_rcode(2)
      :SERVFAIL

      iex> decode_dns_rcode(:SERVFAIL)
      :SERVFAIL

      # raises on unknown names
      iex> decode_dns_rcode(:OKIDOKI)
      ** (DNS.Msg.Error) [invalid (x)rcode] "OKIDOKI is unknown"

      # raises on invalid values
      iex> decode_dns_rcode(65536)
      ** (DNS.Msg.Error) [invalid (x)rcode] "valid range is 0..65535, got: 65536"

  """
  @spec decode_dns_rcode(atom | non_neg_integer) :: atom | non_neg_integer
  def decode_dns_rcode(rcode),
    do: do_decode(@dns_rcodes, rcode, :ercode, 0..65535)

  # [[ DNS TYPE ]]
  # See:
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
  # - https://www.rfc-editor.org/rfc/rfc3597#section-5
  # - https://www.rfc-editor.org/rfc/rfc6891, 6.1 OPT RR definition
  #   `-> pseudo-RR in addtional section of a DNS message
  # - https://www.rfc-editor.org/rfc/rfc6895.html#section-3

  @rr_types %{
              :RESERVED => 0,
              :A => 1,
              :NS => 2,
              :CNAME => 5,
              :SOA => 6,
              :PTR => 12,
              :HINFO => 13,
              :MX => 15,
              :TXT => 16,
              :AAAA => 28,
              :SRV => 33,
              :CERT => 37,
              :OPT => 41,
              :DS => 43,
              :SSHFP => 44,
              :IPSECKEY => 45,
              :RRSIG => 46,
              :NSEC => 47,
              :DNSKEY => 48,
              :NSEC3 => 50,
              :NSEC3PARAM => 51,
              :TLSA => 52,
              :CDS => 59,
              :CDNSKEY => 60,
              :HTTPS => 65,
              :SPF => 99,
              :* => 255,
              :ANY => 255,
              :CAA => 257
            }
            |> Utils.normalize_name_map()

  @doc """
  Encode an RR type to its numeric value.

  DNS types have 3 different subcategories: data (RR)types, Query types and
  Meta-Types.  Hence, they occur in various places including as query types, RR
  types and also in `types covered` fields in some RR's RDATA portion.

  Normally the value `0` is reserved, except in the `types covered` field of
  an RRSIG RR. The caller will have to be aware of its context when encoding
  or decoding TYPEs.

  Known RR types include:
  ```
  #{inspect(Map.filter(@rr_types, fn {k, _} -> is_atom(k) end), pretty: true, width: 10)}
  ```
  See:
  - [IANA DNS Params](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
  - [RFC6895, sec 3](https://www.rfc-editor.org/rfc/rfc6895.html#section-3)

  ## Examples

      iex> encode_rr_type(:A)
      1

      iex> encode_rr_type(:HTTPS)
      65

      # raises on unknown names
      iex> encode_rr_type(:ABC)
      ** (DNS.Msg.Error) [invalid RR type] "ABC is unknown"

      # raises on invalid value
      iex> encode_rr_type(65536)
      ** (DNS.Msg.Error) [invalid RR type] "valid range is 0..65535, got: 65536"

  """
  @spec encode_rr_type(atom | non_neg_integer) :: non_neg_integer()
  def encode_rr_type(type),
    do: do_encode(@rr_types, type, :errtype, 0..65535)

  @doc """
  Decode an RR type to its name, if possible.

  See `encode_rr_type/1` for the names available .

  ## Examples

      iex> decode_rr_type(1)
      :A

      iex> decode_rr_type(65)
      :HTTPS

      iex> decode_rr_type(:HTTPS)
      :HTTPS

      # 3 is in range, so returned as-is
      iex> decode_rr_type(3)
      3

      # raises on unknown names
      iex> decode_rr_type(:ABC)
      ** (DNS.Msg.Error) [invalid RR type] "ABC is unknown"

      # raises on invalid value
      iex> decode_rr_type(65536)
      ** (DNS.Msg.Error) [invalid RR type] "valid range is 0..65535, got: 65536"

  See:
  - [IANA - DNS Params](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
  - [RFC3597](https://www.rfc-editor.org/rfc/rfc3597#section-5)

  """
  @spec decode_rr_type(atom | non_neg_integer) :: atom | non_neg_integer
  def decode_rr_type(type),
    do: do_decode(@rr_types, type, :errtype, 0..65535)

  # [[ DNS OPT CODE ]]
  # - https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  @dns_rropt_codes %{
                     :RESERVED => 0,
                     :LLQ => 1,
                     :UL => 2,
                     :NSID => 3,
                     :DAU => 5,
                     :DHU => 6,
                     :N3U => 7,
                     :CLIENT_SUBNET => 8,
                     :EXPIRE => 9,
                     :COOKIE => 10,
                     :TCP_KEEPALIVE => 11,
                     :PADDING => 12,
                     :CHAIN => 13,
                     :KEY_TAG => 14,
                     :EXTENDED_DNS_ERROR => 15,
                     :CLIENT_TAG => 16,
                     :SERVER_TAG => 17,
                     :UMBRELLA_IDENT => 20292,
                     :DEVICEID => 26946
                   }
                   |> Utils.normalize_name_map()

  @doc """
  Encode an [EDNS0
  OPT-RR](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
  Code to its numeric value.

  Known OPT Codes include:
  ```
  #{inspect(Map.filter(@dns_rropt_codes, fn {k, _} -> is_atom(k) end), pretty: true, width: 10)}
  ```

  ## Examples

      iex> encode_rropt_code(:NSID)
      3

      # keeping it raw
      iex> encode_rropt_code(99)
      99

      # raises on unknown names
      iex> encode_rropt_code(:ABC)
      ** (DNS.Msg.Error) [invalid edns] "ABC is unknown"

      # raises on invalid values
      iex> encode_rropt_code(65536)
      ** (DNS.Msg.Error) [invalid edns] "valid range is 0..65535, got: 65536"

  """
  @spec encode_rropt_code(atom | non_neg_integer) :: non_neg_integer()
  def encode_rropt_code(code),
    do: do_encode(@dns_rropt_codes, code, :eedns, 0..65535)

  @doc """
  Decode an [EDNS0
  OPT-RR](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
  Code to its name, if possible.

  See `encode_rropt_code/1` for known names.

  ## Examples

      iex> decode_rropt_code(3)
      :NSID

      iex> decode_rropt_code(:NSID)
      :NSID

      # keep it raw
      iex> decode_rropt_code(4)
      4

      # raises on unknown names
      iex> decode_rropt_code(:ABC)
      ** (DNS.Msg.Error) [invalid edns] "ABC is unknown"

      # raises on invalid values
      iex> decode_rropt_code(65536)
      ** (DNS.Msg.Error) [invalid edns] "valid range is 0..65535, got: 65536"


  """
  @spec decode_rropt_code(atom | non_neg_integer) :: atom | non_neg_integer
  def decode_rropt_code(code),
    do: do_decode(@dns_rropt_codes, code, :eedns, 0..65535)
end
