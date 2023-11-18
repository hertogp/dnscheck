defmodule DNS.Terms do
  @moduledoc """
  Functions to encode/decode DNS terms.

  See [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

  """

  alias DNS.Utils

  # [[ Helpers ]]

  defp error(reason, data),
    do: raise(MsgError.exception(reason: reason, data: data))

  @spec to_number(map, any) :: non_neg_integer
  defp to_number(map, key) do
    case Map.get(map, key) do
      nil -> error(:eterm, "term #{inspect(key)} not available")
      n when is_integer(n) -> n
      a when is_atom(a) -> Map.get(map, a)
      _ -> error(:eterm, "malformed terms map: #{inspect(map)}")
    end
  end

  @spec to_atom(map, any) :: atom
  defp to_atom(map, key) do
    case Map.get(map, key) do
      nil -> error(:eterm, "term #{inspect(key)} not available")
      n when is_integer(n) -> Map.get(map, n)
      a when is_atom(a) -> a
      _ -> error(:eterm, "malformed terms map: #{inspect(map)}")
    end
  end

  # [[ DNS CLASS ]]
  # Only :IN (1) is supported
  @spec encode_dns_class(any) :: non_neg_integer
  def encode_dns_class(class) when is_integer(class),
    do: class

  def encode_dns_class(_),
    do: 1

  @spec decode_dns_class(any) :: atom
  def decode_dns_class(class) when is_integer(class), do: class
  def decode_dns_class(_), do: :IN

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
  Given a DNS opcode, return its number or nil if not found

  Known names include: :QUERY, :IQUERY (obsolete), :STATUS, :NOTIFY, :UPDATE
  and :DSO (DNS Stateful Operations)

  See [IANA DNS Params](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)

  ## Examples

      iex> encode_dns_opcode(:QUERY)
      0

  """
  @spec encode_dns_opcode(any) :: non_neg_integer
  def encode_dns_opcode(opcode),
    do: to_number(@dns_opcodes, opcode)

  @doc """
  Given a numeric opcode, return its name, "UNASSIGNED" if not found.

  Only codes `[0..2, 4..6]` are known at the moment.
  See [IANA DNS Params](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)

  ## Examples

      iex> decode_dns_opcode(0)
      :QUERY

      iex> decode_dns_opcode(:UPDATE)
      :UPDATE

  """
  @spec decode_dns_opcode(any) :: atom
  def decode_dns_opcode(opcode),
    do: to_atom(@dns_opcodes, opcode)

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
  Given a DNS rcode, return its number or nil if not found

  If `rcode` is numeric, returns that number if known, nil otherwise.
  If `rcode` is lower/uppercase name of uppercase atom, returns the associated
  numeric value if known, nil otherwise.

  Note that DNS `rcode`s occur in several places in a DNS message, not just in
  the 4bit RCODE field in the DNS message header, in which case they may occupy
  up to 16 bits.

  See [RFC6895 2.3](https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3)

  ## Examples

      iex> encode_dns_rcode(:NOERROR)
      0

      iex> encode_dns_rcode(0)
      0

      iex> encode_dns_rcode("ABC")
      nil

  """
  @spec encode_dns_rcode(any) :: non_neg_integer()
  def encode_dns_rcode(rcode),
    do: to_number(@dns_rcodes, rcode)

  @doc """
  Given a numeric RCODE, return its atom of nil if not found.

  ## Examples

      iex> decode_dns_rcode(2)
      :SERVFAIL

      iex> decode_dns_rcode(:SERVFAIL)
      :SERVFAIL

      iex> decode_dns_rcode(65535)
      nil

  """
  @spec decode_dns_rcode(any) :: atom
  def decode_dns_rcode(rcode),
    do: to_atom(@dns_rcodes, rcode)

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
              :MX => 15,
              :TXT => 16,
              :AAAA => 28,
              :OPT => 41,
              :DS => 43,
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
  Given a DNS RR type, return its number, or nil if not found.

  DNS types have 3 different subcategories: data (RR)types, Query types and
  Meta-Types.  Hence, they occur in various places including as query types, RR
  types and also in `types covered` fields in some RR's RDATA portion.
  Normally the value `0` is reserved, except in the `types covered` field of
  a SIG RR. The caller will have to be aware of its context when encoding
  or decoding TYPEs.

  See:
  - [IANA DNS Params](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
  - [RFC6895, sec 3](https://www.rfc-editor.org/rfc/rfc6895.html#section-3)

  ## Examples

      iex> encode_rr_type(:A)
      1

      iex> encode_rr_type(:HTTPS)
      65

      iex> encode_rr_type("ABC")
      nil
  """
  @spec encode_rr_type(any) :: non_neg_integer()
  def encode_rr_type(type),
    do: to_number(@rr_types, type)

  @doc """
  Given a DNS type, return its atom

  ## Examples

      iex> decode_rr_type(1)
      :A

      iex> decode_rr_type(65)
      :HTTPS

      iex> decode_rr_type(:HTTPS)
      :HTTPS

      iex> decode_rr_type(3)
      nil



  See:
  - [IANA DNS Params](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
  - [RFC3597](https://www.rfc-editor.org/rfc/rfc3597#section-5)

  """
  @spec decode_rr_type(any) :: atom
  def decode_rr_type(type),
    do: to_atom(@rr_types, type)

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
                     :EDNS_CLIENT_SUBNET => 8,
                     :EDNS_EXPIRE => 9,
                     :COOKIE => 10,
                     :EDNS_TCP_KEEPALIVE => 11,
                     :PADDING => 12,
                     :CHAIN => 13,
                     :EDNS_KEY_TAG => 14,
                     :EXTENDED_DNS_ERROR => 15,
                     :EDNS_CLIENT_TAG => 16,
                     :EDNS_SERVER_TAG => 17,
                     :UMBRELLA_IDENT => 20292,
                     :DEVICEID => 26946
                   }
                   |> Utils.normalize_name_map()

  @spec encode_rropt_code(any) :: non_neg_integer()
  def encode_rropt_code(code),
    do: to_number(@dns_rropt_codes, code)

  @spec decode_rropt_code(any) :: atom
  def decode_rropt_code(code),
    do: to_atom(@dns_rropt_codes, code)
end
