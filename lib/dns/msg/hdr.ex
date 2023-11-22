defmodule DNS.Msg.Hdr do
  import DNS.Msg.Terms
  alias DNS.Msg.Error

  @moduledoc """

  Low level functions to create, encode or decode a `t:DNS.Msg.Hdr.t/0` struct.

  A DNS header consists of 12 bytes containing the following fields:

  ```
        0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      ID                       |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    QDCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ANCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    NSCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ARCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ```

  See `t:DNS.Msg.Hdr.t/0` for the meaning of the fields.  Some have meaning
  only in requests (like `rd`), others only in replies (like `ra`).  Usually,
  request-flags are copied back into the header, by the nameserver, when
  creating a reply.

  See also:
  - [rfc1035 - Domain names](ttps://www.rfc-editor.org/rfc/rfc1035)
  - [rfc2136 - DNS Update](https://www.rfc-editor.org/rfc/rfc2136)
  - [rfc6840 - clarifications for DNSSEC ](https://www.rfc-editor.org/rfc/rfc6840#section-5.7)
  - [rfc6891 - EDNS0](https://www.rfc-editor.org/rfc/rfc6891)
  - [rfc6895 - IANA considerations](https://www.rfc-editor.org/rfc/rfc6895)
  - [IANA - DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)

  """
  defstruct id: 0,
            qr: 0,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 1,
            ra: 0,
            z: 0,
            ad: 0,
            cd: 0,
            rcode: 0,
            qdc: 0,
            anc: 0,
            nsc: 0,
            arc: 0,
            wdata: <<>>

  @typedoc """
  A `bit` is either `0` or `1`.
  """
  @type bit :: 0 | 1

  @typedoc """
  A `t:DNS.Msg.Hdr.t/0` struct represents part of a `t:DNS.Msg.t/0` message.

  It fields include:

  - `id`, set in a request, copied into a reply (links replies to earlier requests)
  - `qr`, set to 0 in a request, to 1 in a reply
  - `opcode`, defaults to 0 (QUERY), see [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)
  - `aa`, set to 1 in a reply to indicate an authoritative answer
  - `tc`, set to 1 in a reply to indicate a message was truncated
  - `rd`, set to 1 in a query to indicate "recursion desired"
  - `ra`, set to 1 in a reply to indicate "recursion available"
  - `z`, currently MUST be zero
  - `ad`, set to 1 in a reply to indicate "authenticated data"
  - `cd`, set to 1 in a request to indicate (DNSSEC) "check disabled"
  - `rcode`, set in a reply, see [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
  - `qdc`, set in a request to indicate the number of questions
  - `anc`, set in a reply to indicate the number of answer RR's
  - `nsc`, set in a reply to indicate the number of authority RR's
  - `arc`, set in a reply to indicate the number of additional RR's
  - `wdata`, the header's wireformat data upon receiving a reply (or encoding a header)

  """
  @type t :: %__MODULE__{
          id: non_neg_integer,
          qr: bit,
          opcode: non_neg_integer,
          aa: bit,
          tc: bit,
          rd: bit,
          ra: bit,
          z: non_neg_integer,
          ad: bit,
          cd: bit,
          rcode: non_neg_integer,
          qdc: non_neg_integer,
          anc: non_neg_integer,
          nsc: non_neg_integer,
          arc: non_neg_integer,
          wdata: binary
        }

  # [[ HELPERS ]]

  @spec error(any, any) :: Error.t()
  defp error(reason, data),
    do: raise(Error.exception(reason: reason, data: data))

  # [[ API ]]

  @typedoc """
  A non-negative offset into a DNS message's wireformat
  """
  @type offset :: non_neg_integer

  @doc """
  Return `t:DNS.Msg.Hdr.t/0` struct in accordance with given `opts`.

  The default for option-`rd` is `1`, all other options default to
  `0` of `<<>>`.


  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []),
    do: Enum.reduce(opts, %__MODULE__{}, &do_put/2)

  @doc """
  Sets a field value with value validation.

  Raises ArgumentError is value is out of bounds.

  Values for fields `opcode:` and `rcode:` can be given as either a
  numeric value, or their mnemonic atom name (:SERVFAIL)

  """
  @spec put(t(), Keyword.t()) :: t()
  def put(%__MODULE__{} = hdr, opts \\ []),
    do: Enum.reduce(opts, %{hdr | wdata: <<>>}, &do_put/2)

  # skip setting protected/calculated fields
  defp do_put({k, _}, hdr) when k in [:__struct__, :wdata],
    do: hdr

  # check 1bit values
  defp do_put({k, v}, hdr) when k in [:qr, :aa, :tc, :rd, :ra, :z, :ad, :cd] do
    if v in 0..1,
      do: Map.put(hdr, k, v),
      else: error(:evalue, "bit field #{k} not in 0..1, got #{inspect(v)}")
  end

  defp do_put({k, v}, hdr) when k == :opcode,
    do: Map.put(hdr, k, encode_dns_opcode(v))

  defp do_put({k, v}, hdr) when k == :rcode,
    do: Map.put(hdr, k, encode_dns_rcode(v))

  # check 16bit values
  defp do_put({k, v}, hdr) when k in [:id, :qdc, :anc, :nsc, :arc] do
    if v in 0..65535,
      do: Map.put(hdr, k, v),
      else: error(:evalue, "DNS.Msg.Hdr field #{k} not in 0..65535, got #{inspect(v)}")
  end

  # silently ignore other crap
  defp do_put({_k, _v}, hdr),
    do: hdr

  # do: error(:efield, "#{inspect(k)}, #{inspect(v)}")

  @spec encode(t) :: t
  def encode(%__MODULE__{} = hdr) do
    hdr
    |> Map.put(
      :wdata,
      <<hdr.id::16, hdr.qr::1, hdr.opcode::4, hdr.aa::1, hdr.tc::1, hdr.rd::1, hdr.ra::1,
        hdr.z::1, hdr.ad::1, hdr.cd::1, hdr.rcode::4, hdr.qdc::16, hdr.anc::16, hdr.nsc::16,
        hdr.arc::16>>
    )
  end

  @spec decode(offset, binary) :: {offset, t}
  def decode(offset, wdata) do
    <<_::binary-size(offset), id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::1, ad::1,
      cd::1, rcode::4, qdc::16, anc::16, nsc::16, arc::16, _::binary>> = wdata

    hdr =
      new(
        id: id,
        qr: qr,
        opcode: opcode,
        aa: aa,
        tc: tc,
        rd: rd,
        ra: ra,
        z: z,
        ad: ad,
        cd: cd,
        rcode: rcode,
        qdc: qdc,
        anc: anc,
        nsc: nsc,
        arc: arc
      )

    {12, %{hdr | wdata: :binary.part(wdata, {0, 12})}}
  end
end

defimpl Inspect, for: DNS.Msg.Hdr do
  import DNS.Msg.Terms

  def inspect(hdr, opts) do
    syntax_colors = IO.ANSI.syntax_colors()
    opts = Map.put(opts, :syntax_colors, syntax_colors)
    qr = if hdr.qr == 0, do: "request", else: "response"

    hdr
    |> Map.put(:opcode, "#{hdr.opcode} (#{decode_dns_opcode(hdr.opcode)})")
    |> Map.put(:rcode, "#{hdr.rcode} (#{decode_dns_rcode(hdr.rcode)})")
    |> Map.put(:qr, "#{hdr.qr} (#{qr})")
    |> Map.put(:aa, "#{hdr.aa}, (authoritative answer: #{hdr.aa == 1})")
    |> Map.put(:ad, "#{hdr.ad}, (authentic data: #{hdr.ad == 1})")
    |> Map.put(:rd, "#{hdr.rd}, (recursion desired: #{hdr.rd == 1})")
    |> Map.put(:ra, "#{hdr.ra}, (recursion available: #{hdr.ra == 1})")
    |> Map.put(:tc, "#{hdr.tc}, (truncated: #{hdr.tc == 1})")
    |> Map.put(:cd, "#{hdr.tc}, (check disabled: #{hdr.cd == 1})")
    |> Inspect.Any.inspect(opts)
  end
end
