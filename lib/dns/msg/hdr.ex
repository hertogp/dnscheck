defmodule DNS.Msg.Hdr do
  @moduledoc """

  Low level functions to create, encode or decode a `Hdr` `t:t/0` struct.

  Its main use is by `DNS.Msg` when creating queries or decoding a reply.

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

  Some fields have meaning only in requests (like `rd`), others only in replies
  (like `ra`).  Usually, request-flags are copied back into the header, by the
  nameserver, when creating a reply.

  See also:
  - [rfc1035 - Domain names](ttps://www.rfc-editor.org/rfc/rfc1035)
  - [rfc2136 - DNS Update](https://www.rfc-editor.org/rfc/rfc2136)
  - [rfc6840 - clarifications for DNSSEC ](https://www.rfc-editor.org/rfc/rfc6840#section-5.7)
  - [rfc6891 - EDNS0](https://www.rfc-editor.org/rfc/rfc6891)
  - [rfc6895 - IANA considerations](https://www.rfc-editor.org/rfc/rfc6895)
  - [IANA - DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)

  """

  import DNS.MsgError, only: [error: 2]
  alias DNS.Param

  defstruct id: 0,
            qr: 0,
            opcode: :QUERY,
            aa: 0,
            tc: 0,
            rd: 1,
            ra: 0,
            z: 0,
            ad: 0,
            cd: 0,
            rcode: :NOERROR,
            qdc: 0,
            anc: 0,
            nsc: 0,
            arc: 0,
            wdata: <<>>

  @typedoc "A `bit` is either `0` or `1`."
  @type bit :: 0 | 1

  @typedoc "A non-negative offset into a DNS message."
  @type offset :: non_neg_integer

  @typedoc """
  A struct that represents the header of a DNS message.

  Its fields include:

  - `id`, set in a request, copied into a reply (links replies to requests)
  - `qr`, set to 0 in a request, to 1 in a reply
  - `opcode`, defaults to :QUERY (0), see [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)
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
          opcode: atom | non_neg_integer,
          aa: bit,
          tc: bit,
          rd: bit,
          ra: bit,
          z: non_neg_integer,
          ad: bit,
          cd: bit,
          rcode: atom | non_neg_integer,
          qdc: non_neg_integer,
          anc: non_neg_integer,
          nsc: non_neg_integer,
          arc: non_neg_integer,
          wdata: binary
        }

  # [[ API ]]

  @doc """
  Creates a `Hdr` `t:t/0` struct for given `opts`.

  The default for option-`rd` is `1`, all other options default to
  `0` or `<<>>`.  Raises when given improper values for a given field.

  Note that in the `Hdr` `t:t/0` struct, both `opcode` and `rcode` are
  4 bit fields which limits what can be assigned.

  ## Examples

      # new won't touch wdata, even when asked
      iex> new(wdata: "ignored")
      %DNS.Msg.Hdr{
        id: 0,
        qr: 0,
        opcode: :QUERY,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        z: 0,
        ad: 0,
        cd: 0,
        rcode: :NOERROR,
        qdc: 0,
        anc: 0,
        nsc: 0,
        arc: 0,
        wdata: ""
      }

      iex> new(opcode: 16)
      ** (DNS.MsgError) [create] Hdr opcode_decode: unknown parameter value '16'


  """
  @spec new(Keyword.t()) :: t() | no_return
  def new(opts \\ []) do
    Enum.reduce(opts, %__MODULE__{}, &do_put/2)
  rescue
    e in DNS.MsgError -> error(:ecreate, "Hdr " <> e.data)
  end

  @doc """
  Sets `Hdr` `t:t/0` fields for given `opts`, if the key refers to a field.

  Raises `DNS.MsgError` if a value is out of bounds.

  Values for fields `opcode:` and `rcode:` can be given as either a numeric
  value, or their mnemonic atom name (e.g. :SERVFAIL).  See `DNS.Param` for
  known names.  Note that in a header `rcode` is limited to the range of
  0..15.

  Ignores `:wdata` since that should be set via `encode/1`, which is called
  by `DNS.Msg.encode/1` when constructing the wire format of a DNS message.

  ## Examples

      iex> new() |> put(qr: 1, opcode: :QUERY, rcode: 3, wdata: "ignored")
      %DNS.Msg.Hdr{
        id: 0,
        qr: 1,
        opcode: :QUERY,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        z: 0,
        ad: 0,
        cd: 0,
        rcode: :NXDOMAIN,
        qdc: 0,
        anc: 0,
        nsc: 0,
        arc: 0,
        wdata: ""
      }

      # in a header, an rcode value should fit in 4 bites
      iex> new() |> put(rcode: 16)
      ** (DNS.MsgError) [create] Hdr rcode valid range is 0..15, got: 16

  """
  @spec put(t(), Keyword.t()) :: t() | no_return
  def put(%__MODULE__{} = hdr, opts \\ []) do
    Enum.reduce(opts, %{hdr | wdata: <<>>}, &do_put/2)
  rescue
    e in DNS.MsgError -> error(:ecreate, "Hdr " <> e.data)
  end

  # skip setting protected/calculated fields
  defp do_put({k, _}, hdr) when k in [:__struct__, :wdata],
    do: hdr

  # check 1bit values
  defp do_put({k, v}, hdr) when k in [:qr, :aa, :tc, :rd, :ra, :z, :ad, :cd] do
    if v in 0..1,
      do: Map.put(hdr, k, v),
      else: error(:ecreate, "#{k} valid range 0..1,  got: #{inspect(v)}")
  end

  # opcode & rcode store atom's if possible, numbers otherwise
  # in case we have a valid value, but no known name
  defp do_put({k, v}, hdr) when k == :opcode,
    do: Map.put(hdr, k, Param.opcode_decode(v))

  defp do_put({k, v}, hdr) when k == :rcode do
    # encode_dns_rcode accepts extended rcodes as well, so check for v in 0..15
    if Param.rcode_encode(v) in 0..15,
      do: Map.put(hdr, k, Param.rcode_decode(v)),
      else: error(:ecreate, "rcode valid range is 0..15, got: #{inspect(v)}")
  end

  # check 16bit values
  defp do_put({k, v}, hdr) when k in [:id, :qdc, :anc, :nsc, :arc] do
    if v in 0..65535,
      do: Map.put(hdr, k, v),
      else: error(:ecreate, "#{k} valid range 0..65535, got #{inspect(v)}")
  end

  # silently ignore unknown options
  defp do_put({_k, _v}, hdr),
    do: hdr

  @doc """
  Sets the `:wdata` (wiredata) field of the `Hdr` `t:t/0` struct.

  ## Example

      iex> h = new(qr: 1, rcode: :NXDOMAIN) |> encode()
      iex> h.wdata
      <<0, 0, 129, 3, 0, 0, 0, 0, 0, 0, 0, 0>>

  """
  @spec encode(t) :: t | no_return
  def encode(%__MODULE__{} = hdr) do
    opcode = Param.opcode_encode(hdr.opcode)
    rcode = Param.rcode_encode(hdr.rcode)

    hdr
    |> Map.put(
      :wdata,
      <<hdr.id::16, hdr.qr::1, opcode::4, hdr.aa::1, hdr.tc::1, hdr.rd::1, hdr.ra::1, hdr.z::1,
        hdr.ad::1, hdr.cd::1, rcode::4, hdr.qdc::16, hdr.anc::16, hdr.nsc::16, hdr.arc::16>>
    )
  rescue
    e in DNS.MsgError -> error(:eencode, "Hdr " <> e.data)
  end

  @doc """
  Decodes a `Hdr` `t:t/0` struct at given `offset` in DNS `msg`.

  Upon success, returns {`new_offset`, `t:t/0`}, where `new_offset` can be used
  to read the rest of the message (if any).  The `wdata`-field is set to the series
  of octets read during decoding.

  Given `offset` defaults to `0`, since the header is normally found at the start of
  a DNS message.

  ## Example

      iex> decode(<<0, 0, 129, 3, 0, 0, 0, 0, 0, 0, 0, 0>>)
      {12,
       %DNS.Msg.Hdr{
         id: 0,
         qr: 1,
         opcode: :QUERY,
         aa: 0,
         tc: 0,
         rd: 1,
         ra: 0,
         z: 0,
         ad: 0,
         cd: 0,
         rcode: :NXDOMAIN,
         qdc: 0,
         anc: 0,
         nsc: 0,
         arc: 0,
         wdata: <<0, 0, 129, 3, 0, 0, 0, 0, 0, 0, 0, 0>>
       }}

  """
  @spec decode(offset, binary) :: {offset, t} | no_return
  def decode(offset \\ 0, msg) do
    <<_::binary-size(offset), id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::1, ad::1,
      cd::1, rcode::4, qdc::16, anc::16, nsc::16, arc::16, _::binary>> = msg

    hdr =
      new(
        id: id,
        qr: qr,
        opcode: Param.opcode_decode(opcode),
        aa: aa,
        tc: tc,
        rd: rd,
        ra: ra,
        z: z,
        ad: ad,
        cd: cd,
        rcode: Param.rcode_decode(rcode),
        qdc: qdc,
        anc: anc,
        nsc: nsc,
        arc: arc
      )

    {12, %{hdr | wdata: :binary.part(msg, {0, 12})}}
  rescue
    e in DNS.MsgError -> error(:edecode, "Hdr " <> e.data)
    _ -> error(:edecode, "Hdr decode error at offset #{offset}")
  end
end

defimpl String.Chars, for: DNS.Msg.Hdr do
  # ;; ->>HEADER<<- opcode: QUERY, rcode: NXDOMAIN, id: 8496
  # ;; flags: qr rd ra ad ; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 0
  @flags [:qr, :aa, :tc, :rd, :ra, :ad, :cd]

  def to_string(hdr) do
    flags =
      Enum.reduce(@flags, [], fn f, acc ->
        if Map.get(hdr, f) == 1, do: ["#{f}" | acc], else: acc
      end)
      |> Enum.join(" ")

    "opcode: #{hdr.opcode}, rcode: #{hdr.rcode}, id: #{hdr.id}, flags: #{flags} ; z: #{hdr.z}," <>
      " QUERY: #{hdr.qdc}, ANSWER: #{hdr.anc}, AUTHORITY: #{hdr.nsc}, ADDITIONAL: #{hdr.arc}"
  end
end
