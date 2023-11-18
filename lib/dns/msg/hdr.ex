defmodule MsgHdr do
  import DNS.Terms
  # 12 Bytes containing the following fields: (sec 4.1.1)
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                      ID                       |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    QDCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ANCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    NSCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                    ARCOUNT                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  # - ID, 16b, query ID, is copied in the reply
  # - QR, 1b, 0=query, 1=response
  # - Opcode, 4b, kind of query: 0=normal, 1=inverse q, 2=server status, 3-15 reserved
  # - AA, 1b, Authoritative Anser, valid in responses
  # - TC, 1b, TrunCation
  # - RD, 1b, Recursion Desired, may be set in a Qry and copied to Resp.
  # - RA, 1b, Recursion Available, set or cleared in a Resp.
  # - Z, 1b, reserved, must be zero
  # - AD, 1b, authenticated data
  # - CD, 1b, check disabled
  # - RCODE, 4b, Response Code
  # - QDCOUNT, 16b, num entries in Question section
  # - ANCOUNT, 16b, num of RRs in Answer section
  # - NSCOUNT, 16b, num of NS RRs in Authority section
  # - ARCOUNT, 16b, num of RRs in Additional section
  #
  # See:
  # - https://www.rfc-editor.org/rfc/rfc1035
  # - https://www.rfc-editor.org/rfc/rfc2136
  # - https://www.rfc-editor.org/rfc/rfc6840#section-5.7
  # - https://www.rfc-editor.org/rfc/rfc6891 - EDNS(0)
  # - https://www.rfc-editor.org/rfc/rfc6895
  #
  # This module defines:
  # - new/1    -> takes opts, returns MsgHdr
  # - put/3    -> takes (hdr, field, value), returns updated hdr w/ input validation
  # - encode/1 -> takes (hdr),returns a binary (wireformat)
  # - decode/1 -> takes (bin) returns {MsgHdr, restBin}
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

  @type t :: %__MODULE__{
          id: non_neg_integer,
          qr: non_neg_integer,
          opcode: non_neg_integer,
          aa: non_neg_integer,
          tc: non_neg_integer,
          rd: non_neg_integer,
          ra: non_neg_integer,
          z: non_neg_integer,
          ad: non_neg_integer,
          cd: non_neg_integer,
          rcode: non_neg_integer,
          qdc: non_neg_integer,
          anc: non_neg_integer,
          nsc: non_neg_integer,
          arc: non_neg_integer,
          wdata: binary
        }

  @type offset :: non_neg_integer

  @spec new(Keyword.t()) :: t()
  def new(opts \\ []) do
    Enum.reduce(opts, %__MODULE__{}, &do_put/2)
  end

  @spec error(any, any) :: MsgError.t()
  defp error(reason, data),
    do: raise(MsgError.exception(reason: reason, data: data))

  @doc """
  Sets a field value with value validation.

  Raises ArgumentError is value is out of bounds.

  Values for fields `opcode:` and `rcode:` can be given as either a
  numeric value, or their mnemonic name (like "SERVFAIL" or :SERVFAIL)

  """
  @spec put(t(), Keyword.t()) :: t()
  def put(%__MODULE__{} = hdr, opts \\ []),
    do: Enum.reduce(opts, %{hdr | wdata: nil}, &do_put/2)

  # don't these two fields
  defp do_put({k, _}, hdr) when k in [:__struct__, :wdata],
    do: hdr

  # check 1bit values
  defp do_put({k, v}, hdr) when k in [:qr, :aa, :tc, :rd, :ra, :z, :ad, :cd] do
    if v in 0..1,
      do: Map.replace(hdr, k, v),
      else: error(:evalue, "#{k} not in 0..1, got #{inspect(v)}")
  end

  # check 4bit value
  defp do_put({k, v}, hdr) when k == :opcode do
    case encode_dns_opcode(v) do
      nil -> error(:evalue, "#{k} not in 0..15, got #{inspect(v)}")
      v -> Map.put(hdr, k, v)
    end
  end

  # check 4bit value
  defp do_put({k, v}, hdr) when k == :rcode do
    case encode_dns_rcode(v) do
      nil -> error(:evalue, "#{k} not in 0..15, got #{inspect(v)}")
      v -> Map.put(hdr, k, v)
    end
  end

  # check 16bit values
  defp do_put({k, v}, hdr) when k in [:id, :qdc, :anc, :nsc, :arc] do
    if v in 0..65535,
      do: Map.put(hdr, k, v),
      else: error(:evalue, "#{k} not in 0..65535, got #{inspect(v)}")
  end

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

defimpl Inspect, for: MsgHdr do
  import DNS.Terms

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
