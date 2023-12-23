defmodule DNS.Msg do
  @moduledoc """
  Low level functions to create, Encode or decode a `DNS.Msg` `t:/0` struct
  representing a DNS message..

  """

  alias DNS.Msg.Hdr
  alias DNS.Msg.Qtn
  alias DNS.Msg.RR

  # see RFC10135, section 4
  # The top level format of message is divided
  # into 5 sections (some of which are empty in certain cases) shown below:
  #
  #     +---------------------+
  #     |        Header       | DnsHeader
  #     +---------------------+
  #     |       Question      | [DnsQuestion]
  #     +---------------------+
  #     |        Answer       | [DnsRR]
  #     +---------------------+
  #     |      Authority      | [DnsRR]
  #     +---------------------+
  #     |      Additional     | [DnsRR]
  #     +---------------------+
  #
  #     where RR = <<NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA>>=
  #     NAME, RDATA are variable length
  #
  # TODO: add nameserver component somewhere that:
  # - registers ns IP, ns Port, start/stop time in ms
  # ;; Query time: 3 msec
  # ;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
  # ;; WHEN: Sun Nov 19 07:44:06 CET 2023
  # ;; MSG SIZE  rcvd: 51
  defstruct header: nil, question: [], answer: [], authority: [], additional: [], wdata: <<>>

  @type t :: %__MODULE__{
          header: Hdr.t(),
          question: [Qtn.t()],
          answer: [RR.t()],
          authority: [RR.t()],
          additional: [RR.t()],
          wdata: binary
        }

  @type class :: non_neg_integer | binary | atom
  @type type :: non_neg_integer | binary | atom

  @doc ~S"""
  Create a new `t:DNS.Msg.t/0` struct.

  `new/1` takes options for each of its constituents:
  - hdr: `[opts]`, options for `t:DNS.Msg.Hdr.t/0` header
  - qtn: `[[opts]]`, options for `t:DNS.Msg.Qtn.t/0` questions, 1 at a time
  - ans: `[[opts]]`, options for `t:DNS.Msg.RR.t/0` answer RRs, 1 at a time
  - aut: `[[opts]]`, options for `t:DNS.Msg.RR.t/0` authority RRs, 1 at a time
  - add: `[[opts]]`, options for `t:DNS.Msg.RR.t/0` additional RRs, 1 at a time

  ## Examples

      iex> new(
      ...> hdr: [qr: 0],
      ...> qtn: [[name: "host.domain.tld", type: :A]],
      ...> add: [[type: :OPT, bufsize: 1410, do: 1]]
      ...> )
      %DNS.Msg{
        header: %DNS.Msg.Hdr{
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
          qdc: 1,
          anc: 0,
          nsc: 0,
          arc: 1,
          wdata: ""
        },
        question: [
          %DNS.Msg.Qtn{
            name: "host.domain.tld",
            type: :A,
            class: :IN,
            wdata: ""
          }
        ],
        answer: [],
        authority: [],
        additional: [
          %DNS.Msg.RR{
            name: "",
            type: :OPT,
            class: 1410,
            ttl: 32768,
            rdlen: 0,
            rdata: "",
            rdmap: %{bufsize: 1410, do: 1, opts: [], version: 0, xrcode: :NOERROR, z: 0},
            wdata: ""
          }
        ],
        wdata: ""
      }

  """
  @spec new(Keyword.t()) :: t()

  def new(opts \\ []) do
    hdr_opts = Keyword.get(opts, :hdr, [])
    qtn_opts = Keyword.get(opts, :qtn, [])
    ans_opts = Keyword.get(opts, :ans, [])
    aut_opts = Keyword.get(opts, :aut, [])
    add_opts = Keyword.get(opts, :add, [])

    # FIXME: this only works because new is only ever used
    # with only qtn_opts as list of opts for N questions.
    # ans/aut/add opts are always empty lists!

    IO.inspect(hdr_opts, label: :hdr_opts)
    IO.inspect(add_opts, label: :add_opts)
    IO.inspect(qtn_opts, label: :qtn_opts)
    IO.inspect(ans_opts, label: :ans_opts)
    IO.inspect(aut_opts, label: :aut_opts)

    question = for o <- qtn_opts, do: Qtn.new(o)
    answer = for o <- ans_opts, do: RR.new(o)
    authority = for o <- aut_opts, do: RR.new(o)
    additional = for o <- add_opts, do: RR.new(o)

    header =
      hdr_opts
      |> Keyword.put(:qdc, length(question))
      |> Keyword.put(:anc, length(answer))
      |> Keyword.put(:adc, length(authority))
      |> Keyword.put(:arc, length(additional))
      |> Hdr.new()

    %__MODULE__{
      header: header,
      question: question,
      answer: answer,
      authority: authority,
      additional: additional
    }
  end

  # [[ ENCODE MSG ]]

  @doc """
  Sets `wdata`-field of the `Msg` `t:t/0` struct and its sections.
  """
  @spec encode(t) :: t
  def encode(msg) do
    # donot assume qd/an/ns/ad counters are set properly!
    lengths = [
      qdc: length(msg.question),
      anc: length(msg.answer),
      nsc: length(msg.authority),
      adc: length(msg.additional)
    ]

    hdr = Hdr.put(msg.header, lengths) |> Hdr.encode()
    qtn = do_encode_section(msg.question, &Qtn.encode/1)
    ans = do_encode_section(msg.answer, &RR.encode/1)
    aut = do_encode_section(msg.authority, &RR.encode/1)
    add = do_encode_section(msg.additional, &RR.encode/1)

    wdata =
      hdr.wdata <>
        Enum.reduce(qtn, <<>>, fn elm, acc -> acc <> elm.wdata end) <>
        Enum.reduce(ans, <<>>, fn elm, acc -> acc <> elm.wdata end) <>
        Enum.reduce(aut, <<>>, fn elm, acc -> acc <> elm.wdata end) <>
        Enum.reduce(add, <<>>, fn elm, acc -> acc <> elm.wdata end)

    %{
      msg
      | header: hdr,
        question: qtn,
        answer: ans,
        authority: aut,
        additional: add,
        wdata: wdata
    }
  end

  defp do_encode_section(elms, fun) do
    elms
    |> Enum.reduce([], fn elm, acc -> [fun.(elm) | acc] end)
    |> Enum.reverse()
  end

  # [[ DECODE MSG ]]

  @spec decode(binary) :: t
  def decode(msg) do
    {offset, hdr} = Hdr.decode(0, msg)
    {offset, qtn} = do_decode_section(hdr.qdc, offset, msg, &Qtn.decode/2, [])
    {offset, ans} = do_decode_section(hdr.anc, offset, msg, &RR.decode/2, [])
    {offset, aut} = do_decode_section(hdr.nsc, offset, msg, &RR.decode/2, [])
    {_offset, add} = do_decode_section(hdr.arc, offset, msg, &RR.decode/2, [])

    %__MODULE__{
      header: hdr,
      question: qtn,
      answer: ans,
      authority: aut,
      additional: add,
      wdata: msg
    }
  end

  defp do_decode_section(0, offset, _msg, _fun, acc),
    do: {offset, Enum.reverse(acc)}

  defp do_decode_section(n, offset, msg, fun, acc) do
    {offset, elm} = fun.(offset, msg)
    do_decode_section(n - 1, offset, msg, fun, [elm | acc])
  end
end

defimpl String.Chars, for: DNS.Msg do
  def to_string(msg) do
    hdr = "#{msg.header}" |> String.replace(" flags", "\n;; flags")
    qtn = Enum.map(msg.question, fn qtn -> "#{qtn}" end) |> Enum.join("\n; ")
    ans = Enum.map(msg.answer, fn rr -> "#{rr}" end) |> Enum.join("\n")
    aut = Enum.map(msg.authority, fn rr -> "#{rr}" end) |> Enum.join("\n")
    add = Enum.map(msg.additional, fn rr -> "#{rr}" end) |> Enum.join("\n")

    ";; ->>HEADER<<-- " <>
      hdr <>
      "\n\n;; QUESTION:\n" <>
      qtn <>
      "\n\n;; ANSWER:\n" <>
      ans <>
      "\n\n;; AUTHORITY:\n" <>
      aut <>
      "\n\n;; ADDITIONAL:\n" <> add
  end
end
