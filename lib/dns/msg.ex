defmodule DNS.Msg do
  @moduledoc """
  Low level functions to create, encode or decode a DNS message.

  [RFC10135](https://www.rfc-editor.org/rfc/rfc1035#section-4) defines
  A DNS message's format as follows:

  ```
      +---------------------+
      |        Header       |
      +---------------------+
      |       Question      | the question(s) for the name server
      +---------------------+
      |        Answer       | RRs answering the question
      +---------------------+
      |      Authority      | RRs pointing toward an authority
      +---------------------+
      |      Additional     | RRs holding additional information
      +---------------------+
  ```


  """

  alias DNS.Msg.Hdr
  alias DNS.Msg.Qtn
  alias DNS.Msg.RR

  defstruct header: nil, question: [], answer: [], authority: [], additional: [], wdata: <<>>

  @typedoc """
  A struct that represents a DNS message.

  It consists of:
  - a `t:DNS.Msg.Hdr.t/0` for the header section
  - a list of `t:DNS.Msg.Qtn.t/0` for the question section
  - a list of `t:DNS.Msg.RR.t/0` for the answer, authority and/or additional sections
  - `wdata`, a binary that can hold the wire formatted data of the DNS message.

  Nowadays, the question section only holds one question.  Nameservers tend to ignore
  all but the first question.

  """
  @type t :: %__MODULE__{
          header: Hdr.t(),
          question: [Qtn.t()],
          answer: [RR.t()],
          authority: [RR.t()],
          additional: [RR.t()],
          wdata: binary
        }

  @doc ~S"""
  Creates a new `t:DNS.Msg.t/0` struct.

  Returns the result in an `:ok/:error` tuple, so either:
  - `{:ok, DNS.Msg.t}`, or
  - `{:error, DNS.MsgError.t}`

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
      {:ok, %DNS.Msg{
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
        wdata: ""}
      }

      iex> DNS.Msg.new(hdr: [qr: 3])
      {:error, %DNS.MsgError{reason: :ecreate, data: "Hdr qr valid range 0..1,  got: 3"}}
  """
  @spec new(Keyword.t()) :: {:ok, t()} | {:error, DNS.MsgError.t()}
  def new(opts \\ []) do
    hdr_opts = Keyword.get(opts, :hdr, [])
    qtn_opts = Keyword.get(opts, :qtn, [])
    ans_opts = Keyword.get(opts, :ans, [])
    aut_opts = Keyword.get(opts, :aut, [])
    add_opts = Keyword.get(opts, :add, [])

    question = for o <- qtn_opts, do: Qtn.new(o)
    answer = for o <- ans_opts, do: RR.new(o)
    authority = for o <- aut_opts, do: RR.new(o)
    additional = for o <- add_opts, do: RR.new(o)

    header =
      hdr_opts
      |> Keyword.put(:qdc, length(question))
      |> Keyword.put(:anc, length(answer))
      |> Keyword.put(:nsc, length(authority))
      |> Keyword.put(:arc, length(additional))
      |> Hdr.new()

    {:ok,
     %__MODULE__{
       header: header,
       question: question,
       answer: answer,
       authority: authority,
       additional: additional
     }}
  rescue
    e -> {:error, e}
  end

  # [[ ENCODE MSG ]]

  @doc """
  Sets `wdata`-field of the given `msg` and its sections.

  The binary in the `wdata` field can then be sent via udp or
  tcp, either as a query or as a response to a question.

  The message's `wdata` is the concatenation of all the `wdata`
  fields of its sections.

  For RR's in the answer, authority and/or additional sections,
  their `rdata` is first set to the binary encoding of their `rdmap`,
  which is then used in the encoding of its `wdata` field.

  Note that RR's can be `raw`, which means their `rdmap`'s are ignored and
  their `rdata` fields are used *as-is* when assembling the `wdata` field for the
  RR. This allows for experimentation with RR's not supported by this library.

  ## Example

      iex> {:ok, msg} = DNS.Msg.new(qtn: [[name: "example.com", type: :A]])
      iex> byte_size(msg.wdata)
      0
      iex> {:ok, msg} = encode(msg)
      iex> msg
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
          arc: 0,
          wdata: <<0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0>>
        },
        question: [
          %DNS.Msg.Qtn{
            name: "example.com",
            type: :A,
            class: :IN,
            wdata: <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1 >>
          }
        ],
        answer: [],
        authority: [],
        additional: [],
        wdata: <<0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108,
          101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>
      }

  """
  @spec encode(t) :: {:ok, t} | {:error, DNS.MsgError.t()}
  def encode(%__MODULE__{} = msg) do
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

    {:ok,
     %{
       msg
       | header: hdr,
         question: qtn,
         answer: ans,
         authority: aut,
         additional: add,
         wdata: wdata
     }}
  rescue
    e in DNS.MsgError -> {:error, e}
  end

  defp do_encode_section(elms, fun) do
    elms
    |> Enum.reduce([], fn elm, acc -> [fun.(elm) | acc] end)
    |> Enum.reverse()
  end

  # [[ DECODE MSG ]]

  @doc """
  Decodes a wire formatted binary into a `t:DNS.Msg.t/0` struct.

  When decoding an RR, its `rdmap` is populated with fields and values
  that represent its `rdata` as found in the binary.  If no decoder is
  available for that particular RR type, its `rdmap` map is simply set
  to an empty map and its `raw` set to true.

  Other types of decoding issues are usually fatal, in which case an
  '{:error, `t:DNS.MsgError.t/0`}' is returned.

  ## Examples

      # suppose this came out of a udp/tcp socket
      iex> wdata = <<0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108,
      ...>           101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>
      iex> decode(wdata)
      {:ok,
        %DNS.Msg{
          header: %DNS.Msg.Hdr{
            id: 0, qr: 0, opcode: :QUERY,
            aa: 0, tc: 0, rd: 1, ra: 0, z: 0,
            ad: 0, cd: 0, rcode: :NOERROR, qdc: 1, anc: 0, nsc: 0, arc: 0,
            wdata: <<0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0>>},
          question: [
            %DNS.Msg.Qtn{
            name: "example.com",
            type: :A,
            class: :IN,
            wdata: <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>}
          ],
          answer: [],
          authority: [],
          additional: [],
          wdata: <<0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>
        }
      }

      # illegal binaries don't do well
      iex> decode(<<"oops">>)
      {:error, %DNS.MsgError{reason: :edecode, data: "Hdr decode error at offset 0"}}

  """
  @spec decode(binary) :: {:ok, t} | {:error, DNS.MsgError.t()}
  def decode(msg) do
    {offset, hdr} = Hdr.decode(0, msg)
    {offset, qtn} = do_decode_section(hdr.qdc, offset, msg, &Qtn.decode/2, [])
    {offset, ans} = do_decode_section(hdr.anc, offset, msg, &RR.decode/2, [])
    {offset, aut} = do_decode_section(hdr.nsc, offset, msg, &RR.decode/2, [])
    {_offset, add} = do_decode_section(hdr.arc, offset, msg, &RR.decode/2, [])

    {:ok,
     %__MODULE__{
       header: hdr,
       question: qtn,
       answer: ans,
       authority: aut,
       additional: add,
       wdata: msg
     }}
  rescue
    e in DNS.MsgError -> {:error, e}
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
