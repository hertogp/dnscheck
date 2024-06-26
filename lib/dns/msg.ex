defmodule DNS.Msg do
  @moduledoc """
  Low level functions to create, encode or decode a DNS message.

  [RFC10135](https://www.rfc-editor.org/rfc/rfc1035#section-4) defines
  A DNS message's format as follows:

  ```
      +---------------------+
      |        Header       |
      +---------------------+
      /       Question      / the question(s) for the name server
      +---------------------+
      /        Answer       / RRs answering the question
      +---------------------+
      /      Authority      / RRs pointing toward an authority
      +---------------------+
      /      Additional     / RRs holding additional information
      +---------------------+
  ```

  The [header](`DNS.Msg.Hdr`) consists of 12 bytes, the other portions are variable
  in length.

  Nowadays, the [question](`DNS.Msg.Qtn`) section only holds one question. Nameservers tend to
  ignore all but the first question.  Each question contains
  a name, type and class (which is usually `:IN`, since the other protocols
  didn't really take off)

  The resource records (or [RRs](`DNS.Msg.RR`)) found in the answer, authority and
  additional sections each consists of a name, class, type, ttl, a resource
  data length and the resource data itself.  Note that each section may contain
  zero or more of these records.

  If the resource data cannot be decoded into an `rdmap` of key,value-pairs, the
  `rdmap` is set to an empty map and the RR's `raw` field is set to true and the
  RR in question is retained in the DNS message struct.

  Note that when decoding, domain name compression is supported.  However, when
  encoding no domain name compression is applied.

  """

  alias DNS.Msg.Hdr
  alias DNS.Msg.Qtn
  alias DNS.Msg.RR

  defstruct header: nil,
            question: [],
            answer: [],
            authority: [],
            additional: [],
            wdata: <<>>,
            xdata: %{}

  @typedoc """
  A struct that represents a DNS message.

  It consists of:
  - a `t:DNS.Msg.Hdr.t/0` for the header section
  - a list of `t:DNS.Msg.Qtn.t/0` for the question section
  - a list of `t:DNS.Msg.RR.t/0` for the answer, authority and/or additional sections
  - `wdata`, a binary that holds the wire formatted data of the DNS message.
  - `xdata`, a map with details on the nameserver that replied (empty if msg is from cache)


  """
  @type t :: %__MODULE__{
          header: Hdr.t(),
          question: [Qtn.t()],
          answer: [RR.t()],
          authority: [RR.t()],
          additional: [RR.t()],
          wdata: binary,
          xdata: map
        }

  @doc ~S"""
  Creates a new `t:DNS.Msg.t/0` struct.

  Returns the result in an `:ok/:error` tuple, so either:
  - `{:ok, DNS.Msg.t}`, or
  - `{:error, DNS.MsgError.t}`

  `new/1` takes options for each of its constituents:
  - `:hdr` `[opts]` for the [header](`DNS.Msg.Hdr`)
  - `:qtn` `[[opts]]` for the [questions](`DNS.Msg.Qtn`) in the question section, 1 at a time
  - `:ans` `[[opts]]` for the [RR's](`DNS.Msg.RR`) in the answer section, 1 at a time
  - `:aut` `[[opts]]` for the [RR's](`DNS.Msg.RR`) in the authority section, 1 at a time
  - `:add` `[[opts]]` for the [RR's](`DNS.Msg.RR`) in the additional section, 1 at a time

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
    # do not assume qd/an/ns/ad counters are set properly
    lengths = [
      qdc: length(msg.question),
      anc: length(msg.answer),
      nsc: length(msg.authority),
      adc: length(msg.additional)
    ]

    hdr = Hdr.put(msg.header, lengths) |> Hdr.encode()
    qtn = Enum.map(msg.question, &Qtn.encode/1)
    ans = Enum.map(msg.answer, &RR.encode/1)
    aut = Enum.map(msg.authority, &RR.encode/1)
    add = Enum.map(msg.additional, &RR.encode/1)

    wdata =
      hdr.wdata <>
        Enum.map_join(qtn, & &1.wdata) <>
        Enum.map_join(ans, & &1.wdata) <>
        Enum.map_join(aut, & &1.wdata) <>
        Enum.map_join(add, & &1.wdata)

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

  # [[ DECODE MSG ]]

  @doc """
  Decodes a wire formatted binary into a `t:DNS.Msg.t/0` struct.

  When decoding an RR, its `rdmap` is populated with fields and values
  that represent its `rdata` as found in the binary.  If no decoder is
  available for that particular RR type, its `rdmap` map is simply set
  to an empty map and its `raw` field is set to true.

  Other types of decoding issues are usually fatal, in which case an
  '{:error, `t:DNS.MsgError.t/0`}' is returned.

  ## Examples

      # suppose this came out of a udp/tcp socket
      iex> wdata = <<0, 0, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97, 109,
      ...> 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 7, 101, 120, 97, 109, 112,
      ...> 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 10, 1, 1, 1>>
      iex> DNS.Msg.decode(wdata)
      {:ok,
        %DNS.Msg{
          header: %DNS.Msg.Hdr{
            id: 0, qr: 1, opcode: :QUERY, aa: 0, tc: 0, rd: 1, ra: 1, z: 0,
            ad: 0, cd: 0, rcode: :NOERROR, qdc: 1, anc: 1, nsc: 0, arc: 0,
            wdata: <<0, 0, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0>>},
          question: [
            %DNS.Msg.Qtn{
            name: "example.com",
            type: :A,
            class: :IN,
            wdata: <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1>>}
          ],
          answer: [
            %DNS.Msg.RR{
              name: "example.com",
              type: :A,
              class: :IN,
              ttl: 0,
              raw: false,
              rdlen: 4,
              rdmap: %{ip: "10.1.1.1"},
              rdata: <<10, 1, 1, 1>>,
              wdata: <<7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0,
                       0, 0, 0, 0, 4, 10, 1, 1, 1>>
            }
          ],
          authority: [],
          additional: [],
          wdata: <<0, 0, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 7, 101, 120, 97, 109,
                   112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 7, 101, 120, 97, 109, 112,
                   108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 10, 1, 1, 1>>
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
