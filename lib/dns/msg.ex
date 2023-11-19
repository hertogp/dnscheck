defmodule Msg do
  @moduledoc """
  Encode or decode a DNS message.

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

  @doc """
  Create a new `t:Msg.t/0` struct.

  TODO:
  A new Msg.t should take options:
  - hdr: [], options for the header
  - qtn: [], options for questions, 1 at a time
  - ans: [], options for answer RRs, 1 at a time
  - aut: [], options for authority RRs, 1 at a time
  - add: [], options for additional RRs, 1 at a time

  ## Examples

      iex> Msg.new(
      ...> hdr: [qr: 0],
      ...> qtn: [[name: "host.domain.tld", type: :A]],
      ...> add: [[type: :OPT, bufsize: 1410, do: 1]]
      ...> )

  """
  @spec new(Keyword.t()) :: t()

  def new(opts) do
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
  Sets `wdata`-fields of the `t:Msg.t/0` sections .
  """
  @spec encode(t) :: t
  def encode(msg) do
    hdr = Hdr.encode(msg.header)
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

  # [[ RESOLVE ]]

  @doc """
  Tries to resolve and Return a `Msg` for given `name` and `type`.

  Options include:
  - `rd`, defaults to 1 (recursion desired, true)
  - `id`, defaults to 0 (used to link replies to requests)
  - `opcode`, defaults to 0
  - `bufsize`, defaults to 1410 if edns0 is used
  - `do`, defaults to 0 (dnssec ok, false)
  - `cd`, defaults to 0 (dnssec check disable, fals)
  - `nameserver`, defaults to `{{127,0,0,53}, 53}`

  If any of the `bufsize, do or cd` options is used, a pseudo-RR
  is added to the additonal section of the `Msg`.


  """
  @spec resolve(binary, type) :: t
  def resolve(name, type, opts \\ []) do
    {edns_opts, opts} = Keyword.split(opts, [:bufsize, :do, :cd])
    {hdr_opts, opts} = Keyword.split(opts, [:rd, :id, :opcode])
    qtn_opts = [name: name, type: type]
    edns_opts = if edns_opts == [], do: [], else: [Keyword.put(edns_opts, :type, :OPT)]

    msg =
      new(qtn: [qtn_opts], hdr: hdr_opts, add: edns_opts)
      |> IO.inspect(label: :query)
      |> encode()

    send_udp(msg.wdata, opts)
    |> case do
      {:error, reason} -> {:error, reason}
      response -> decode(response)
    end
  end

  # [[ SEND/RECV MSG ]]

  def send_udp(msg, opts \\ []) do
    nameserver = Keyword.get(opts, :nameserver, {{127, 0, 0, 53}, 53})
    {:ok, sock} = :gen_udp.open(0, [:binary, active: false, recbuf: 4000])
    :ok = :gen_udp.send(sock, nameserver, msg)

    timeout_ms = 500

    case :gen_udp.recv(sock, 0, timeout_ms) do
      {:ok, {_address, _port, response}} ->
        response

      {:error, reason} ->
        {:error, reason}
    end
  end
end
