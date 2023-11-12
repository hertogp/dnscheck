defmodule MsgError do
  @moduledoc """
  MsgError provides information on errors encountered.

  """
  defexception [:reason, :data]

  @typedoc """
  A DNS Message exception that lists the reason and provides some data.

  """
  @type t :: %__MODULE__{reason: atom(), data: any()}

  # possible exception reasons
  @reasons %{
    efield: "[invalid field]",
    evalue: "[invalid value]",
    elabel: "[invalid label]",
    edname: "[invalid dname]"
  }

  def exception(reason, data),
    do: %__MODULE__{reason: reason, data: data}

  def message(%__MODULE__{reason: reason, data: data}) do
    category = Map.get(@reasons, reason, "[ERROR]")
    "#{category} #{inspect(data)}"
  end
end

defmodule Msg do
  @moduledoc """
  Encode or decode a DNS message.

  """

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
  defstruct header: nil, question: [], answer: [], authority: [], additional: [], wdata: <<>>

  @type t :: %__MODULE__{
          header: MsgHdr.t(),
          question: [MsgQtn.t()],
          answer: [MsgRR.t()],
          authority: [MsgRR.t()],
          additional: [MsgRr.t()],
          wdata: binary
        }

  @type class :: non_neg_integer | binary | atom
  @type type :: non_neg_integer | binary | atom

  @doc """
  Create a new `t:Msg.t/0` struct.

  """
  @spec new(binary, type, Keyword.t()) :: t()

  def new(name, type, opts),
    do: new([{name, type}], opts)

  @spec new([tuple], Keyword.t()) :: t
  def new(queries, opts) when is_list(queries) do
    question =
      queries
      |> Enum.reduce([], fn
        {name, type}, acc -> [MsgQtn.new(qname: name, qclass: "IN", qtype: type) | acc]
        {name, class, type}, acc -> [MsgQtn.new(qname: name, qclass: class, qtype: type) | acc]
      end)
      |> Enum.reverse()

    {edns, opts} = Keyword.pop(opts, :edns, [])

    additional =
      case edns do
        [] -> []
        opts -> [MsgRR.encode_edns(opts)]
      end

    opts = Keyword.merge(opts, qdc: length(question), anc: 0, nsc: 0, arc: length(additional))

    %__MODULE__{header: MsgHdr.new(opts), question: question, additional: additional}
  end

  # [[ ENCODE MSG ]]

  @doc """
  Sets `wdata`-fields of the `t:Msg.t/0` sections .
  """
  @spec encode(t) :: t
  def encode(msg) do
    hdr = MsgHdr.encode(msg.header)
    qtn = do_encode_section(msg.question, &MsgQtn.encode/1)
    ans = do_encode_section(msg.answer, &MsgRR.encode/1)
    aut = do_encode_section(msg.authority, &MsgRR.encode/1)
    add = do_encode_section(msg.additional, &MsgRR.encode/1)

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
    {offset, hdr} = MsgHdr.decode(0, msg)
    {offset, qtn} = do_decode_section(hdr.qdc, offset, msg, &MsgQtn.decode/2, [])
    {offset, ans} = do_decode_section(hdr.anc, offset, msg, &MsgRR.decode/2, [])
    {offset, aut} = do_decode_section(hdr.nsc, offset, msg, &MsgRR.decode/2, [])
    {_offset, add} = do_decode_section(hdr.arc, offset, msg, &MsgRR.decode/2, [])

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

  @spec resolve(binary, type) :: t
  def resolve(name, type, opts \\ []) do
    msg =
      new(name, type, Keyword.put(opts, :rd, 1))
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
