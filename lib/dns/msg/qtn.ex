defmodule DNS.Msg.Qtn do
  import DNS.Msg.Terms
  import DNS.Msg.Fields
  alias DNS.Msg.Error

  @moduledoc """

  Low level functions to create, encode or decode a `Qtn` `t:t/0` struct.

  As per
  [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2), the
  question section of a DNS message is used to carry the "question" in most
  queries, i.e., the parameters that define what is being asked.  The section
  contains QDCOUNT (usually 1) entries, each of the following format:

  ```
         0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                                               |
       /                     NAME                      /
       /                                               /
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                     TYPE                      |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
       |                     CLASS                     |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ```

  - `NAME`, `n` octets, the domain name being queried, as a sequence of length-encoded labels
  - `TYPE`, 2 octets, the RR type of the record being queried
  - `CLASS`, 2 octets, the DNS class of the record being queried, usally IN (1)

  Although the RFC's allow for a list of questions, it seems most nameservers only
  ever answer the first question and ignore the rest.

  """

  defstruct name: "", type: :A, class: :IN, wdata: <<>>

  @typedoc "A non negative offset into a DNS message."
  @type offset :: non_neg_integer

  @typedoc "An atom name (if known) or a 16 bit number."
  @type type :: atom | non_neg_integer

  @typedoc "An atom name (if known) or a 16 bit number."
  @type class :: atom | non_neg_integer

  @typedoc """
  A struct which represents a single question in a DNS message.

  Its fields include:
  - `name`, the domain name being queried (default "")
  - `type`, the type of RR record being queried (default `:A`)
  - `class`, the DNS class of the record being queried, (default `:IN`)
  - `wdata`, wire format of the question (default `<<>>`)

  """
  @type t :: %__MODULE__{
          name: binary,
          type: type,
          class: class,
          wdata: binary
        }

  # [[ HELPERS ]]

  defp error(reason, data),
    do: raise(Error.exception(reason: reason, data: data))

  # [[ DECODE ]]

  @doc """
  Decodes a `Qtn` `t:t/0` struct at given `offset` in `msg`.

  Returns {`new_offset`, `t:t/0`}, where `new_offset` can be used to read the
  rest of the message.  Uses `DNS.Msg.Fields.dname_decode/2`.

  ## Example

      iex> msg = <<"stuff", 7, "example", 3, "com", 0, 1::16, 1::16, "more stuff">>
      iex> {offset, qtn} = decode(5, msg)
      iex> qtn
      %DNS.Msg.Qtn{
        name: "example.com",
        type: :A,
        class: :IN,
        wdata: <<7, "example", 3, "com", 0, 1::16, 1::16>>
      }
      iex> <<_::binary-size(offset), rest::binary>> = msg
      iex> rest
      "more stuff"

  """
  @spec decode(offset, binary) :: {offset, t()}
  def decode(offset, msg) do
    # offset2 - offset might not equal byte_size(name) due to name compression
    {offset2, name} = dname_decode(offset, msg)
    <<_::binary-size(offset2), type::16, class::16, _::binary>> = msg

    wdata = :binary.part(msg, {offset, offset2 - offset + 4})
    qtn = new(name: name, type: type, class: class)

    # new(..) will not set calculated wdata-field
    {offset2 + 4, %{qtn | wdata: wdata}}
  end

  # [[ ENCODE ]]

  @doc """
  Sets the `:wdata` (wiredata) field of the `Qtn` struct.

  ## Example

      iex> q = new(name: "example.com")
      %DNS.Msg.Qtn{
         name: "example.com",
         type: :A,
         class: :IN,
         wdata: ""
       }
      iex> encode(q)
      %DNS.Msg.Qtn{
         name: "example.com",
         type: :A,
         class: :IN,
         wdata: <<7, "example", 3, "com", 0, 1::16, 1::16>>
       }

  """
  @spec encode(t()) :: t()
  def encode(%__MODULE__{} = qtn) do
    dname = dname_encode(qtn.name)
    class = encode_dns_class(qtn.class)
    type = encode_rr_type(qtn.type)
    %{qtn | wdata: <<dname::binary, type::16, class::16>>}
  end

  # [[ NEW ]]

  @doc ~S"""
  Creates a Qtn `t:t/0` struct for given `name` and `opts`.

  Options include:
  - `name`, a valid domain name, defaults to ""
  - `type`, 16 bit number, defaults to 1 (A)
  - `class`, 16 bit number, defaults to 1 (IN class)

  Any options that are not known or needed are silently ignored.
  Note that this cannot be used to set the `wdata` field.

  ## Examples

      iex> new()
      %DNS.Msg.Qtn{
        name: "",
        type: :A,
        class: :IN,
        wdata: ""
      }

      iex> new(name: "example.com", wdata: "ignored", foo: :bar)
      %DNS.Msg.Qtn{
        name: "example.com",
        type: :A,
        class: :IN,
        wdata: ""
      }

  `new/1` will raise on errors to help prevent creating malformed DNS messages
  that would only result in `FORMERROR`'s.

      iex> new(name: "example.123")
      ** (DNS.Msg.Error) [invalid dname] "example.123"

  But if you want to see how nameservers respond to illegal names, you can set
  the name manually before encoding, since `encode/1` uses `DNS.Msg.Fields.dname_encode/1` which
  checks only for name/label lengths.

      iex> q = %{new() | name: "example.123"}
      %DNS.Msg.Qtn{name: "example.123", type: :A, class: :IN, wdata: ""}
      iex> q = encode(q)
      iex> q.wdata
      <<7, "example", 3, "123", 0, 1::16, 1::16>>

    For convenience, a simple `String.Chars` implementation is available (adds
    the root dot)

      iex> q = new(name: "example.com")
      iex> "#{q}"
      "example.com.\tIN\tA"

  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []),
    do: Enum.reduce(opts, %__MODULE__{}, &do_put/2)

  # [[ PUT ]]

  @doc """
  Sets `t:t/0`-field(s) for given `opts`, if the key refers to a field.

  Ignores unknown keys.

  ## Examples

      iex> new() |> put(name: "example.com")
      %DNS.Msg.Qtn{
        name: "example.com",
        type: :A,
        class: :IN,
        wdata: ""
      }

      iex> new() |> put(name: "example.com", foo: :bar, type: :AAAA)
      %DNS.Msg.Qtn{
        name: "example.com",
        type: :AAAA,
        class: :IN,
        wdata: ""
      }

      iex> new() |> put(name: "example.123")
      ** (DNS.Msg.Error) [invalid dname] "example.123"

  """
  @spec put(t(), Keyword.t()) :: t()
  def put(%__MODULE__{} = qtn, opts \\ []),
    do: Enum.reduce(opts, %{qtn | wdata: <<>>}, &do_put/2)

  @spec do_put({atom, any}, t()) :: t()
  defp do_put({k, v}, qtn) when k == :name do
    if dname_valid?(v),
      do: Map.put(qtn, k, v),
      else: error(:edname, "#{v}")
  end

  defp do_put({k, v}, qtn) when k == :type,
    do: Map.put(qtn, k, decode_rr_type(v))

  defp do_put({k, v}, qtn) when k == :class,
    do: Map.put(qtn, k, decode_dns_class(v))

  # ignore options we donot need or know
  defp do_put(_, qtn),
    do: qtn
end

defimpl String.Chars, for: DNS.Msg.Qtn do
  def to_string(qtn),
    do: "#{qtn.name}.\t#{qtn.class}\t#{qtn.type}"
end

defimpl Inspect, for: DNS.Msg.Qtn do
  def inspect(qtn, opts) do
    syntax_colors = IO.ANSI.syntax_colors()
    opts = Map.put(opts, :syntax_colors, syntax_colors)

    qtn
    |> Map.put(:wdata, "#{Kernel.inspect(qtn.wdata, limit: 10)}")
    |> Inspect.Any.inspect(opts)
  end
end
