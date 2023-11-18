defmodule MsgQtn do
  import DNS.Terms
  import DNS.Fields

  # RFC1035, 4.2.1 Question section format
  # The question section is used to carry the "question" in most queries,
  # i.e., the parameters that define what is being asked.  The section
  # contains QDCOUNT (usually 1) entries, each of the following format:
  #
  #                                     1  1  1  1  1  1
  #       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                                               |
  #     /                     name                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     type                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     class                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # - name, domain name (series of length encoded labels)
  # - type, 2 octets, type of qtn
  # - class, 2 octets, class of qtn, usally IN (1)
  #

  defstruct name: "", type: 1, class: 1, wdata: <<>>

  @type offset :: non_neg_integer
  @type type :: non_neg_integer
  @type class :: non_neg_integer

  @type t :: %__MODULE__{
          name: binary,
          type: type,
          class: class,
          wdata: binary
        }

  # [[ HELPERS ]]

  defp error(reason, data),
    do: raise(MsgError.exception(reason: reason, data: data))

  # [[ new ]]

  @doc """
  Create a MsgQtn struct for given `name` and `opts`.

  The `name` is assumed to be a length encoded binary domain name.

  Options include:
  - `name`, defaults to ""
  - `type`, defaults to 1 (QUERY)
  - `class, defaults to 1 (IN class)

  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []),
    do: Enum.reduce(opts, %__MODULE__{}, &do_put/2)

  # [[ put ]]

  @spec put(t(), Keyword.t()) :: t()
  def put(%__MODULE__{} = qtn, opts \\ []),
    do: Enum.reduce(opts, %{qtn | wdata: nil}, &do_put/2)

  defp do_put({k, v}, qtn) when k == :name do
    if is_binary(v),
      do: Map.put(qtn, k, v),
      else: error(:evalue, "#{k} not binary, got: #{inspect(v)}")
  end

  @spec do_put({atom, any}, t()) :: t()
  defp do_put({k, v}, qtn) when k == :type,
    do: Map.put(qtn, k, decode_rr_type(v))

  defp do_put({k, v}, qtn) when k == :class,
    do: Map.put(qtn, k, v)

  # [[ encode ]]
  @doc """
  Sets the `:wdata` (wiredata) field of the `MsgQtn` struct.

  """
  @spec encode(t()) :: t()
  def encode(%__MODULE__{} = qtn) do
    dname = encode_dname(qtn.name)
    class = 1
    type = encode_rr_type(qtn.type)
    %{qtn | wdata: <<dname::binary, type::16, class::16>>}
  end

  # [[ decode ]]
  @doc """
  Decode a `t:MsgQtn.t/0` struct at given `offset` and `msg`.

  Returns `{new_offset, t:MsgQtn.t/0}`.

  """
  @spec decode(offset, binary) :: {offset, t()}
  def decode(offset, msg) do
    # offset2 - offset might not equal byte_size(name) due to name compression
    {offset2, name} = decode_dname(offset, msg)
    <<_::binary-size(offset2), type::16, class::16, _::binary>> = msg

    wdata = :binary.part(msg, {offset, offset2 - offset + 4})
    qtn = new(name: name, type: type, class: class)

    # new(..) will not set calculated wdata-field
    {offset2 + 4, %{qtn | wdata: wdata}}
  end

  @spec to_string(t) :: binary
  def to_string(%__MODULE__{} = qtn) do
    "#{qtn.name}" <>
      "\t#{qtn.class}" <>
      "\t#{decode_rr_type(qtn.type)}"
  end
end

defimpl Inspect, for: MsgQtn do
  import DNS.Terms

  def inspect(qtn, opts) do
    syntax_colors = IO.ANSI.syntax_colors()
    opts = Map.put(opts, :syntax_colors, syntax_colors)

    qtn
    |> Map.put(:type, "#{encode_rr_type(qtn.type)} (#{qtn.type})")
    |> Map.put(:class, "#{qtn.class} (IN)")
    |> Inspect.Any.inspect(opts)
  end
end
