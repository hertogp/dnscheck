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
  #     /                     QNAME                     /
  #     /                                               /
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QTYPE                     |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #     |                     QCLASS                    |
  #     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  #
  # - QNAME, domain name (series of length encoded labels)
  # - QTYPE, 2 octets, type of Qry
  # - QCLASS, 2 octets, class of Qry, usally IN (1)
  #

  defstruct qname: "", qtype: 1, qclass: 1, wdata: <<>>

  @type offset :: non_neg_integer
  @type type :: non_neg_integer
  @type class :: non_neg_integer

  @type t :: %__MODULE__{
          qname: binary,
          qtype: type,
          qclass: class,
          wdata: binary
        }

  # [[ HELPERS ]]

  defp error(reason, data),
    do: raise(MsgError.exception(reason: reason, data: data))

  # [[ new ]]

  @doc """
  Create a DnsQuestion struct for given `qname` and `opts`.

  The `qname` is assumed to be a length encoded binary domain name.

  Options include:
  - `qtype`, defaults to 1 (QUERY)
  - `qclass, defaults to 1 (IN class)

  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []),
    do: Enum.reduce(opts, %__MODULE__{}, &do_put/2)

  # [[ put ]]

  @spec put(t(), Keyword.t()) :: t()
  def put(%__MODULE__{} = qry, opts \\ []),
    do: Enum.reduce(opts, %{qry | wdata: nil}, &do_put/2)

  defp do_put({k, v}, qry) when k == :qname do
    if is_binary(v),
      do: Map.put(qry, k, v),
      else: error(:evalue, "#{k} not binary, got: #{inspect(v)}")
  end

  @spec do_put({atom, any}, t()) :: t()
  defp do_put({k, v}, qry) when k == :qtype do
    case encode_dns_type(v) do
      nil -> error(:evalue, "invalid #{k},: got #{inspect(v)}?")
      v -> Map.put(qry, k, v)
    end
  end

  defp do_put({k, v}, qry) when k == :qclass do
    case encode_dns_class(v) do
      nil -> error(:evalue, "invalid #{k}, got #{inspect(v)}")
      v -> Map.put(qry, k, v)
    end
  end

  # [[ encode ]]
  @doc """
  Sets the `:wdata` (wiredata) field of the `MsgQry` struct.

  """
  @spec encode(t()) :: t()
  def encode(qry) do
    dname = encode_dname(qry.qname)
    %{qry | wdata: <<dname::binary, qry.qtype::16, qry.qclass::16>>}
  end

  # [[ decode ]]
  @doc """
  Decode a `t:MsgQry.t/0` struct at given `offset` and `msg`.

  Returns `{new_offset, t:MsgQry.t/0}`.

  """
  @spec decode(offset, binary) :: {offset, t()}
  def decode(offset, msg) do
    # offset2 - offset might not equal byte_size(qname) due to name compression
    {offset2, qname} = decode_dname(offset, msg)
    <<_::binary-size(offset2), qtype::16, qclass::16, _::binary>> = msg

    wdata = :binary.part(msg, {offset, offset2 - offset + 4})
    qry = new(qname: qname, qtype: qtype, qclass: qclass)

    # new(..) will not set calculated wdata-field
    {offset2 + 4, %{qry | wdata: wdata}}
  end

  @spec to_string(t) :: binary
  def to_string(%__MODULE__{} = qtn) do
    "#{qtn.qname}" <>
      "\t#{decode_dns_class(qtn.qclass)}" <>
      "\t#{decode_dns_type(qtn.qtype)}"
  end
end

# defimpl Inspect, for: MsgQtn do
#   import Inspect.Algebra
#   import DNS.Terms
#
#   def inspect(qtn, _opts) do
#     concat([
#       "{#{qtn.qname}, #{decode_dns_class(qtn.qclass)}, #{decode_dns_type(qtn.qtype)}}"
#     ])
#   end
# end
