defmodule DNS.MsgError do
  @moduledoc """
  `t:DNS.MsgError.t/0` provides information on errors encountered when
  encoding or decoding a `t:DNS.Msg.t/0`.

  """

  # Only 3 error types needed:
  # :eencode -> error during encoding
  # :edecode -> error during decoding
  # :eoption -> error during creation
  # the errmsg should say what was wrong

  @reasons %{
    eencode: "[encode]",
    edecode: "[decode]",
    eoption: "[option]",
    ebinary: "[binary]",
    eclass: "[invalid class]",
    edname: "[invalid dname]",
    eedns: "[invalid edns]",
    efield: "[invalid field]",
    elabel: "[invalid label]",
    enotimp: "[not implemented]",
    eopcode: "[invalid opcode]",
    ercode: "[invalid (x)rcode]",
    erdata: "[invalid rdata]",
    erdmap: "[invalid rdmap]",
    errtype: "[unknown RR type]",
    evalue: "[invalid value]",
    ewdata: "[invalid wire data]"
  }

  defexception [:reason, :data]

  @typedoc """
  A DNS Message exception with a `reason` atom and some data.

  During the creation, encoding or decoding of a DNS message, errors may occur
  which are raised as an exception. Possible error reasons include:

  #{Enum.join(Enum.map(@reasons, fn {k, v} -> "- `:#{k}` #{v}" end), "  \r\n")}
  """
  @type t :: %__MODULE__{reason: atom(), data: any()}

  @doc """
  Creates a DNS message exception for given `reason` and `data`.
  """
  @spec exception(atom, any) :: t()
  def exception(reason, data),
    do: %__MODULE__{reason: reason, data: data}

  @doc """
  Gets the message for a DNS message exception.
  """
  @spec message(Exception.t()) :: String.t()
  def message(%__MODULE__{reason: reason, data: data}) do
    category = Map.get(@reasons, reason, "[#{inspect(reason)}]")

    data =
      if is_binary(data),
        do: data,
        else: "#{inspect(data, limit: 50)}"

    "#{category} #{data}"
  end

  @doc """
  Raises a DNS.MsgError exception for given `reason` and `data` provided.

  A convenience function used in various modules that do `import DNS.MsgError
  only: [error: 2]`.

  """
  @spec error(atom, any) :: Error.t()
  def error(reason, data) when is_binary(data),
    do: raise(exception(reason, data))

  def error(reason, data),
    do: raise(exception(reason, inspect(data)))
end
