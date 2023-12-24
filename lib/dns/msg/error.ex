defmodule DNS.Msg.Error do
  @moduledoc """
  `t:DNS.Msg.Error.t/0` provides information on errors encountered when
  encoding or decoding a `t:DNS.Msg.t/0`.

  """

  @reasons %{
    eclass: "[invalid class]",
    edname: "[invalid dname]",
    eedns: "[invalid edns]",
    eencode: "[RR encoding]",
    efield: "[invalid field]",
    elabel: "[invalid label]",
    enotimp: "[not implemented]",
    eopcode: "[invalid opcode]",
    ercode: "[invalid (x)rcode]",
    erdata: "[invalid rdata]",
    erdmap: "[invalid rdmap]",
    errtype: "[unknown RR type]",
    euser: "[user contribution]",
    evalue: "[invalid value]"
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
    "#{category} #{inspect(data, limit: 50)}"
  end

  @doc """
  Raises a DNS.Msg.Error exception for given `reason` and `data` provided.

  A convenience function used in various modules that do `import DNS.Msg.Error
  only: [error: 2]`.

  """
  @spec error(atom, any) :: Error.t()
  def error(reason, data),
    do: raise(exception(reason, inspect(data)))
end
