defmodule DNS.Msg.Error do
  @moduledoc """
  `t:DNS.Msg.Error.t/0` provides information on errors encountered when
  encoding or decoding a `t:DNS.Msg.t/0`.

  """
  defexception [:reason, :data]

  @typedoc """
  A DNS Message exception that lists the reason and provides some data.

  """
  @type t :: %__MODULE__{reason: atom(), data: any()}

  # possible exception reasons
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

  def exception(reason, data),
    do: %__MODULE__{reason: reason, data: data}

  def message(%__MODULE__{reason: reason, data: data}) do
    category = Map.get(@reasons, reason, "[#{inspect(reason)}]")
    "#{category} #{inspect(data, limit: 50)}"
  end

  @spec error(any, any) :: Error.t()
  def error(reason, data),
    do: raise(%__MODULE__{reason: reason, data: data})
end
