defmodule DNS.Msg.Error do
  @moduledoc """
  `t:DNS.Msg.Error/0` provides information on errors encountered when
  encoding or decoding a `t:DNS.Msg/0`.

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
    edname: "[invalid dname]",
    eedns: "[invalid edns]"
  }

  def exception(reason, data),
    do: %__MODULE__{reason: reason, data: data}

  def message(%__MODULE__{reason: reason, data: data}) do
    category = Map.get(@reasons, reason, "[#{inspect(reason)}]")
    "#{category} #{inspect(data, limit: 50)}"
  end
end
