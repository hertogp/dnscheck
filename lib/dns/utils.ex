defmodule DNS.Utils do
  @moduledoc """
  Utility functions used in various places

  """

  @doc """
  Normalizes a `:NAME,value` lookup map.

  Normalizing a :NAME,value-map means:
  - turn all keys into uppercase ATOM keys
  - add reverse mapping value -> :KEY

  Best used on maps that have all either upper or lowercase, unique keys.

  ## Examples

       iex> normalize_name_map(%{"A" => 1})
       %{1 => :A, :A => 1}

       iex> normalize_name_map(%{"a" => 1})
       %{1 => :A, :A => 1}

       iex> normalize_name_map(%{a: 1})
       %{1 => :A, :A => 1}

  """
  @spec normalize_name_map(map) :: any
  def normalize_name_map(map) when is_map(map) do
    up = fn x -> to_string(x) |> String.upcase() |> String.to_atom() end

    map
    |> Enum.reduce(%{}, fn {k, v}, acc -> acc |> Map.put(up.(k), v) |> Map.put(v, up.(k)) end)
  end
end
