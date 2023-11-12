defmodule DNS.Utils do
  @moduledoc """
  Utility functions used in various places

  """

  @doc """
  Normalizes a `name,value` lookup map.

  Normalizing a name.value-map means:
  - all non-binary keys are deleted
  - each remaining `{key,value}`-pair is replaced by:
      - `{lowercase(key), value}`
      - `{uppercase(key), value}`
      - `{atom of uppercase(key), value}`
      - `{value, uppercase(key)}`
    pairs.

  Before the final map is created, the list of all `{key,value}`-pairs are sorted in descending
  order, so whatever `{key,value}`-pair sorts last, wins.

  Best used on maps that have all either upper or lowercase, unique keys.

  ## Examples

       iex> map_both_ways(%{"A" => 1})
       %{1 => "A", :A => 1, "A" => 1, "a" => 1}

       iex> map_both_ways(%{"a" => 1})
       %{1 => "A", :A => 1, "A" => 1, "a" => 1}

       iex> map_both_ways(%{"A" => 1, "b" => 2})
       %{1 => "A", 2 => "B", :A => 1, :B => 2, "A" => 1, "B" => 2, "a" => 1, "b" => 2}

  """
  @spec normalize_name_map(map) :: any
  def normalize_name_map(map) when is_map(map) do
    updown = fn {k, v}, acc ->
      upKey = String.upcase(k)
      loKey = String.downcase(k)
      atKey = String.to_atom(upKey)
      [{upKey, v}, {loKey, v}, {atKey, v}, {v, upKey} | acc]
    end

    map
    |> Enum.filter(fn {key, _} -> is_binary(key) end)
    |> Enum.reduce([], &updown.(&1, &2))
    |> Map.new()
  end
end
