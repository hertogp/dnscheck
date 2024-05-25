defmodule DNS.Time do
  @moduledoc """
  Functions to manage time.

  """

  @doc """
  Returns the current point in monotonic time.

  Uses `:millisecond` as the time unit.

  """
  @spec now() :: integer
  def now(),
    do: System.monotonic_time(:millisecond)

  @doc """
  Returns a point in monotonic time, `delta` ms from now.

  """
  @spec time(non_neg_integer) :: integer
  def time(delta),
    do: now() + max(0, delta)

  @doc """
  Returns the remaining time, in ms, for `time` relative to `now/0`.

  The remaining time is always 0 or more milliseconds.

  """
  @spec timeout(integer) :: non_neg_integer
  def timeout(time),
    do: timeout(now(), time)

  @doc """
  Returns the remaining time, in ms, for `time` relative to `endtime`.

  Returns 0 if given `time` is already past `endtime`.

  """
  # how many ms till monotonic `time` reaches monotonic `endtime`
  @spec timeout(integer, integer) :: non_neg_integer
  def timeout(time, endtime),
    do: max(0, endtime - time)

  #   if time < endtime,
  #     do: endtime - time,
  #     else: 0
  # end

  @doc """
  Returns `:ok` after `delta` milliseconds.

  """
  @spec wait(non_neg_integer) :: :ok
  def wait(delta) when delta <= 0,
    do: :ok

  def wait(delta) do
    receive do
    after
      delta -> :ok
    end
  end
end
