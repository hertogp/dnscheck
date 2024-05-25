defmodule DNS.Time do
  @moduledoc """
  Functions to manage time.

  """

  @doc false
  # current moment in monotonic time
  def now(),
    do: System.monotonic_time(:millisecond)

  @doc false
  # create a (usually future), monotonic point in time, timeout ms from now
  def time(timeout),
    do: now() + timeout

  @doc false
  # remaining time [ms] till we reach the monotonic `time`
  def timeout(time),
    do: timeout(now(), time)

  @doc false
  # how many ms till monotonic `time` reaches monotonic `endtime`
  def timeout(time, endtime) do
    if time < endtime,
      do: endtime - time,
      else: 0
  end

  @doc false
  # donot wait
  def wait(0),
    do: :ok

  # wait for `time` ms, don't match any messages
  def wait(time) do
    receive do
    after
      time -> :ok
    end
  end
end
