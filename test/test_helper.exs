ExUnit.start()

defmodule Drill do
  @moduledoc """
  Test helper functions that create test files in "test/data"

  """

  @data_dir Path.join([File.cwd!(), "test", "data"])
  @temp_dir System.tmp_dir!()

  @header """
  #
  # Autogenerated file using drill
  # - see test_helper.exs
  #

  """

  unless File.exists?(@data_dir),
    do: File.mkdir!(@data_dir)

  @doc """
  Runs a drill using given `name`, `type` and `options`, returns the wiredata

  Needs a working Internet connection since resolving is against 8.8.8.8, since
  local systemd only handles common record types and no DNSSEC related ones.
  """
  def drill(name, type, _opts \\ []) do
    # put a unique number in filename just in case tests run async
    nr = System.unique_integer([:positive, :monotonic])
    tmp_file = Path.join(@temp_dir, "drill-#{nr}.txt")
    System.cmd("drill", [name, "#{type}", "-w", tmp_file, "@8.8.8.8"])

    {:ok, wiredata} =
      File.read!(tmp_file)
      |> String.replace(~r/;.*\n/, "")
      |> String.replace(~r/\s*/, "")
      |> Base.decode16(case: :lower)

    File.rm!(tmp_file)
    {name, type, wiredata}
  end

  def ensure_testfile(fname, forced \\ false) do
    if forced or not File.exists?(fname),
      do: generate_tests(fname)

    :ok
  end

  def generate_tests(fname) when fname == "test/data/a-samples" do
    tests =
      ["google.nl", "google.com", "sidn.nl", "example.com"]
      |> Enum.map(fn name -> drill(name, :A) end)

    File.write(fname, "#{@header}#{inspect(tests, limit: :infinity, pretty: true)}")
  end

  def generate_tests(fname) when fname == "test/data/aaaa-samples" do
    tests =
      ["google.nl", "google.com", "sidn.nl", "example.com"]
      |> Enum.map(fn name -> drill(name, :AAAA) end)

    File.write(fname, "#{@header}#{inspect(tests, limit: :infinity, pretty: true)}")
  end

  def generate_tests(fname) when fname == "test/data/cname-samples" do
    tests =
      ["www.us.gov", "www.azure.com", "www.sidn.nl", "www.aws.com", "www.amazon.com"]
      |> Enum.map(fn name -> drill(name, :CNAME) end)

    File.write(fname, "#{@header}#{inspect(tests, limit: :infinity, pretty: true)}")
  end

  def generate_tests(fname) when fname == "test/data/ns-samples" do
    tests =
      ["google.nl", "google.com", "sidn.nl", "example.com"]
      |> Enum.map(fn name -> drill(name, :NS) end)

    File.write(fname, "#{@header}#{inspect(tests, limit: :infinity, pretty: true)}")
  end

  def generate_tests(fname) when fname == "test/data/soa-samples" do
    tests =
      ["google.nl", "google.com", "sidn.nl", "example.com"]
      |> Enum.map(fn name -> drill(name, :SOA) end)

    File.write(fname, "#{@header}#{inspect(tests, limit: :infinity, pretty: true)}")
  end
end
