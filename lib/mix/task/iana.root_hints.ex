defmodule Mix.Tasks.Iana.Root do
  @moduledoc """
  Retrieves IANA's root hints and/or trust anchor.

  Use:
  - `mix iana.root hints` to update local copy of IANA's root nameservers
  - `mix iana.root trust` to update local copy of IANA's trust anchor
  - `mix iana.root all` to do both

  """
  @shortdoc "Retrieves Iana's root hints"
  use Mix.Task

  @priv :code.priv_dir(:dnscheck)
  @user_agent {'User-agent', 'Elixir Dnscheck'}

  # httpc options
  @cacerts :public_key.cacerts_get()
  @ssl_opts [{:verify, :verify_peer}, {:depth, 99}, {:cacerts, @cacerts}]
  @http_opts [timeout: 3000, ssl: @ssl_opts]
  @opts [body_format: :binary]

  # root hints
  @root_hints "https://www.internic.net/domain/named.root"
  @fname_root Path.join([@priv, "named.root"])
  @fname_rrs Path.join([@priv, "rrs.root"])

  # trust anchors
  @trust_url "https://data.iana.org/root-anchors"
  @fname_chk Path.join(@priv, "checksums-sha256.txt")
  @dnskey "https://dns.google.com/resolve?name=.&type=dnskey"

  # Notes
  # % openssl smime -verify -CAfile icannbundle.pem -inform der -in root-anchors.p7s -content root-anchors.xml
  # -> verification successful
  @impl Mix.Task
  def run(args) do
    case args do
      ["hints"] -> hints()
      ["trust"] -> trust()
      ["all"] -> all()
      [] -> all()
      huh -> Mix.shell().info("\n#{huh} not supported, try: 'hints', 'trust', 'all' or nothing")
    end
  end

  # [[ ALL ]]
  defp all() do
    hints()
    trust()
  end

  # [[ TRUST ANCHORS ]]
  defp trust() do
    Mix.shell().info("Checking trust anchor")

    fname = "checksums-sha256.txt"
    new_chk = fetch("#{@trust_url}/#{fname}")
    old_chk = read_file(@fname_chk)

    if old_chk == new_chk do
      Mix.shell().info(" - local checksums match the remote checkums")
      Mix.shell().info(" - local trust is up to date")
    else
      Mix.shell().info(" - local checksums do not match the remote checksums")
      Mix.shell().info(" - saving new checksums to #{fname}")
      File.write!(@fname_chk, new_chk)
      Mix.shell().info(" - updating local trust anchor")

      new_chk
      |> String.split("\n", trim: true)
      |> Enum.map(fn s -> String.split(s) end)
      |> Enum.reduce(%{}, fn [chksum, fname], acc ->
        Map.put(acc, String.downcase(fname), chksum)
      end)
      |> Enum.map(fn {fname, chksum} -> check(fname, chksum) end)
    end
  end

  # [[ ROOT HINTS ]]

  defp hints() do
    Mix.shell().info("Checking root hints")
    new_body = fetch(@root_hints)
    new_serial = get_serial(new_body)
    new_rrs = hints_to_rrs(new_body)

    old_body = read_file(@fname_root)
    old_serial = get_serial(old_body)
    old_rrs = hints_to_rrs(old_body)

    Mix.shell().info(" - remote serial #{inspect(new_serial)}")
    Mix.shell().info(" - local  serial #{inspect(old_serial)}")

    if old_serial == new_serial do
      Mix.shell().info(" - root hints up to date")

      # just to be sure
      unless File.exists?(@fname_rrs),
        do: File.write!(@fname_rrs, :erlang.term_to_binary(new_rrs))
    else
      File.write!(@fname_root, new_body)
      File.write!(@fname_rrs, :erlang.term_to_binary(new_rrs))

      new_hints =
        new_rrs
        |> Enum.filter(fn rr -> rr not in old_rrs end)
        |> Enum.map(fn rr -> " + #{rr.name}\t#{rr.ttl}\t#{rr.type}\t#{rr.rdmap.ip}" end)
        |> Enum.join("\n")

      old_hints =
        old_rrs
        |> Enum.filter(fn rr -> rr not in new_rrs end)
        |> Enum.map(fn rr -> " - #{rr.name}\t#{rr.ttl}\t#{rr.type}\t#{rr.rdmap.ip}" end)
        |> Enum.join("\n")

      Mix.shell().info(" - updates include:")
      Mix.shell().info(new_hints)
      Mix.shell().info(old_hints)
    end
  end

  # [[ HELPERS ]]

  @spec fetch(String.t()) :: {:error, String.t()} | String.t()
  defp fetch(url) do
    # https://www.erlang.org/doc/man/httpc#request-1
    request = {url, [@user_agent]}

    with {:ok, {{_http_ver, 200, 'OK'}, _headers, body}} <-
           :httpc.request(:get, request, @http_opts, @opts) do
      body
    else
      metadata -> {:error, "#{inspect(metadata)}"}
    end
  end

  @spec get_serial(String.t()) :: String.t()
  defp get_serial(body) do
    case Regex.run(~r/version\s+of\s+root\s+zone:\s*(\d+)/, body) do
      nil -> ""
      list -> List.last(list)
    end
  end

  @spec hints_to_rrs(String.t()) :: [DNS.Msg.RR.t()]
  defp hints_to_rrs(body) do
    # body might be "" so filter that out
    body
    |> String.split("\n")
    |> Enum.filter(fn s -> s != "" end)
    |> Enum.filter(fn s -> not String.starts_with?(s, [";", "."]) end)
    |> Enum.map(fn s -> String.split(s) end)
    |> Enum.map(fn entry -> to_RR(entry) end)
  end

  defp to_RR([]),
    do: []

  @spec to_RR([String.t()]) :: DNS.Msg.RR.t()
  defp to_RR([name, ttl, type, ip]) do
    {ttl, ""} = Integer.parse(ttl)

    type =
      case type do
        "A" -> :A
        "AAAA" -> :AAAA
        _ -> raise "error reading type from entry: #{inspect({name, ttl, type, ip})}"
      end

    DNS.Msg.RR.new(name: name, type: type, ttl: ttl, rdmap: %{ip: ip})
  end

  @spec read_file(String.t()) :: String.t()
  defp read_file(fname) do
    with {:ok, body} <- File.read(fname) do
      body
    else
      _ -> ""
    end
  end

  defp check(name, checksum) do
    Mix.shell().info(" + fetching #{name}")
    dta = fetch("#{@trust_url}/#{name}")
    Mix.shell().info("   - retrieved #{byte_size(dta)} bytes")

    if verify_checksum(:sha256, dta, checksum) do
      Mix.shell().info("   - checksum is ok")
      Mix.shell().info("   - saving #{name}")
      path = Path.join(@priv, name)
      File.write!(path, dta)
    else
      Mix.shell().info("   - checksum failed!")
      Mix.shell().info("   - ignoring #{name}")
    end
  end

  @spec verify_checksum(atom, String.t(), String.t()) :: boolean
  defp verify_checksum(type, dta, chksum) do
    chks =
      :crypto.hash(type, dta)
      |> Base.encode16(case: :lower)

    chks == String.downcase(chksum)
  end
end
