defmodule Mix.Tasks.Iana.Update do
  @moduledoc """
  Retrieve the root hints from Iana.

  Saves the root hints to `priv/named.root` and creates
  `priv/rrs.root` containing NS resource records.

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
  @root_hints_url "https://www.internic.net/domain/named.root"
  @fname_root Path.join([@priv, "named.root"])
  @fname_rrs Path.join([@priv, "rrs.root"])

  # trust anchors
  @trust_crc "https://data.iana.org/root-anchors/checksums-sha256.txt"
  @trust_pem "https://data.iana.org/root-anchors/icannbundle.pem"
  @trust_sig "https://data.iana.org/root-anchors/root-anchors.p7s"
  @trust_xml "https://data.iana.org/root-anchors/root-anchors.xml"
  @fname_crc Path.join(@priv, "checksums-sha256.txt")
  @fname_pem Path.join(@priv, "icannbundle.pem")
  @fname_sig Path.join(@priv, "root-anchors.p7s")
  @fname_xml Path.join(@priv, "root-anchors.xml")

  @impl Mix.Task
  def run(args) do
    case args do
      ["hints"] -> hints()
      ["trust"] -> trust()
      _ -> Mix.shell().info("expected one of 'hints', 'trust'")
    end
  end

  # [[ TRUST ]]
  defp trust() do
    Mix.shell().info("Updating trust anchors")

    new_crc = fetch(@trust_crc)
    old_crc = read_file(@fname_crc)

    if old_crc == new_crc do
      Mix.shell().info("Checksum's have not changed, Trust is up to date")
    else
      Mix.shell().info("Saving #{@fname_crc}")
      File.write!(@fname_crc, new_crc)
      new_pem = fetch(@trust_pem)
      Mix.shell().info("Saving #{@fname_pem}")
      File.write!(@fname_pem, new_pem)
      new_sig = fetch(@trust_sig)
      Mix.shell().info("Saving #{@fname_sig}")
      File.write!(@fname_sig, new_sig)
      new_xml = fetch(@trust_xml)
      Mix.shell().info("Saving #{@fname_xml}")
      File.write!(@fname_xml, new_xml)
    end
  end

  # [[ HINTS ]]

  defp hints() do
    new_body = fetch(@root_hints_url)
    new_serial = get_serial(new_body)
    new_rrs = hints_to_rrs(new_body)

    old_body = read_file(@fname_root)
    old_serial = get_serial(old_body)
    old_rrs = hints_to_rrs(old_body)

    if old_serial == new_serial do
      Mix.shell().info("Serial #{old_serial}, root hints up to date")

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

      Mix.shell().info("\nUpdated serial #{old_serial} -> #{new_serial}, root hints changed:\n")
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

  @spec get_serial(String.t()) :: String.t()
  defp get_serial(body) do
    case Regex.run(~r/version\s+of\s+root\s+zone:\s*(\d+)/, body) do
      nil -> ""
      list -> List.last(list)
    end
  end
end
