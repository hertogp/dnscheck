defmodule Mix.Tasks.Iana.Update do
  @moduledoc """
  Retrieves IANA's root hints and/or trust anchor.

  Use:
  - `mix iana.update hints` to update local copy of IANA's root nameservers
  - `mix iana.update trust` to update local copy of IANA's trust anchor
  - `mix iana.update check` to check local copy of IANA trust anchor is valid
  - `mix iana.root all` to do all actions

  """
  @shortdoc "Retrieves Iana's root hints"
  use Mix.Task

  # for xml parsing
  import Record, only: [defrecord: 2, extract: 2]
  defrecord :xmlElement, extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl")
  defrecord :xmlAttribute, extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  defrecord :xmlText, extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl")

  # priv setup
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
  @fname_rrs Path.join([@priv, "named.root.rrs"])

  # trust anchors
  @dnskey_url "https://dns.google.com/resolve?name=.&type=dnskey"
  @trust_url "https://data.iana.org/root-anchors"
  @froot %{
    checksums: "checksums-sha256.txt",
    anchors_xml: "root-anchors.xml",
    anchors_sig: "root-anchors.p7s",
    anchors_pem: "icannbundle.pem"
  }

  # Notes
  # % openssl smime -verify -CAfile icannbundle.pem -inform der -in root-anchors.p7s -content root-anchors.xml
  # -> verification successful
  @impl Mix.Task
  def run(args) do
    case args do
      ["hints"] -> hints()
      ["trust"] -> trust()
      ["dnskey"] -> fetch_ksks_google()
      ["xml"] -> xml_get_valid_keys()
      [] -> all()
      huh -> Mix.shell().info("\n#{huh} not supported, try: 'hints', 'trust', 'all' or nothing")
    end
  end

  # [[ ALL ]]

  defp all() do
    hints()
    trust()
  end

  # [[ ROOT DNSKEYs ]]

  defp fetch_ksks_google() do
    # fetch DNSKEY's using google's DNS API
    Mix.shell().info("DNSKEYs\n - fetching #{@dnskey_url}")
    {:ok, dnskeys} = fetch(@dnskey_url)

    ksks =
      Jason.decode!(dnskeys)
      |> Map.get("Answer")
      |> Enum.filter(fn m -> m["type"] == 48 end)
      |> Enum.map(fn m -> String.split(m["data"]) end)
      |> Enum.filter(fn [flags, _p, _a, _k] -> flags == "257" end)
      |> Enum.map(fn [flags, proto, algo, pubkey] ->
        {f, ""} = Integer.parse(flags)
        {p, ""} = Integer.parse(proto)
        {a, ""} = Integer.parse(algo)
        {:ok, k} = Base.decode64(pubkey)
        rdata = <<0::8, f::16, p::8, a::8, k::binary>>
        {f, p, a, k, :crypto.hash(:sha256, rdata) |> Base.encode16(case: :upper)}
      end)

    case ksks do
      [] -> {:error, "Could not retrieve KSKs via Google's API"}
      ksks -> {:ok, ksks}
    end
  end

  # [[ TRUST ANCHORS ]]
  # https://www.rfc-editor.org/rfc/rfc7958
  # - The SubjectPublicKeyInfo in the certificate represents the public key of the
  # Key Signing Key (KSK). The Subject field has the following attributes:
  defp trust() do
    Mix.shell().info("Checking trust anchor")

    {:ok, new_chk} = fetch("#{@trust_url}/#{@froot.checksums}")
    old_chk = read_file(Path.join(@priv, @froot.checksums))

    # TODO check != back to ==
    if old_chk != new_chk do
      Mix.shell().info(" - local checksums match the remote checkums")
      Mix.shell().info(" - local trust is up to date")
    else
      Mix.shell().info(" - local checksums do not match the remote checksums")
      Mix.shell().info(" - saving new checksums to #{@froot.checksums}")
      File.write!(Path.join(@priv, @froot.checksums), new_chk)
      Mix.shell().info(" - updating local trust anchors")

      checksums =
        new_chk
        |> String.split("\n", trim: true)
        |> Enum.map(fn s -> String.split(s) end)
        |> Enum.reduce(%{}, fn [chksum, fname], acc ->
          Map.put(acc, String.downcase(fname), chksum)
        end)

      with {:ok, xml} <- fetch_verified(@froot.anchors_xml, checksums[@froot.anchors_xml]),
           {:ok, _sig} <- fetch_verified(@froot.anchors_sig, checksums[@froot.anchors_sig]),
           {:ok, _pem} <- fetch_verified(@froot.anchors_pem, checksums[@froot.anchors_pem]),
           {:ok, _} <- validate_root_xml(),
           {:ok, keys} <- xml_get_valid_keys(xml),
           {:ok, ksks} <- fetch_ksks_google() do
        Mix.shell().info("Got keys")
        IO.inspect(keys)

        ksks =
          for ksk <- ksks, key <- keys do
            IO.inspect({ksk, key})
            IO.inspect(elem(ksk, 4) == key.digest, label: :match?)
          end
      else
        {:error, reason} -> raise "#{inspect(reason)}"
      end
    end
  end

  defp xml_get_valid_keys(),
    do: xml_get_valid_keys(File.read!(Path.join(@priv, @froot.anchors_xml))) |> IO.inspect()

  defp xml_get_valid_keys(xml) do
    {dta, _} = xml |> String.to_charlist() |> :xmerl_scan.string(space: :normalize)
    # there MUST be only one TrustAnchor
    [ta] = :xmerl_xpath.string('/TrustAnchor', dta)

    # check zone is '.'
    [zone] = :xmerl_xpath.string('/TrustAnchor/Zone/text()', ta)
    zone = xmlText(zone, :value) |> to_string

    if zone == ".",
      do: Mix.shell().info(" - zone is #{zone}"),
      else: raise("Trust anchor zone is not root! #{inspect(zone)}")

    # get the keys
    keys = :xmerl_xpath.string('//KeyDigest', ta)

    keys =
      for key <- keys do
        # get attributes: id, validFrom and validUntil (is optional)
        [id, from | until] =
          :xmerl_xpath.string('//@id | //@validFrom | //@validUntil', key)
          |> Enum.map(fn attr -> xmlAttribute(attr, :value) |> to_string end)

        {:ok, from, 0} = DateTime.from_iso8601(from)

        {:ok, until, 0} =
          if until != [],
            do: DateTime.from_iso8601(to_string(until)),
            else: {:ok, nil, 0}

        # get KeyTag elements (comes out in alphabetical order it seems
        [algo, digest, digestType, keytag] =
          :xmerl_xpath.string('Algorithm | Digest | DigestType | KeyTag', key)
          |> Enum.map(fn elm -> xmlElement(elm, :content) end)
          |> Enum.map(fn [txt] -> xmlText(txt, :value) |> to_string end)

        {algo, ""} = Integer.parse(algo)
        {digestType, ""} = Integer.parse(digestType)
        {keytag, ""} = Integer.parse(keytag)

        %{
          id: id,
          validFrom: from,
          validUntil: until,
          algo: algo,
          digest: digest,
          keytag: keytag,
          digestType: digestType
        }
      end
      |> Enum.filter(&is_valid_key?/1)

    case keys do
      [] -> {:error, "no valid keys were found in #{@froot.anchors_xml}"}
      keys -> {:ok, keys}
    end
  end

  defp is_valid_key?(%{validFrom: from, validUntil: until} = key) do
    now = DateTime.utc_now()
    startOk = DateTime.compare(from, now) in [:lt, :eq]
    stopOk = if until, do: DateTime.compare(now, until) in [:lt, :eq], else: true

    if startOk and stopOk do
      true
    else
      Mix.shell().info(" - ignoring invalid key #{key.id}, key validity: #{from} -- #{until}")
      false
    end
  end

  defp validate_root_xml() do
    # openssl smime -verify -CAfile icannbundle.pem -inform der -in root-anchors.p7s -content root-anchors.xml
    # => prints the xml and says: Verfication successful
    # openssl asn1parse -inform der -in priv/root-anchors.p7s
    # => show sequences of asn1 objects
    fpem = Path.join(@priv, @froot.anchors_pem)
    fxml = Path.join(@priv, @froot.anchors_xml)
    fsig = Path.join(@priv, @froot.anchors_sig)

    args = [
      "smime",
      "-verify",
      "-CAfile",
      fpem,
      "-inform",
      "der",
      "-in",
      fsig,
      "-content",
      fxml
    ]

    case System.cmd("openssl", args, stderr_to_stdout: true) do
      {_dta, 0} -> {:ok, Mix.shell().info(" - verfication of #{@froot.anchors_xml} successful")}
      {msg, n} -> {:error, "Error: exit status #{n}, #{inspect(msg)}"}
    end

    # So how to do the same using erlang's :crypto or :publick_key modules??
    # openssl pkcs7 -in priv/root-anchors.p7s -inform DER -print_certs
    # => prints two certs
    # openssl pkcs7 -inform DER -outform PEM -in priv/root-anchors.p7s -out priv/huh.pem
    # => pem file contains ---BEGIN PKCS7--- ... ---END PKCS7---
    # :public_key.pem_decode(File.read!("priv/huh.pem"))
    # => [c1] = [{:Contentinfo, <<binary>>, :not_encrypted}]
    # c2 = :public_key.pem_entry_decode(c1)
    # => {:ContentInfo, {1, 2, 840, 113549, 1, 7, 2}, {:SignedData, ...}}
    # ???
  end

  # [[ ROOT HINTS ]]

  defp hints() do
    Mix.shell().info("Checking root hints")
    {:ok, new_body} = fetch(@root_hints)
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

  @spec fetch(String.t()) :: {:error, String.t()} | {:ok, String.t()}
  defp fetch(url) do
    # https://www.erlang.org/doc/man/httpc#request-1
    request = {url, [@user_agent]}

    with {:ok, {{_http_ver, 200, 'OK'}, _headers, body}} <-
           :httpc.request(:get, request, @http_opts, @opts) do
      {:ok, body}
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

  @spec fetch_verified(String.t(), String.t()) :: {:ok, any} | {:error, String.t()}
  defp fetch_verified(name, checksum) do
    # get file from IANA and compare its checksum against checksum
    Mix.shell().info(" + fetching #{name}")
    {:ok, dta} = fetch("#{@trust_url}/#{name}")
    Mix.shell().info("   - retrieved #{byte_size(dta)} bytes")
    cks = :crypto.hash(:sha256, dta) |> Base.encode16(case: :lower)

    if cks == String.downcase(checksum) do
      Mix.shell().info("   - checksum is ok")
      Mix.shell().info("   - saving #{name}")
      path = Path.join(@priv, name)
      File.write!(path, dta)
      {:ok, dta}
    else
      Mix.shell().info("   - checksum failed!")
      {:error, "Checksum failed for #{name}"}
    end
  end

  # @spec verify_checksum(atom, String.t(), String.t()) :: boolean
  # defp verify_checksum(type, dta, chksum) do
  #   chks =
  #     :crypto.hash(type, dta)
  #     |> Base.encode16(case: :lower)
  #
  #   chks == String.downcase(chksum)
  # end
end
