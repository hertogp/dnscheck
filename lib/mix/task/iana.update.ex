defmodule Mix.Tasks.Iana.Update do
  @moduledoc """
  Updates local copy of IANA's root hints and/or trust anchor(s).

  Use:
  - `mix iana.update hints` to update local copy of IANA's root nameservers
  - `mix iana.update trust` to update local copy of IANA's trust anchor
  - `mix iana.update` to do both actions

  Optionally provide `forced` on the cli as well, to force an update.
  """
  @shortdoc "updates local copy of IANA's root hints and/or trust anchors"

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
    anchors_pem: "icannbundle.pem",
    anchors_rrs: "root.rrs"
  }

  # Notes
  # % openssl smime -verify -CAfile icannbundle.pem -inform der -in root-anchors.p7s -content root-anchors.xml
  # -> verification successful
  @impl Mix.Task
  def run(args) do
    forced = Enum.member?(args, "forced")
    command = Enum.reject(args, fn w -> w == "forced" end)

    case command do
      ["hints"] -> hints(forced)
      ["trust"] -> trust(forced)
      [] -> all(forced)
      ["all"] -> all(forced)
      huh -> Mix.shell().info("\n#{huh} not supported, try: 'hints', 'trust', 'all' or nothing")
    end
  end

  # [[ ALL ]]

  defp all(forced) do
    hints(forced)
    trust(forced)
  end

  # [[ TRUST ANCHORS ]]
  # https://www.rfc-editor.org/rfc/rfc7958
  defp trust(forced) do
    Mix.shell().info("Checking trust anchor")

    {:ok, new_chk} = fetch("#{@trust_url}/#{@froot.checksums}")
    old_chk = read_file(Path.join(@priv, @froot.checksums))

    if not forced and old_chk == new_chk and have_locals?() do
      Mix.shell().info(" - local checksums match the remote checkums")
      Mix.shell().info(" - local trust is up to date")
    else
      Mix.shell().info(" - saving new checksums to #{@froot.checksums}")
      Mix.shell().info(" - updating local trust achnors")
      File.write!(Path.join(@priv, @froot.checksums), new_chk)

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
           {:ok, _} <- xml_verify_root_anchors(),
           {:ok, keys} <- xml_get_valid_keys(xml),
           {:ok, ksks} <- fetch_ksks_google() do
        Mix.shell().info(" - validating KSKs")

        ksks =
          for ksk <- ksks, key <- keys do
            # hash = elem(ksk, 4)
            hash = ksk_digest(ksk, key.digestType)

            if hash == key.digest do
              Mix.shell().info("   - key #{key.keytag} validates KSK #{inspect(hash)}")
              ksk
            end
          end
          |> Enum.map(&ksk_to_dnskey_ds_RR/1)
          |> List.flatten()

        File.write!(Path.join(@priv, @froot.anchors_rrs), :erlang.term_to_binary(ksks))
        len = length(ksks) |> div(2)
        Mix.shell().info(" - saved #{len} DNSKEY & DS RRs to #{@froot.anchors_rrs}")
      else
        {:error, reason} -> raise "#{inspect(reason)}"
      end
    end
  end

  # [[ ROOT HINTS ]]

  defp hints(forced) do
    Mix.shell().info("Checking root hints")
    {:ok, new_body} = fetch(@root_hints)
    Mix.shell().info(" - fetched remote named.root")
    new_serial = get_serial(new_body)
    # TODO make nameservers a list of [{ip-tuple, name}, ..]
    # save result of inspect(nss) so its readable, root.nss
    new_rrs = hints_to_rrs(new_body)

    old_body = read_file(@fname_root)
    old_serial = get_serial(old_body)
    old_rrs = hints_to_rrs(old_body)
    Mix.shell().info(" - read local copy (if any)")

    Mix.shell().info(" - remote serial #{inspect(new_serial)}")
    Mix.shell().info(" - local  serial #{inspect(old_serial)}")

    if not forced and old_serial == new_serial do
      Mix.shell().info(" - root hints up to date")

      # just to be sure
      unless File.exists?(@fname_rrs),
        do: File.write!(@fname_rrs, :erlang.term_to_binary(new_rrs))
    else
      File.write!(@fname_root, new_body)
      Mix.shell().info(" - saved named.root")
      File.write!(@fname_rrs, :erlang.term_to_binary(new_rrs))
      Mix.shell().info(" - saved named.root.rrs")

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

      if new_hints != old_hints do
        Mix.shell().info(" - updates include:")
        Mix.shell().info(new_hints)
        Mix.shell().info(old_hints)
      end
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

  defp fetch_ksks_google() do
    # fetch DNSKEY's using google's DNS API
    Mix.shell().info(" - fetching DNSKEYs from google")
    {:ok, dnskeys} = fetch(@dnskey_url)

    ksks =
      Jason.decode!(dnskeys)
      |> Map.get("Answer")
      |> Enum.filter(fn m -> m["type"] == 48 end)
      |> Enum.map(fn m -> String.split(m["data"]) end)
      |> Enum.filter(fn [flags, _p, _a, _k] -> flags == "257" end)
      |> Enum.map(fn [flags, proto, algo, pubkey] ->
        # String.to_integer is easier
        # [f, p ,a] = [flags, proto, algo] |> Enum.map(fn n -> String.to_integer(n) end)
        {f, ""} = Integer.parse(flags)
        {p, ""} = Integer.parse(proto)
        {a, ""} = Integer.parse(algo)
        {:ok, k} = Base.decode64(pubkey)
        %{flags: f, proto: p, algo: a, pubkey: k}
      end)

    case ksks do
      [] -> {:error, "Could not retrieve KSKs via Google's API"}
      ksks -> {:ok, ksks}
    end
  end

  @spec fetch_verified(String.t(), String.t()) :: {:ok, any} | {:error, String.t()}
  defp fetch_verified(name, checksum) do
    # get file from IANA and compare its checksum against given `checksum`
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

  @spec get_serial(String.t()) :: String.t()
  defp get_serial(body) do
    case Regex.run(~r/version\s+of\s+root\s+zone:\s*(\d+)/, body) do
      nil -> ""
      list -> List.last(list)
    end
  end

  defp have_locals?() do
    @froot
    |> Enum.map(fn {_, fname} -> Path.join(@priv, fname) end)
    |> Enum.all?(&File.exists?/1)
  end

  @spec hints_to_rrs(String.t()) :: [DNS.Msg.RR.t()]
  defp hints_to_rrs(body) do
    # body might be "" so filter that out
    body
    |> String.split("\n")
    |> Enum.filter(fn s -> s != "" end)
    |> Enum.filter(fn s -> not String.starts_with?(s, [";", "."]) end)
    |> Enum.map(fn s -> String.split(s) end)
    |> Enum.map(fn entry -> ns_to_RR(entry) end)
  end

  defp ksk_digest(ksk, dtype) do
    rdata = <<0::8, ksk.flags::16, ksk.proto::8, ksk.algo::8, ksk.pubkey::binary>>

    case dtype do
      1 -> :crypto.hash(:sha, rdata)
      2 -> :crypto.hash(:sha256, rdata)
      n -> raise "Error, KeyDigest type #{inspect(n)} unknown"
    end
    |> Base.encode16(case: :upper)
  end

  defp ksk_to_dnskey_ds_RR(ksk) do
    dnskey =
      DNS.Msg.RR.new(
        name: ".",
        type: 48,
        ttl: 3600,
        rdmap: ksk
      )

    # TODO: maybe make this a DNS.Msg.Util function
    keytag =
      <<ksk.flags::16, ksk.proto::8, ksk.algo::8, ksk.pubkey::binary>>
      |> :binary.bin_to_list()
      |> Enum.with_index()
      |> Enum.map(fn {n, idx} -> if Bitwise.band(idx, 1) == 1, do: n, else: Bitwise.bsl(n, 8) end)
      |> Enum.sum()
      |> then(fn acc -> [acc, Bitwise.bsr(acc, 16) |> Bitwise.band(0xFFFF)] end)
      |> Enum.sum()
      |> Bitwise.band(0xFFFF)

    digest = ksk_digest(ksk, 2)

    ds =
      DNS.Msg.RR.new(
        name: ".",
        type: 43,
        ttl: 3600,
        rdmap: %{keytag: keytag, algo: ksk.algo, type: 2, digest: digest}
      )

    [dnskey, ds]
  end

  defp ns_to_RR([]),
    do: []

  @spec ns_to_RR([String.t()]) :: DNS.Msg.RR.t()
  defp ns_to_RR([name, ttl, type, ip]) do
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
    if File.exists?(fname),
      do: File.read!(fname),
      else: ""
  end

  @spec xml_get_valid_keys(String.t()) :: {:ok, [map]} | {:error, String.t()}
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

        # TODO: make sure KeyTag elements indeed come out in alphabetical order!
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
      |> Enum.filter(&xml_is_valid_key?/1)

    case keys do
      [] -> {:error, "no valid keys were found in #{@froot.anchors_xml}"}
      keys -> {:ok, keys}
    end
  end

  defp xml_is_valid_key?(%{validFrom: from, validUntil: until} = key) do
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

  defp xml_verify_root_anchors() do
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
end
