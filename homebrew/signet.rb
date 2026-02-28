# Homebrew formula for Signet
# To install: brew install jmcentire/signet/signet
#
# This formula builds from source. For a tap, create the repository
# jmcentire/homebrew-signet and place this file as Formula/signet.rb

class Signet < Formula
  desc "Personal Sovereign Agent Stack -- cryptographic vault for AI agents"
  homepage "https://github.com/jmcentire/signet"
  url "https://github.com/jmcentire/signet/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "UPDATE_WITH_ACTUAL_SHA256_AFTER_RELEASE"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--path", "crates/signet", "--root", prefix
  end

  test do
    assert_match "signet", shell_output("#{bin}/signet --version")
  end
end
