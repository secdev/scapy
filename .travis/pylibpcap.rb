class Pylibpcap <Formula
  url "http://downloads.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz"
  homepage "http://pylibpcap.sourceforge.net/"
  sha256 "cfc365f2707a7986496acacf71789fef932a5ddbeaa36274cc8f9834831ca3b1"
 
  def install
    system "python", *Language::Python.setup_install_args(prefix)
  end
end

